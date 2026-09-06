//go:build linux

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"golang.org/x/sys/unix"
)

const (
	uninstallRequestLimit  = 4096
	uninstallReceiptWait   = 30 * time.Second
	uninstallReceiptPoll   = 50 * time.Millisecond
	uninstallHeaderTimeout = 2 * time.Second
)

var uninstallOperationID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type peerUIDContextKey struct{}

type uninstallNotifyFunc func(context.Context, string) (reconcile.UninstallNoticeResult, error)
type receiptExistsFunc func(string) (bool, error)

type linuxUninstallServer struct {
	path     string
	listener net.Listener
	server   *http.Server
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
	inode    socketIdentity
}

type socketIdentity struct {
	dev uint64
	ino uint64
}

func startLocalUninstallServer(app *App) (localUninstallServer, error) {
	return newLinuxUninstallServer(app.cfg.StateDir, uninstallReceiptWait, app.NotifyUninstall, app.store.ReceiptExists)
}

func newLinuxUninstallServer(stateDir string, wait time.Duration, notify uninstallNotifyFunc, receipt receiptExistsFunc) (*linuxUninstallServer, error) {
	if notify == nil || receipt == nil {
		return nil, errors.New("uninstall endpoint requires notification and receipt callbacks")
	}
	path := filepath.Join(stateDir, UninstallSocketName)
	if err := prepareUninstallSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	inode, err := socketIdentityAt(path)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = removeSocketIfIdentity(path, inode)
		}
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("chmod uninstall socket: %w", err)
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	handler := newUninstallHandler(wait, notify, receipt)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: uninstallHeaderTimeout,
		ReadTimeout:       uninstallHeaderTimeout,
		WriteTimeout:      wait + 2*time.Second,
		IdleTimeout:       uninstallHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			uid, err := unixPeerUID(conn)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, peerUIDContextKey{}, uid)
		},
	}
	local := &linuxUninstallServer{path: path, listener: listener, server: srv, cancel: cancel, done: make(chan struct{}), inode: inode}
	go func() {
		defer close(local.done)
		_ = srv.Serve(listener)
	}()
	cleanup = false
	return local, nil
}

func newUninstallHandler(wait time.Duration, notify uninstallNotifyFunc, receipt receiptExistsFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != UninstallHTTPPath {
			writeUninstallError(w, http.StatusNotFound, "not_found")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeUninstallError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		uid, ok := r.Context().Value(peerUIDContextKey{}).(uint32)
		if !ok || uid != 0 {
			writeUninstallError(w, http.StatusForbidden, "root_required")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeUninstallError(w, http.StatusUnsupportedMediaType, "application_json_required")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, uninstallRequestLimit+1))
		if err != nil {
			writeUninstallError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if len(body) > uninstallRequestLimit {
			writeUninstallError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		var request struct {
			OperationID string `json:"operation_id"`
		}
		if err := protocol.DecodeStrictJSONInto(body, &request); err != nil || !uninstallOperationID.MatchString(request.OperationID) {
			writeUninstallError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		defer cancel()
		result, err := notify(ctx, request.OperationID)
		if err != nil {
			writeUninstallError(w, http.StatusServiceUnavailable, "notification_failed")
			return
		}
		if !result.Online || result.Status != "QUEUED" {
			writeUninstallError(w, http.StatusServiceUnavailable, "agent_offline")
			return
		}
		for {
			if ctx.Err() != nil {
				writeUninstallError(w, http.StatusGatewayTimeout, "receipt_timeout")
				return
			}
			exists, err := receipt(request.OperationID)
			if err != nil {
				writeUninstallError(w, http.StatusServiceUnavailable, "receipt_check_failed")
				return
			}
			if exists {
				_ = json.NewEncoder(w).Encode(struct {
					OperationID string `json:"operation_id"`
					Status      string `json:"status"`
				}{OperationID: request.OperationID, Status: "RECEIPTED"})
				return
			}
			timer := time.NewTimer(uninstallReceiptPoll)
			select {
			case <-ctx.Done():
				timer.Stop()
				writeUninstallError(w, http.StatusGatewayTimeout, "receipt_timeout")
				return
			case <-timer.C:
			}
		}
	})
}

func writeUninstallError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: code})
}

func unixPeerUID(conn net.Conn) (uint32, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection does not expose syscall credentials")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, controlErr
}

func prepareUninstallSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect uninstall socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket uninstall endpoint %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("refusing to replace uninstall socket not owned by agent")
	}
	identity := socketIdentity{dev: uint64(stat.Dev), ino: stat.Ino}
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("uninstall endpoint is already active")
	}
	if err := quarantineStaleSocket(path, identity); err != nil {
		return fmt.Errorf("quarantine stale uninstall socket: %w", err)
	}
	return nil
}

// quarantineStaleSocket atomically moves the terminal component out of the
// stable name and then verifies that the moved inode is the socket inspected
// before the connectivity probe. It deliberately does not unlink the retired
// inode: Linux has no pathname unlink primitive conditional on inode identity,
// so deleting it would reopen a final replacement race.
func quarantineStaleSocket(path string, want socketIdentity) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate stale socket quarantine name: %w", err)
	}
	quarantine := path + ".stale-" + hex.EncodeToString(nonce[:])
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, quarantine, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	got, err := socketIdentityAt(quarantine)
	if err == nil && got == want {
		return nil
	}
	// A replacement won before rename. Restore it without overwriting anything
	// that appeared at the stable name, and fail closed either way.
	restoreErr := unix.Renameat2(unix.AT_FDCWD, quarantine, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	if err != nil {
		return errors.Join(errors.New("socket changed during stale quarantine"), err, restoreErr)
	}
	return errors.Join(errors.New("socket identity changed during stale quarantine"), restoreErr)
}

func removeSocketIfIdentity(path string, want socketIdentity) error {
	got, err := socketIdentityAt(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("uninstall socket changed before removal")
	}
	return os.Remove(path)
}

func socketIdentityAt(path string) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return socketIdentity{}, fmt.Errorf("inspect uninstall socket identity: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return socketIdentity{}, errors.New("uninstall endpoint is not a socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}, errors.New("uninstall socket has no stat identity")
	}
	return socketIdentity{dev: uint64(stat.Dev), ino: stat.Ino}, nil
}

func (s *linuxUninstallServer) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.once.Do(func() {
		s.cancel()
		_ = s.server.Shutdown(ctx)
		_ = s.listener.Close()
	})
	select {
	case <-s.done:
		if err := removeSocketIfIdentity(s.path, s.inode); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove uninstall socket: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
