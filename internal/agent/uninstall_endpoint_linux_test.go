//go:build linux

package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
)

const testUninstallOperationID = "0123456789abcdef0123456789abcdef"

func uninstallRequest(t *testing.T, handler http.Handler, uid uint32, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, UninstallHTTPPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), peerUIDContextKey{}, uid))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func queuedUninstallResult(operationID string) reconcile.UninstallNoticeResult {
	return reconcile.UninstallNoticeResult{OperationID: operationID, Online: true, Status: "QUEUED"}
}

func TestUninstallEndpointRejectsUnauthorizedPeer(t *testing.T) {
	var called atomic.Bool
	handler := newUninstallHandler(time.Second, func(context.Context, string) (reconcile.UninstallNoticeResult, error) {
		called.Store(true)
		return reconcile.UninstallNoticeResult{}, nil
	}, func(string) (bool, error) { return false, nil })

	response := uninstallRequest(t, handler, 1000, `{"operation_id":"`+testUninstallOperationID+`"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if called.Load() {
		t.Fatal("unauthorized request reached NotifyUninstall")
	}
}

func TestUninstallEndpointRejectsMalformedRequests(t *testing.T) {
	handler := newUninstallHandler(time.Second, func(context.Context, string) (reconcile.UninstallNoticeResult, error) {
		t.Fatal("malformed request reached NotifyUninstall")
		return reconcile.UninstallNoticeResult{}, nil
	}, func(string) (bool, error) { return false, nil })

	for name, body := range map[string]string{
		"missing operation": `{}`,
		"unknown field":     `{"operation_id":"` + testUninstallOperationID + `","extra":true}`,
		"duplicate field":   `{"operation_id":"` + testUninstallOperationID + `","operation_id":"` + testUninstallOperationID + `"}`,
		"bad operation":     `{"operation_id":"../not-an-operation"}`,
		"trailing value":    `{"operation_id":"` + testUninstallOperationID + `"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := uninstallRequest(t, handler, 0, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}
}

func TestUninstallEndpointRejectsOversizeRequest(t *testing.T) {
	handler := newUninstallHandler(time.Second, func(context.Context, string) (reconcile.UninstallNoticeResult, error) {
		t.Fatal("oversize request reached NotifyUninstall")
		return reconcile.UninstallNoticeResult{}, nil
	}, func(string) (bool, error) { return false, nil })

	response := uninstallRequest(t, handler, 0, strings.Repeat("x", uninstallRequestLimit+1))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
}

func TestUninstallEndpointFailsClosedWithoutReceipt(t *testing.T) {
	var notified atomic.Bool
	handler := newUninstallHandler(25*time.Millisecond, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		notified.Store(true)
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return false, nil })

	response := uninstallRequest(t, handler, 0, `{"operation_id":"`+testUninstallOperationID+`"}`)
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusGatewayTimeout, response.Body.String())
	}
	if !notified.Load() {
		t.Fatal("NotifyUninstall was not called")
	}
}

func TestUninstallEndpointFailsClosedOffline(t *testing.T) {
	handler := newUninstallHandler(time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		return reconcile.UninstallNoticeResult{OperationID: operationID, Status: "UNKNOWN"}, nil
	}, func(string) (bool, error) {
		t.Fatal("offline request checked for a receipt")
		return false, nil
	})

	response := uninstallRequest(t, handler, 0, `{"operation_id":"`+testUninstallOperationID+`"}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
}

func TestUninstallEndpointReturnsOnlyAfterReceipt(t *testing.T) {
	var receipted atomic.Bool
	handler := newUninstallHandler(time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		go func() {
			time.Sleep(20 * time.Millisecond)
			receipted.Store(true)
		}()
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return receipted.Load(), nil })

	response := uninstallRequest(t, handler, 0, `{"operation_id":"`+testUninstallOperationID+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"status":"RECEIPTED"`) {
		t.Fatalf("response body = %s", response.Body.String())
	}
}

func TestLinuxUninstallServerSocketModeAndCleanup(t *testing.T) {
	dir := t.TempDir()
	server, err := newLinuxUninstallServer(dir, time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("start endpoint: %v", err)
	}
	path := filepath.Join(dir, UninstallSocketName)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want socket 0600", info.Mode())
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("close endpoint: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestLinuxUninstallServerRejectsSymlinkSocket(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, UninstallSocketName)); err != nil {
		t.Fatal(err)
	}
	_, err := newLinuxUninstallServer(dir, time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return true, nil })
	if err == nil {
		t.Fatal("endpoint replaced a symlink")
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || string(got) != "retain" {
		t.Fatalf("symlink target changed: content=%q err=%v", got, readErr)
	}
}

func TestLinuxUninstallServerReplacesOnlyStaleSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UninstallSocketName)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	server, err := newLinuxUninstallServer(dir, time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	retired, err := filepath.Glob(path + ".stale-*")
	if err != nil || len(retired) != 1 {
		t.Fatalf("retired stale sockets = %v, err=%v; want one quarantined inode", retired, err)
	}
}

func TestQuarantineStaleSocketRestoresIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UninstallSocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	actual, err := socketIdentityAt(path)
	if err != nil {
		t.Fatal(err)
	}
	wrong := actual
	wrong.ino++
	if err := quarantineStaleSocket(path, wrong); err == nil {
		t.Fatal("identity mismatch was accepted")
	}
	got, err := socketIdentityAt(path)
	if err != nil {
		t.Fatalf("replacement was not restored: %v", err)
	}
	if got != actual {
		t.Fatalf("restored identity = %+v, want %+v", got, actual)
	}
}

func TestLinuxUninstallEndpointSpeaksHTTPOverUnixSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root peer credential required")
	}
	dir := t.TempDir()
	server, err := newLinuxUninstallServer(dir, time.Second, func(_ context.Context, operationID string) (reconcile.UninstallNoticeResult, error) {
		return queuedUninstallResult(operationID), nil
	}, func(string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, UninstallSocketName))
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Post("http://localhost"+UninstallHTTPPath, "application/json", strings.NewReader(`{"operation_id":"`+testUninstallOperationID+`"}`))
	if err != nil {
		t.Fatalf("POST over unix socket: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.StatusCode, body)
	}
}
