// P14 Story 6: Agent uninstall notice (M3 work package 6).
//
// Allocates the uninstall notice as a bounded best-effort send: online agents
// queue the notice through the outbox (the controller's durable receipt
// eventually GCs it), offline agents record UNKNOWN because no client can
// promise a silent remote stop. The local terminal marker is the one-way
// authority: whether or not the notice reached the controller, a
// DECOMMISSIONED (or DECOMMISSIONING) marker ALWAYS prevents LKG recovery.
package reconcile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// errUninstall is the uninstall-notice error class.
type errUninstall string

func (e errUninstall) Error() string { return string(e) }

// UninstallNoticeResult is the bounded outcome.
type UninstallNoticeResult struct {
	OperationID     string `json:"operation_id"`
	Online          bool   `json:"online"`
	Status          string `json:"status"` // QUEUED | UNKNOWN
	TerminalRefused bool   `json:"terminal_refused,omitempty"`
}

// NotifyUninstall issues the bounded uninstall notice: online -> the notice is
// queued as an outbox result so the controller durably receives it;
// offline -> UNKNOWN. If the durable terminal marker is already
// DECOMMISSIONED/DECOMMISSIONING the notice is still recorded (the operator
// asked) but LKG recovery was already impossible.
func NotifyUninstall(ctx context.Context, store *localstate.Store, stateDir, operationID string, online func() bool, sessionIdentity ...func() (uint64, string, error)) (UninstallNoticeResult, error) {
	if operationID == "" {
		return UninstallNoticeResult{}, errUninstallRequiresOperation
	}
	if online == nil {
		online = func() bool { return true }
	}
	isOnline := online()
	notice := localstate.UninstallNotice{
		OperationID: operationID, Connectivity: isOnline, QueuedAtUnix: time.Now().Unix(),
	}
	if err := store.RecordUninstallNotice(notice); err != nil {
		return UninstallNoticeResult{}, err
	}
	if isOnline {
		// Queue the notice payload through the standard outbox so the controller
		// delivers its durable receipt; the receiver then GCs the row.
		payload, err := marshalUninstallNotice(operationID)
		if err != nil {
			return UninstallNoticeResult{}, err
		}
		if err := queueUninstallResult(ctx, store, operationID, payload, sessionIdentity...); err != nil {
			return UninstallNoticeResult{}, err
		}
	}
	marker, err := localstate.LoadMarker(stateDir)
	if err != nil {
		return UninstallNoticeResult{}, err
	}
	result := UninstallNoticeResult{OperationID: operationID, Online: isOnline}
	if isOnline {
		result.Status = "QUEUED"
	} else {
		result.Status = "UNKNOWN"
	}
	if marker != localstate.MarkerActive {
		result.TerminalRefused = true
	}
	return result, nil
}

func queueUninstallResult(ctx context.Context, store *localstate.Store, operationID string, payload []byte, sessionIdentity ...func() (uint64, string, error)) error {
	if len(sessionIdentity) == 0 || sessionIdentity[0] == nil {
		return store.QueueResultSessionIndependent(operationID, payload)
	}
	epoch, session, err := sessionIdentity[0]()
	if err != nil {
		return err
	}
	if epoch == 0 || session == "" {
		return store.QueueResultSessionIndependent(operationID, payload)
	}
	return RecordResult(ctx, store, epoch, session, operationID, payload)
}

// marshalUninstallNotice renders the wire notice payload.
func marshalUninstallNotice(operationID string) ([]byte, error) {
	env := struct {
		OperationID string `json:"deletion_operation_id"`
		Notice      string `json:"notice"`
	}{
		OperationID: operationID,
		Notice:      "agent uninstall requested",
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	_ = protocol.ProtocolDomain // boundary reference: the notice rides the control envelope domain
	return raw, nil
}

var errUninstallRequiresOperation = errUninstall("uninstall notice requires an operation id")
