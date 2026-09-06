// P14 Story 5 (reconcile side): RECOVERY_QUARANTINE decision helper.
//
// LKG recovery is deferred when either one-way boundary is engaged: the
// terminal marker (DECOMMISSIONING/DECOMMISSIONED) or the restore quarantine
// marker. This is the reconcile-layer statement of the deep-spec rule that a
// restored Agent must NOT auto-restore its LKG listeners until the Controller
// issues a recovery authorization, and that the terminal/uninstall marker is
// never reopened by an old backup.
package reconcile

import (
	"fmt"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// DeferRecoveryReason classifies why LKG recovery is being deferred.
type DeferRecoveryReason string

const (
	// RecoveryAllowed means neither one-way boundary is engaged.
	RecoveryAllowed DeferRecoveryReason = ""
	// DeferredByTerminalMarker means the terminal marker is not ACTIVE.
	DeferredByTerminalMarker DeferRecoveryReason = "TERMINAL_MARKER"
	// DeferredByRecoveryQuarantine means the restore quarantine is set.
	DeferredByRecoveryQuarantine DeferRecoveryReason = "RECOVERY_QUARANTINE"
)

// RecoveryDeferred reports whether agent startup should skip the automatic
// last-known-good listener recovery pass and why. A DECOMMISSIONED marker takes
// priority over quarantine; the quarantine marker is never written over it.
func RecoveryDeferred(stateDir string, marker localstate.MarkerState) (bool, DeferRecoveryReason, error) {
	if marker != localstate.MarkerActive {
		return true, DeferredByTerminalMarker, nil
	}
	quarantined, err := localstate.LoadRecoveryQuarantine(stateDir)
	if err != nil {
		// repair-1 L6: an ambiguous/unreadable quarantine file must fail CLOSED.
		// The side-effect-deferred result is true (LKG recovery is NOT allowed)
		// and the error is surfaced, so even a caller that ignores the error
		// never auto-recovers listeners on an ambiguous quarantine file.
		return true, DeferredByRecoveryQuarantine, fmt.Errorf("reconcile: load recovery quarantine: %w", err)
	}
	if quarantined {
		return true, DeferredByRecoveryQuarantine, nil
	}
	return false, RecoveryAllowed, nil
}
