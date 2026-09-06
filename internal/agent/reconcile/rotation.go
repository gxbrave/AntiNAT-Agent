// P14 Story 4 (agent side): accepting a controller key-rotation pin.
//
// The agent verifies the signed rotation certificate against its CURRENTLY
// pinned controller key, enforces the generation strictly increases, fsyncs
// the new pin set (bbolt write), then ACKs. A downgrade, wrong-signer, or
// certificate bound to a different pin is refused fail-closed.
package reconcile

import (
	"crypto/ed25519"
	"fmt"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// ErrRotationPinRefused is the fail-closed agent rotation refusal.
var ErrRotationPinRefused = fmt.Errorf("reconcile: controller pin rotation refused")

// AcceptControllerRotationPin verifies a controller key-rotation certificate
// against the pinned controller key and persists the successor pin at the
// higher generation. The bbolt write is durable (fsync) before this returns,
// so an ACK is only ever sent for a pin the agent can verify locally.
func AcceptControllerRotationPin(store *localstate.Store, instanceID string, certRaw []byte) (localstate.ControllerPin, security.RotationCertificate, error) {
	pin, found, err := store.ControllerPin(instanceID)
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, err
	}
	if !found {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: no pinned controller for %q", ErrRotationPinRefused, instanceID)
	}
	cert, err := security.DecodeRotationCertificate(certRaw, pin.PublicKey())
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: certificate: %v", ErrRotationPinRefused, err)
	}
	if cert.Scope != "controller" {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: scope %q", ErrRotationPinRefused, cert.Scope)
	}
	// repair-1 M1: the anti-downgrade comparison is the CERTIFICATE vs the
	// PERSISTED pin generation, which DecodeRotationCertificate cannot see. A
	// legit gen-4 pin must only accept a successor whose certificate chains
	// exactly from the persisted generation to a strictly higher one. A forged
	// gen-1->3 downgrade OR a cross-chain (gen-1->5) certificate signed by the
	// current key is refused fail-closed before any persistence.
	if cert.OldGeneration != pin.Generation {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: certificate old generation %d does not match persisted pin generation %d", ErrRotationPinRefused, cert.OldGeneration, pin.Generation)
	}
	if cert.NewGeneration <= pin.Generation {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: certificate new generation %d does not increase the persisted pin generation %d", ErrRotationPinRefused, cert.NewGeneration, pin.Generation)
	}
	newPub, _, err := cert.PublicKeys()
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, err
	}
	if cert.OldKeyID != security.KeyIDOf(pin.PublicKey()) {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: certificate old key id does not match persisted pin", ErrRotationPinRefused)
	}
	next := localstate.ControllerPin{
		InstanceID: instanceID, KeyID: cert.NewKeyID,
		PublicKeyRaw: append(ed25519.PublicKey(nil), newPub...),
		Generation:   cert.NewGeneration,
	}
	if err := store.SaveControllerPin(next); err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: persist successor pin: %v", ErrRotationPinRefused, err)
	}
	return next, cert, nil
}
