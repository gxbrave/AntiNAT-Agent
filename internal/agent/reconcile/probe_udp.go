package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/netip"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// UDPProbeResult is a socket-independent classifier action. The single UDP
// ingress reader owns recvfrom/sendto; the probe manager only authenticates and
// durably consumes the datagram, then returns the exact ACK and control receipt.
type UDPProbeResult struct {
	Matched bool
	// Drop marks a full-match control frame that cannot be safely processed
	// (capacity overflow, recovery error, or store failure). The classifier must
	// consume it without ACK and without forwarding it to the business backend —
	// fail closed, symmetric with the TCP probe gate quarantine.
	Drop    bool
	ProbeID [protocol.ProbeIDLen]byte
	ACK     []byte
	Receipt []byte
}

// HandleUDPProbe classifies one complete UDP datagram. A valid full-match WAN1
// is consumed by the existing durable ProbeManager state machine. Invalid
// lookalikes return zero material and must fall through to the business path.
// A replay of an already-consumed probe is matched (so it is never forwarded to
// business), but ACK1 is returned only while the durable ACK remains unsent.
func (m *ProbeManager) HandleUDPProbe(forwardID string, source netip.AddrPort, raw []byte) UDPProbeResult {
	if m == nil || !source.IsValid() || !source.Addr().Is4() {
		return UDPProbeResult{}
	}
	frame, err := protocol.ParseProviderFrame(raw)
	if err != nil {
		return UDPProbeResult{}
	}
	var sourceIP [4]byte
	sourceIP = source.Addr().Unmap().As4()
	now := m.clock()

	m.mu.Lock()
	m.sweep(now)
	if m.recoveryErr != nil {
		// Probe state is unavailable or overflowing after recovery: consuming any
		// probe now would be unverifiable, so fail closed rather than risk a
		// control frame reaching the business backend.
		m.mu.Unlock()
		return UDPProbeResult{Drop: true}
	}
	if _, replayed := m.replay[frame.ProbeID]; replayed {
		binding, bound := m.replaySource[frame.ProbeID]
		m.mu.Unlock()
		if !bound || binding.digest != frame.ArmDigest || binding.source != sourceIP || binding.forwardID != forwardID || m.store == nil {
			return UDPProbeResult{}
		}
		rec, ok, err := m.store.LoadArmedProbe(frame.ProbeID)
		if err != nil || !ok || !rec.Consumed || rec.Arm.ExpectedSourceIP != sourceIP || rec.ForwardID != forwardID ||
			rec.Digest != frame.ArmDigest || rec.Arm.ProviderID != frame.ProviderID || rec.Arm.Activation != frame.Activation ||
			rec.Arm.Endpoint != frame.Endpoint || rec.Arm.ExpiryOpaque != frame.ExpiryOpaque || rec.ChallengeHash != frame.ChallengeHash() ||
			!ed25519.Verify(rec.Arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
			return UDPProbeResult{}
		}
		result := UDPProbeResult{Matched: true, ProbeID: frame.ProbeID}
		if !rec.ACKSent {
			result.ACK = append([]byte(nil), rec.ACK...)
		}
		return result
	}

	op := m.ops[frame.ProbeID]
	if op == nil || op.used || !now.Before(op.deadline) || op.forwardID != forwardID ||
		op.arm.ExpectedSourceIP != sourceIP || op.digest != frame.ArmDigest ||
		op.arm.ProviderID != frame.ProviderID || op.arm.Activation != frame.Activation ||
		op.arm.Endpoint != frame.Endpoint || op.arm.ExpiryOpaque != frame.ExpiryOpaque ||
		!ed25519.Verify(op.arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
		// Not a full outstanding match: indistinguishable from ordinary traffic.
		m.mu.Unlock()
		return UDPProbeResult{}
	}
	// A structurally complete, full-match WAN1 that cannot be processed because
	// of capacity or state availability is consumed without ACK and never
	// forwarded to the business backend (fail closed).
	if m.key == nil || m.store == nil || len(m.replay) >= m.maxReplay {
		m.mu.Unlock()
		return UDPProbeResult{Drop: true}
	}

	chash := frame.ChallengeHash()
	ackSigning := make([]byte, 0, 4+2*protocol.ProbeDigestLen)
	ackSigning = append(ackSigning, protocol.ProbeMagicACK...)
	ackSigning = append(ackSigning, op.digest[:]...)
	ackSigning = append(ackSigning, chash[:]...)
	ackSig, err := m.key.Sign(ackSigning)
	if err != nil {
		m.mu.Unlock()
		return UDPProbeResult{}
	}
	ack := append(append([]byte(nil), ackSigning...), ackSig...)
	if len(ack) > len(raw) { // frozen UDP anti-amplification rule
		m.mu.Unlock()
		return UDPProbeResult{}
	}

	var receiptSigning bytes.Buffer
	receiptSigning.WriteString(protocol.ProbeMagicReceipt)
	receiptSigning.Write(op.digest[:])
	receiptSigning.Write(chash[:])
	receiptSigning.Write(op.arm.ProviderID[:])
	receiptSig, err := m.key.Sign(receiptSigning.Bytes())
	if err != nil {
		m.mu.Unlock()
		return UDPProbeResult{}
	}
	receipt := append(append([]byte(nil), receiptSigning.Bytes()...), receiptSig...)
	receiptID := probeReceiptOperationID(receipt)
	receiptDeadline := op.deadline.Add(protocol.ProbeReplayWindow)

	// Serialize durable consumption with the in-memory operation lock. This is a
	// rare control datagram and preserves exactly-once admission across concurrent
	// classifier calls without introducing a second state machine.
	if err := m.store.MarkArmedProbeConsumedWithACK(frame.ProbeID, receipt, ack, chash, receiptID, receiptDeadline); err != nil {
		// A full-match probe that could not be durably consumed must not reach
		// the business backend or produce an ack; drop it (fail closed).
		m.mu.Unlock()
		return UDPProbeResult{Drop: true}
	}
	op.used = true
	m.replay[frame.ProbeID] = receiptDeadline
	m.replaySource[frame.ProbeID] = replaySource{source: sourceIP, forwardID: forwardID, digest: op.digest}
	m.mu.Unlock()

	return UDPProbeResult{Matched: true, ProbeID: frame.ProbeID, ACK: ack, Receipt: receipt}
}

// MarkUDPProbeACKSent records completion after the single ingress socket has
// sent every ACK byte to the datagram's exact source tuple.
func (m *ProbeManager) MarkUDPProbeACKSent(probeID [protocol.ProbeIDLen]byte) error {
	if m == nil || m.store == nil {
		return ErrProbeArmRejected
	}
	return m.store.MarkArmedProbeACKSent(probeID)
}

// MarkUDPProbeReceiptSent records completion after the existing signed control
// sender has accepted the receipt returned by HandleUDPProbe.
func (m *ProbeManager) MarkUDPProbeReceiptSent(probeID [protocol.ProbeIDLen]byte) error {
	if m == nil || m.store == nil {
		return ErrProbeArmRejected
	}
	return m.store.MarkArmedProbeReceiptSent(probeID)
}

// SendUDPProbeReceipt pushes the durable RCT1 receipt over the signed control
// channel and marks transport delivery once accepted, mirroring the TCP ingress
// path. A failed send stays retryable through RetryPendingReceipts.
func (m *ProbeManager) SendUDPProbeReceipt(result UDPProbeResult) {
	if m == nil || m.store == nil || len(result.Receipt) == 0 || m.send == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.sendTimeout)
	defer cancel()
	if m.send(ctx, "probe_ingress_receipt", result.Receipt) == nil {
		_ = m.store.MarkArmedProbeReceiptSent(result.ProbeID)
	}
}
