// Package protocol implements the frozen AntiNAT wire contracts
// (docs/protocol.md, docs/state-model.md): the signed control envelope, the
// enrollment transcript, the probe wire frames and their state machine, the
// strict JSON payload rules, the domain model types, and endpoint
// classification.
//
// Every parser validates framing, header, consistency, hash, and signature
// BEFORE any payload decode, and reports the exact frozen rejection stage.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

// Normative constants frozen by docs/protocol.md §3.1.
const (
	ProtocolDomain  = "AntiNAT-Control-v1"
	EnvelopeMagic   = "ANAT"
	WireVersion     = 1
	MaxHeaderBytes  = 4096
	MaxPayloadBytes = 65536
	MaxJSONDepth    = 16

	// DirectionC2A marks a Controller→Agent frame.
	DirectionC2A byte = 0x01
	// DirectionA2C marks an Agent→Controller frame.
	DirectionA2C byte = 0x02

	// MaxHeaderStringField is the frozen 1..255 bound on the variable-length
	// protected-header string fields (docs/protocol.md §3.2).
	MaxHeaderStringField = 255

	// EnvelopeSigLen is the fixed Ed25519 signature length.
	EnvelopeSigLen = ed25519.SignatureSize

	// EnvelopeHeaderFieldCount is the exact number of protected header
	// fields; the header must contain no trailing bytes.
	EnvelopeHeaderFieldCount = 14
)

// Stage is the phase at which a frame was rejected. The frozen contract
// requires all wire/header/hash/signature failures to happen BEFORE any
// payload decode; only strict JSON payload validation may fail in the
// payload stage.
type Stage int

const (
	// StageOK means the frame passed every pre-payload check.
	StageOK Stage = iota
	// StageFraming rejects the frame envelope layout itself.
	StageFraming
	// StageHeader rejects the protected header structure.
	StageHeader
	// StageConsistency rejects domain/length/hash/direction/credential
	// consistency.
	StageConsistency
	// StageSignature rejects Ed25519 verification.
	StageSignature
	// StagePayloadJSON rejects the strict JSON payload rules.
	StagePayloadJSON
)

func (s Stage) String() string {
	switch s {
	case StageFraming:
		return "framing"
	case StageHeader:
		return "header"
	case StageConsistency:
		return "consistency"
	case StageSignature:
		return "signature"
	case StagePayloadJSON:
		return "payload_json"
	default:
		return "ok"
	}
}

// Envelope is a fully parsed, verified control envelope.
type Envelope struct {
	HeaderLen  uint32
	PayloadLen uint32
	Header     ProtectedHeader
	// HeaderBytes are the exact protected header bytes (signed content).
	HeaderBytes []byte
	// Payload is the raw payload; it is NOT decoded here (payload decoding
	// is a separate stage).
	Payload []byte
	// Signature is the 64-byte Ed25519 signature.
	Signature []byte
}

// ProtectedHeader is the fixed ordered list of exactly 14 length-prefixed
// fields frozen by docs/protocol.md §3.2.
type ProtectedHeader struct {
	ProtocolDomain       string
	ControllerInstanceID [16]byte
	NodeID               [16]byte
	ControllerKeyID      string
	AgentCredentialVer   uint32
	ConnectionEpoch      uint64
	SessionID            string
	Direction            byte
	Sequence             uint64
	MessageID            [16]byte
	MessageType          string
	SchemaVersion        uint32
	PayloadLength        uint64
	PayloadSHA256        [32]byte
}

// validateHeaderStringFields enforces the frozen 1..255 bound on the
// variable-length protected-header string fields (docs/protocol.md §3.2:
// controller_key_id, session_id, message_type) on both the encode and decode
// paths so the codec never emits or accepts an out-of-range value.
func validateHeaderStringFields(h ProtectedHeader) error {
	if len(h.ControllerKeyID) == 0 || len(h.ControllerKeyID) > MaxHeaderStringField {
		return errors.New("protocol: controller_key_id must be 1..255 bytes")
	}
	if len(h.SessionID) == 0 || len(h.SessionID) > MaxHeaderStringField {
		return errors.New("protocol: session_id must be 1..255 bytes")
	}
	if len(h.MessageType) == 0 || len(h.MessageType) > MaxHeaderStringField {
		return errors.New("protocol: message_type must be 1..255 bytes")
	}
	return nil
}

// EncodeProtectedHeader renders the canonical length-prefixed header. It is
// used both by the encoder and by callers that must hash/pin the exact
// protected bytes.
func EncodeProtectedHeader(h ProtectedHeader) ([]byte, error) {
	if err := validateHeaderStringFields(h); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	putField := func(b []byte) error {
		if len(b) > math.MaxUint32 {
			return errors.New("protocol: header field too large")
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
		return nil
	}
	fields := [][]byte{
		[]byte(h.ProtocolDomain),
		h.ControllerInstanceID[:],
		h.NodeID[:],
		[]byte(h.ControllerKeyID),
		encodeU32(h.AgentCredentialVer),
		encodeU64(h.ConnectionEpoch),
		[]byte(h.SessionID),
		{h.Direction},
		encodeU64(h.Sequence),
		h.MessageID[:],
		[]byte(h.MessageType),
		encodeU32(h.SchemaVersion),
		encodeU64(h.PayloadLength),
		h.PayloadSHA256[:],
	}
	for _, f := range fields {
		if err := putField(f); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func encodeU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func encodeU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// decodeProtectedHeader parses and validates the 14 canonical fields.
func decodeProtectedHeader(b []byte) (ProtectedHeader, error) {
	var h ProtectedHeader
	idx := 0
	next := func() ([]byte, error) {
		if len(b)-idx < 4 {
			return nil, errors.New("protocol: header truncated in length prefix")
		}
		l := binary.BigEndian.Uint32(b[idx : idx+4])
		idx += 4
		if uint64(l) > uint64(len(b)-idx) {
			return nil, errors.New("protocol: header field length exceeds header")
		}
		f := b[idx : idx+int(l)]
		idx += int(l)
		return f, nil
	}
	var parts [EnvelopeHeaderFieldCount][]byte
	for i := range parts {
		f, err := next()
		if err != nil {
			return h, err
		}
		parts[i] = f
	}
	if idx != len(b) {
		return h, errors.New("protocol: trailing bytes after protected header")
	}
	h.ProtocolDomain = string(parts[0])
	if len(parts[1]) != 16 {
		return h, errors.New("protocol: controller_instance_id must be 16 bytes")
	}
	copy(h.ControllerInstanceID[:], parts[1])
	if len(parts[2]) != 16 {
		return h, errors.New("protocol: node_id must be 16 bytes")
	}
	copy(h.NodeID[:], parts[2])
	h.ControllerKeyID = string(parts[3])
	if len(parts[4]) != 4 {
		return h, errors.New("protocol: agent_credential_version must be 4 bytes")
	}
	h.AgentCredentialVer = binary.BigEndian.Uint32(parts[4])
	if len(parts[5]) != 8 {
		return h, errors.New("protocol: connection_epoch must be 8 bytes")
	}
	h.ConnectionEpoch = binary.BigEndian.Uint64(parts[5])
	h.SessionID = string(parts[6])
	if len(parts[7]) != 1 {
		return h, errors.New("protocol: direction must be 1 byte")
	}
	h.Direction = parts[7][0]
	if len(parts[8]) != 8 {
		return h, errors.New("protocol: sequence must be 8 bytes")
	}
	h.Sequence = binary.BigEndian.Uint64(parts[8])
	if len(parts[9]) != 16 {
		return h, errors.New("protocol: message_id must be 16 bytes")
	}
	copy(h.MessageID[:], parts[9])
	h.MessageType = string(parts[10])
	if len(parts[11]) != 4 {
		return h, errors.New("protocol: schema_version must be 4 bytes")
	}
	h.SchemaVersion = binary.BigEndian.Uint32(parts[11])
	if len(parts[12]) != 8 {
		return h, errors.New("protocol: payload_length must be 8 bytes")
	}
	h.PayloadLength = binary.BigEndian.Uint64(parts[12])
	if len(parts[13]) != 32 {
		return h, errors.New("protocol: payload_sha256 must be 32 bytes")
	}
	copy(h.PayloadSHA256[:], parts[13])
	if err := validateHeaderStringFields(h); err != nil {
		return h, err
	}
	return h, nil
}

// BuildEnvelope assembles a signed control frame from a protected header and
// payload. It fills payload_length and payload_sha256, enforces the frozen
// caps, and signs the frozen signature input.
func BuildEnvelope(priv ed25519.PrivateKey, h ProtectedHeader, payload []byte) ([]byte, error) {
	h.PayloadLength = uint64(len(payload))
	sum := sha256.Sum256(payload)
	h.PayloadSHA256 = sum
	headerBytes, err := EncodeProtectedHeader(h)
	if err != nil {
		return nil, err
	}
	if len(headerBytes) > MaxHeaderBytes {
		return nil, errors.New("protocol: protected header exceeds maxHeaderBytes")
	}
	if len(payload) > MaxPayloadBytes {
		return nil, errors.New("protocol: payload exceeds maxPayloadBytes")
	}
	if len(priv) != framecrypto.PrivateKeySize {
		return nil, framecrypto.ErrInvalidKeySize
	}
	sig, err := framecrypto.SignEnvelope(priv, []byte(h.ProtocolDomain), headerBytes, h.PayloadSHA256[:])
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, 13+len(headerBytes)+len(payload)+EnvelopeSigLen)
	frame = append(frame, EnvelopeMagic...)
	frame = append(frame, WireVersion)
	frame = append(frame, encodeU32(uint32(len(headerBytes)))...)
	frame = append(frame, encodeU32(uint32(len(payload)))...)
	frame = append(frame, headerBytes...)
	frame = append(frame, payload...)
	frame = append(frame, sig...)
	return frame, nil
}

// ParseEnvelope validates framing, header, consistency, and signature in the
// frozen order and returns the stage at which validation stopped. It never
// decodes the payload; strict JSON payload validation is a separate stage.
// The Envelope returned on success exposes the raw payload only after every
// pre-payload check has passed.
func ParseEnvelope(frame []byte, peer ed25519.PublicKey) (Envelope, Stage, error) {
	var env Envelope
	if len(frame) < 13+EnvelopeSigLen {
		return env, StageFraming, errors.New("protocol: frame shorter than minimum envelope")
	}
	if !bytes.Equal(frame[:4], []byte(EnvelopeMagic)) {
		return env, StageFraming, errors.New("protocol: bad magic")
	}
	if frame[4] != WireVersion {
		return env, StageFraming, fmt.Errorf("protocol: unsupported wire version %d", frame[4])
	}
	headerLen := binary.BigEndian.Uint32(frame[5:9])
	payloadLen := binary.BigEndian.Uint32(frame[9:13])
	if headerLen == 0 || headerLen > MaxHeaderBytes {
		return env, StageFraming, errors.New("protocol: header length out of range")
	}
	if payloadLen > MaxPayloadBytes {
		return env, StageFraming, errors.New("protocol: payload length out of range")
	}
	if uint64(len(frame)) != uint64(13)+uint64(headerLen)+uint64(payloadLen)+uint64(EnvelopeSigLen) {
		return env, StageFraming, errors.New("protocol: frame length inconsistent with declared lengths")
	}
	headerBytes := frame[13 : 13+headerLen]
	payload := frame[13+headerLen : 13+headerLen+payloadLen]
	sig := frame[13+headerLen+payloadLen:]

	header, err := decodeProtectedHeader(headerBytes)
	if err != nil {
		return env, StageHeader, err
	}
	if header.ProtocolDomain != ProtocolDomain {
		return env, StageConsistency, errors.New("protocol: protocol domain mismatch")
	}
	if header.PayloadLength != uint64(payloadLen) {
		return env, StageConsistency, errors.New("protocol: payload_length header field does not match frame length")
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], header.PayloadSHA256[:]) {
		return env, StageConsistency, errors.New("protocol: payload sha256 mismatch")
	}
	if header.Direction != DirectionC2A && header.Direction != DirectionA2C {
		return env, StageConsistency, errors.New("protocol: invalid direction byte")
	}
	if header.AgentCredentialVer == 0 {
		return env, StageConsistency, errors.New("protocol: agent credential version must be non-zero")
	}
	if len(peer) != framecrypto.PublicKeySize {
		return env, StageConsistency, errors.New("protocol: invalid peer key size")
	}
	if !framecrypto.VerifyEnvelope(peer, []byte(header.ProtocolDomain), headerBytes, header.PayloadSHA256[:], sig) {
		return env, StageSignature, errors.New("protocol: signature verification failed")
	}
	env.HeaderLen = headerLen
	env.PayloadLen = payloadLen
	env.Header = header
	env.HeaderBytes = headerBytes
	env.Payload = payload
	env.Signature = sig
	return env, StageOK, nil
}
