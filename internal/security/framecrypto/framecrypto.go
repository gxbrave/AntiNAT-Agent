// Package framecrypto provides the bounded Ed25519 primitives used to sign
// and verify AntiNAT fixed wire frames (control envelope, enrollment
// transcript, probe frames).
//
// The signature inputs are the exact protected bytes frozen by
// docs/protocol.md: for the control envelope the input is
// domain || protected_header_bytes || payload_sha256; probe and enrollment
// frames sign their canonical encoding with the frame magic/domain carried
// inside the signed bytes.
//
// All entry points validate key and signature sizes and fail closed; they
// never panic on malformed inputs.
package framecrypto

import (
	"crypto/ed25519"
	"errors"
)

// Size constants mirror crypto/ed25519 so callers never import the raw
// package for constants alone.
const (
	PublicKeySize  = ed25519.PublicKeySize  // 32
	PrivateKeySize = ed25519.PrivateKeySize // 64
	SignatureSize  = ed25519.SignatureSize  // 64
)

var (
	// ErrInvalidKeySize reports a private or public key of the wrong size.
	ErrInvalidKeySize = errors.New("framecrypto: invalid ed25519 key size")
	// ErrInvalidSignatureSize reports a signature of the wrong size.
	ErrInvalidSignatureSize = errors.New("framecrypto: invalid signature size")
)

// Sign returns the Ed25519 signature of message under priv. It fails closed
// on a private key of the wrong size rather than panicking.
func Sign(priv ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(priv) != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}
	return ed25519.Sign(priv, message), nil
}

// Verify reports whether sig is a valid Ed25519 signature of message under
// pub. Wrong-size keys and signatures always return false.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(pub) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// EnvelopeSignatureInput builds the frozen control-envelope signature input:
// protocol_domain_bytes || protected_header_bytes || payload_sha256_bytes.
func EnvelopeSignatureInput(domain, protectedHeader, payloadSHA256 []byte) []byte {
	out := make([]byte, 0, len(domain)+len(protectedHeader)+len(payloadSHA256))
	out = append(out, domain...)
	out = append(out, protectedHeader...)
	out = append(out, payloadSHA256...)
	return out
}

// SignEnvelope signs the frozen control-envelope signature input.
func SignEnvelope(priv ed25519.PrivateKey, domain, protectedHeader, payloadSHA256 []byte) ([]byte, error) {
	return Sign(priv, EnvelopeSignatureInput(domain, protectedHeader, payloadSHA256))
}

// VerifyEnvelope verifies the frozen control-envelope signature input.
func VerifyEnvelope(pub ed25519.PublicKey, domain, protectedHeader, payloadSHA256, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return Verify(pub, EnvelopeSignatureInput(domain, protectedHeader, payloadSHA256), sig)
}

// DomainSeparatedMessage returns domain || message for the enrollment and
// probe transcripts, which sign domain-separated canonical fields.
func DomainSeparatedMessage(domain string, canonical []byte) []byte {
	out := make([]byte, 0, len(domain)+len(canonical))
	out = append(out, domain...)
	out = append(out, canonical...)
	return out
}
