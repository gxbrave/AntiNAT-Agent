// Bounded STUN RFC 8489 message codec. The codec parses and builds STUN
// messages with strict bounds: the 16-bit message length must be a multiple
// of 4 (RFC 8489 §5), every attribute must fit inside the declared message,
// FINGERPRINT must be the last attribute (RFC 8489 §14.7), and attributes
// after MESSAGE-INTEGRITY other than FINGERPRINT are ignored by the
// integrity computation (RFC 8489 §14.5). Unknown comprehension-required
// attributes are reported so a server can answer 420 (RFC 8489 §14.8);
// comprehension-optional attributes are skipped. MESSAGE-INTEGRITY supports
// the short-term credential boundary (HMAC-SHA1 keyed by the password);
// long-term credentials are an explicit non-goal of v1 STUN keepalive.
package stun

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
)

// Wire constants (RFC 8489 §5, §14).
const (
	MagicCookie     = 0x2112A442
	HeaderSize      = 20
	MaxMessageSize  = 65535 // attribute section bound implied by the 16-bit length field
	fingerprintXor  = 0x5354554E
	integrityLength = 20 // HMAC-SHA1
)

// Codec sentinel errors. Parse failures never panic and always return one of
// these so callers can classify truncated versus malformed input.
var (
	ErrTruncated            = errors.New("stun: message shorter than its header/length declares")
	ErrMalformed            = errors.New("stun: malformed message structure")
	ErrBadCookie            = errors.New("stun: bad magic cookie")
	ErrOversize             = errors.New("stun: message exceeds the bounded maximum size")
	ErrNoIntegrity          = errors.New("stun: message has no MESSAGE-INTEGRITY attribute")
	ErrNoFingerprint        = errors.New("stun: message has no FINGERPRINT attribute")
	ErrIntegrityMismatch    = errors.New("stun: MESSAGE-INTEGRITY verification failed")
	ErrFingerprintMismatch  = errors.New("stun: FINGERPRINT verification failed")
	ErrUnknownFamily        = errors.New("stun: unknown address family in address attribute")
	ErrDuplicateAddressAttr = errors.New("stun: multiple MAPPED-ADDRESS-family attributes")
)

// Method is the 12-bit STUN method (RFC 8489 §5). v1 uses Binding only.
type Method uint16

const MethodBinding Method = 0x001

// Class is the 2-bit STUN message class (RFC 8489 §5).
type Class uint8

const (
	ClassRequest    Class = 0 // 0b00
	ClassIndication Class = 1 // 0b01
	ClassSuccess    Class = 2 // 0b10
	ClassError      Class = 3 // 0b11
)

// MessageType is the 14-bit wire message type.
type MessageType uint16

// Canonical Binding message types.
const (
	MessageTypeBindingRequest    MessageType = 0x0001
	MessageTypeBindingIndication MessageType = 0x0011
	MessageTypeBindingSuccess    MessageType = 0x0101
	MessageTypeBindingError      MessageType = 0x0111
)

// Method extracts the 12-bit method from the wire type (Figure 3 layout:
// M11..M8 at bits 15..12, M7..M3 at bits 10..6, M2..M0 at bits 4..2).
func (t MessageType) Method() Method {
	v := uint16(t)
	return Method(v&0x000F | (v>>1)&0x0070 | (v>>2)&0x0F80)
}

// Class extracts the 2-bit class (C1 at bit 11, C0 at bit 5).
func (t MessageType) Class() Class {
	v := uint16(t)
	return Class((v>>7)&0x2 | (v>>4)&0x1)
}

// NewMessageType encodes method and class into the wire type field.
func NewMessageType(method Method, class Class) MessageType {
	m := uint16(method)
	c := uint16(class)
	return MessageType(m&0x000F | (m&0x0070)<<1 | (m&0x0F80)<<2 | (c&0x2)<<7 | (c&0x1)<<4)
}

// AttributeType is the 16-bit STUN attribute type. Types below 0x8000 are
// comprehension-required (RFC 8489 §14); unknown required attributes in a
// request demand a 420 error response.
type AttributeType uint16

// Attributes the v1 codec understands.
const (
	AttrMappedAddress     AttributeType = 0x0001
	AttrUsername          AttributeType = 0x0006
	AttrMessageIntegrity  AttributeType = 0x0008
	AttrErrorCode         AttributeType = 0x0009
	AttrUnknownAttributes AttributeType = 0x000A
	AttrXORMappedAddress  AttributeType = 0x0020
	AttrAlternateServer   AttributeType = 0x0023
	AttrPriority          AttributeType = 0x0024
	AttrSoftware          AttributeType = 0x8022
	AttrIceControlled     AttributeType = 0x8029
	AttrFingerprint       AttributeType = 0x8028
)

// comprehensionRequired reports whether the type's top bit is clear.
func (t AttributeType) comprehensionRequired() bool { return t&0x8000 == 0 }

// knownAttribute reports whether the codec understands the type.
func (t AttributeType) known() bool {
	switch t {
	case AttrMappedAddress, AttrUsername, AttrMessageIntegrity, AttrErrorCode,
		AttrUnknownAttributes, AttrXORMappedAddress, AttrAlternateServer,
		AttrPriority, AttrSoftware, AttrIceControlled, AttrFingerprint:
		return true
	}
	return false
}

// TransactionID is the 96-bit transaction identifier.
type TransactionID [12]byte

// Attribute is one raw TLV in wire order. Value excludes padding.
type Attribute struct {
	Type  AttributeType
	Value []byte
}

// Message is a parsed or buildable STUN message. Messages produced by
// ParseMessage retain the exact wire bytes so MESSAGE-INTEGRITY and
// FINGERPRINT verification run over the original encoding (attribute padding
// bytes are not recoverable from the parsed attribute values alone).
type Message struct {
	Type          MessageType
	TransactionID TransactionID
	Attributes    []Attribute
	raw           []byte
}

// NewBindingRequest builds a Binding request carrying the given transaction
// ID (RFC 8489 §6.3).
func NewBindingRequest(txid TransactionID) *Message {
	return &Message{Type: MessageTypeBindingRequest, TransactionID: txid}
}

// NewErrorResponse builds a Binding error response with ERROR-CODE.
func NewErrorResponse(txid TransactionID, code int, reason string) *Message {
	msg := &Message{Type: MessageTypeBindingError, TransactionID: txid}
	_ = msg.SetErrorCode(code, reason)
	return msg
}

// NewTransactionID draws 96 bits from the CSPRNG (RFC 8489 §5: transaction
// IDs MUST be cryptographically random).
func NewTransactionID() (TransactionID, error) {
	var txid TransactionID
	if _, err := rand.Read(txid[:]); err != nil {
		return TransactionID{}, fmt.Errorf("stun: transaction id: %w", err)
	}
	return txid, nil
}

// Add appends an attribute in wire order.
func (m *Message) Add(t AttributeType, value []byte) {
	m.Attributes = append(m.Attributes, Attribute{Type: t, Value: value})
}

// Get returns the first attribute of the given type.
func (m *Message) Get(t AttributeType) ([]byte, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == t {
			return attr.Value, true
		}
	}
	return nil, false
}

// Count returns how many attributes of the type are present.
func (m *Message) Count(t AttributeType) int {
	n := 0
	for _, attr := range m.Attributes {
		if attr.Type == t {
			n++
		}
	}
	return n
}

// UnknownComprehensionRequired lists comprehension-required attribute types
// the codec does not understand (RFC 8489 §6.4: respond 420 with
// UNKNOWN-ATTRIBUTES when a request carries any).
func (m *Message) UnknownComprehensionRequired() []AttributeType {
	var unknown []AttributeType
	seen := map[AttributeType]bool{}
	for _, attr := range m.Attributes {
		if attr.Type.comprehensionRequired() && !attr.Type.known() && !seen[attr.Type] {
			seen[attr.Type] = true
			unknown = append(unknown, attr.Type)
		}
	}
	return unknown
}

// ParseMessage decodes one bounded STUN message. It never panics and never
// allocates more than the input size. The declared length must equal the
// actual attribute-section size (bounds are strict).
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrTruncated
	}
	if binary.BigEndian.Uint32(data[4:8]) != MagicCookie {
		return nil, ErrBadCookie
	}
	declared := int(binary.BigEndian.Uint16(data[2:4]))
	if declared > MaxMessageSize {
		return nil, ErrOversize
	}
	if declared%4 != 0 {
		return nil, ErrMalformed
	}
	if len(data)-HeaderSize < declared {
		return nil, ErrTruncated
	}
	msg := &Message{
		Type:          MessageType(binary.BigEndian.Uint16(data[0:2])),
		TransactionID: TransactionID(*(*[12]byte)(data[8:20])),
		raw:           append([]byte(nil), data[:HeaderSize+declared]...),
	}
	rest := data[HeaderSize : HeaderSize+declared]
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, ErrMalformed
		}
		attrType := AttributeType(binary.BigEndian.Uint16(rest[0:2]))
		attrLen := int(binary.BigEndian.Uint16(rest[2:4]))
		if attrLen > len(rest)-4 {
			return nil, ErrTruncated
		}
		value := rest[4 : 4+attrLen]
		msg.Attributes = append(msg.Attributes, Attribute{Type: attrType, Value: value})
		// Attributes are padded to a 4-byte boundary; the padding is not
		// part of the attribute length but is part of the message length.
		padded := (4 + attrLen + 3) &^ 3
		rest = rest[padded:]
	}
	// FINGERPRINT must be the last attribute (RFC 8489 §14.7).
	if msg.Count(AttrFingerprint) > 0 && msg.Attributes[len(msg.Attributes)-1].Type != AttrFingerprint {
		return nil, ErrMalformed
	}
	return msg, nil
}

// attributeSectionLength returns the padded wire size of all attributes.
func (m *Message) attributeSectionLength() int {
	total := 0
	for _, attr := range m.Attributes {
		total += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	return total
}

// Marshal encodes the message with the current attributes. Callers that want
// MESSAGE-INTEGRITY or FINGERPRINT on the wire must call AddMessageIntegrity
// and AddFingerprint before Marshal (RFC 8489 §14.5/§14.7 ordering).
func (m *Message) Marshal() ([]byte, error) {
	section := m.attributeSectionLength()
	if section > MaxMessageSize {
		return nil, ErrOversize
	}
	out := make([]byte, HeaderSize+section)
	binary.BigEndian.PutUint16(out[0:2], uint16(m.Type))
	binary.BigEndian.PutUint16(out[2:4], uint16(section))
	binary.BigEndian.PutUint32(out[4:8], MagicCookie)
	copy(out[8:20], m.TransactionID[:])
	offset := HeaderSize
	for _, attr := range m.Attributes {
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(len(attr.Value)))
		copy(out[offset+4:], attr.Value)
		offset += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	return out, nil
}

// AddXORMappedAddress appends an XOR-MAPPED-ADDRESS attribute
// (RFC 8489 §14.2: X-Port = port XOR cookie>>16; X-Address = address XOR
// magic cookie for IPv4, XOR cookie||transaction ID for IPv6).
func (m *Message) AddXORMappedAddress(addr netip.AddrPort) error {
	if m.Count(AttrXORMappedAddress) > 0 {
		return ErrDuplicateAddressAttr
	}
	ip := addr.Addr()
	var value []byte
	switch {
	case ip.Is4():
		value = make([]byte, 8)
		value[1] = 0x01
		ip4 := ip.As4()
		binary.BigEndian.PutUint16(value[2:4], addr.Port()^uint16(MagicCookie>>16))
		value[4] = ip4[0] ^ byte(MagicCookie>>24&0xFF)
		value[5] = ip4[1] ^ byte(MagicCookie>>16&0xFF)
		value[6] = ip4[2] ^ byte(MagicCookie>>8&0xFF)
		value[7] = ip4[3] ^ byte(MagicCookie&0xFF)
	case ip.Is6() && !ip.Is4In6():
		value = make([]byte, 20)
		value[1] = 0x02
		binary.BigEndian.PutUint16(value[2:4], addr.Port()^uint16(MagicCookie>>16))
		ip16 := ip.As16()
		cookieTxid := make([]byte, 16)
		binary.BigEndian.PutUint32(cookieTxid[0:4], MagicCookie)
		copy(cookieTxid[4:16], m.TransactionID[:])
		for i := 0; i < 16; i++ {
			value[4+i] = ip16[i] ^ cookieTxid[i]
		}
	default:
		return fmt.Errorf("%w: %v", ErrUnknownFamily, ip)
	}
	m.Add(AttrXORMappedAddress, value)
	return nil
}

// XORMappedAddress decodes the single XOR-MAPPED-ADDRESS attribute. Multiple
// occurrences are malformed (RFC 8489 §14.2).
func (m *Message) XORMappedAddress() (netip.AddrPort, error) {
	value, ok := m.Get(AttrXORMappedAddress)
	if !ok {
		return netip.AddrPort{}, ErrUnknownFamily
	}
	if m.Count(AttrXORMappedAddress) > 1 {
		return netip.AddrPort{}, ErrDuplicateAddressAttr
	}
	return decodeAddressAttribute(value, m.TransactionID, true)
}

// AddAlternateServer appends ALTERNATE-SERVER (RFC 8489 §14.15: encoded like
// MAPPED-ADDRESS, plain family/port/address).
func (m *Message) AddAlternateServer(addr netip.AddrPort) error {
	ip := addr.Addr()
	var value []byte
	switch {
	case ip.Is4():
		value = make([]byte, 8)
		value[1] = 0x01
		ip4 := ip.As4()
		binary.BigEndian.PutUint16(value[2:4], addr.Port())
		copy(value[4:8], ip4[:])
	case ip.Is6() && !ip.Is4In6():
		value = make([]byte, 20)
		value[1] = 0x02
		binary.BigEndian.PutUint16(value[2:4], addr.Port())
		ip16 := ip.As16()
		copy(value[4:20], ip16[:])
	default:
		return fmt.Errorf("%w: %v", ErrUnknownFamily, ip)
	}
	m.Add(AttrAlternateServer, value)
	return nil
}

// AlternateServer decodes the single ALTERNATE-SERVER attribute.
func (m *Message) AlternateServer() (netip.AddrPort, error) {
	value, ok := m.Get(AttrAlternateServer)
	if !ok {
		return netip.AddrPort{}, ErrUnknownFamily
	}
	if m.Count(AttrAlternateServer) > 1 {
		return netip.AddrPort{}, ErrDuplicateAddressAttr
	}
	return decodeAddressAttribute(value, m.TransactionID, false)
}

// decodeAddressAttribute decodes MAPPED-ADDRESS-family values. When xor is
// true the port/address are de-obfuscated with the magic cookie (and
// transaction ID for IPv6) as in XOR-MAPPED-ADDRESS.
func decodeAddressAttribute(value []byte, txid TransactionID, xor bool) (netip.AddrPort, error) {
	if len(value) < 4 {
		return netip.AddrPort{}, ErrMalformed
	}
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	switch value[1] {
	case 0x01:
		if len(value) < 8 {
			return netip.AddrPort{}, ErrMalformed
		}
		var ip4 [4]byte
		copy(ip4[:], value[4:8])
		if xor {
			ip4[0] ^= byte(MagicCookie >> 24 & 0xFF)
			ip4[1] ^= byte(MagicCookie >> 16 & 0xFF)
			ip4[2] ^= byte(MagicCookie >> 8 & 0xFF)
			ip4[3] ^= byte(MagicCookie & 0xFF)
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip4), port), nil
	case 0x02:
		if len(value) < 20 {
			return netip.AddrPort{}, ErrMalformed
		}
		var ip16 [16]byte
		copy(ip16[:], value[4:20])
		if xor {
			cookieTxid := make([]byte, 16)
			binary.BigEndian.PutUint32(cookieTxid[0:4], MagicCookie)
			copy(cookieTxid[4:16], txid[:])
			for i := 0; i < 16; i++ {
				ip16[i] ^= cookieTxid[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip16), port), nil
	}
	return netip.AddrPort{}, ErrUnknownFamily
}

// SetErrorCode appends ERROR-CODE (RFC 8489 §14.8: two reserved bytes, class
// = hundreds digit, number = code modulo 100, then the reason phrase).
func (m *Message) SetErrorCode(code int, reason string) error {
	if code < 300 || code > 699 {
		return fmt.Errorf("stun: error code %d out of 300..699 range", code)
	}
	value := make([]byte, 4+len(reason))
	value[2] = byte(code / 100)
	value[3] = byte(code % 100)
	copy(value[4:], reason)
	m.Add(AttrErrorCode, value)
	return nil
}

// ErrorCode decodes ERROR-CODE and returns the numeric code and reason.
func (m *Message) ErrorCode() (int, string, error) {
	value, ok := m.Get(AttrErrorCode)
	if !ok {
		return 0, "", ErrMalformed
	}
	if m.Count(AttrErrorCode) > 1 || len(value) < 4 {
		return 0, "", ErrMalformed
	}
	code := int(value[2])*100 + int(value[3])
	if code < 300 || code > 699 {
		return 0, "", ErrMalformed
	}
	return code, string(value[4:]), nil
}

// AddUnknownAttributes appends UNKNOWN-ATTRIBUTES (RFC 8489 §14.10) listing
// the 16-bit types a 420 response must echo.
func (m *Message) AddUnknownAttributes(types []AttributeType) {
	value := make([]byte, 0, 2*len(types))
	for _, t := range types {
		value = binary.BigEndian.AppendUint16(value, uint16(t))
	}
	m.Add(AttrUnknownAttributes, value)
}

// UnknownAttributes decodes the UNKNOWN-ATTRIBUTES list.
func (m *Message) UnknownAttributes() ([]AttributeType, error) {
	value, ok := m.Get(AttrUnknownAttributes)
	if !ok {
		return nil, nil
	}
	if len(value)%2 != 0 {
		return nil, ErrMalformed
	}
	out := make([]AttributeType, 0, len(value)/2)
	for i := 0; i < len(value); i += 2 {
		out = append(out, AttributeType(binary.BigEndian.Uint16(value[i:i+2])))
	}
	return out, nil
}

// AddMessageIntegrity appends MESSAGE-INTEGRITY using the short-term
// credential boundary (RFC 8489 §9.1.1: HMAC-SHA1 keyed by the password).
// The HMAC input is the header whose Length field points to the end of the
// MESSAGE-INTEGRITY attribute, followed by every attribute preceding it
// (RFC 8489 §14.5). A second MESSAGE-INTEGRITY is rejected.
func (m *Message) AddMessageIntegrity(key []byte) error {
	if m.Count(AttrMessageIntegrity) > 0 {
		return errors.New("stun: message already carries MESSAGE-INTEGRITY")
	}
	section := m.attributeSectionLength()
	if section+4+integrityLength > MaxMessageSize {
		return ErrOversize
	}
	// The HMAC input is the header (whose Length field points to the end of
	// the MESSAGE-INTEGRITY attribute) followed by every attribute preceding
	// it. The MESSAGE-INTEGRITY attribute itself is not part of the input
	// (RFC 8489 §14.5); the adjusted length field carries its size.
	wire := make([]byte, HeaderSize+section)
	binary.BigEndian.PutUint16(wire[0:2], uint16(m.Type))
	binary.BigEndian.PutUint16(wire[2:4], uint16(section+4+integrityLength))
	binary.BigEndian.PutUint32(wire[4:8], MagicCookie)
	copy(wire[8:20], m.TransactionID[:])
	offset := HeaderSize
	for _, attr := range m.Attributes {
		binary.BigEndian.PutUint16(wire[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(wire[offset+2:offset+4], uint16(len(attr.Value)))
		copy(wire[offset+4:], attr.Value)
		offset += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(wire)
	m.Add(AttrMessageIntegrity, mac.Sum(nil))
	return nil
}

// VerifyMessageIntegrity recomputes the HMAC-SHA1 over the message up to the
// MESSAGE-INTEGRITY attribute (Length adjusted to its end) and compares in
// constant time. Attributes after MESSAGE-INTEGRITY other than FINGERPRINT
// are ignored by the computation (RFC 8489 §14.5). Parsed messages verify
// against their original wire bytes so exotic padding is preserved.
func (m *Message) VerifyMessageIntegrity(key []byte) (bool, error) {
	idx := -1
	for i, attr := range m.Attributes {
		if attr.Type == AttrMessageIntegrity {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, ErrNoIntegrity
	}
	if m.Count(AttrMessageIntegrity) > 1 {
		return false, ErrMalformed
	}
	stored := m.Attributes[idx].Value
	if len(stored) != integrityLength {
		return false, ErrMalformed
	}
	wire, err := m.integrityInput(idx)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(wire)
	return hmac.Equal(mac.Sum(nil), stored), nil
}

// integrityInput returns the exact HMAC input bytes: the header (Length
// pointing to the end of the MESSAGE-INTEGRITY attribute) plus every
// attribute preceding it, either from the original wire or rebuilt from the
// parsed attributes.
func (m *Message) integrityInput(idx int) ([]byte, error) {
	section := 0
	for i := 0; i < idx; i++ {
		section += 4 + ((len(m.Attributes[i].Value) + 3) &^ 3)
	}
	wire := make([]byte, HeaderSize+section)
	binary.BigEndian.PutUint16(wire[0:2], uint16(m.Type))
	binary.BigEndian.PutUint16(wire[2:4], uint16(section+4+integrityLength))
	binary.BigEndian.PutUint32(wire[4:8], MagicCookie)
	copy(wire[8:20], m.TransactionID[:])
	offset := HeaderSize
	for i := 0; i < idx; i++ {
		attr := m.Attributes[i]
		binary.BigEndian.PutUint16(wire[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(wire[offset+2:offset+4], uint16(len(attr.Value)))
		copy(wire[offset+4:], attr.Value)
		offset += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	if len(m.raw) == 0 {
		return wire, nil
	}
	// Prefer the original wire: its padding bytes are authoritative. The
	// rebuilt prefix must match it byte-for-byte except that the rebuilt
	// Length field carries the adjusted value (the raw header carries the
	// final length including the MESSAGE-INTEGRITY attribute).
	if len(m.raw) >= len(wire) && string(m.raw[:len(wire)]) == string(wire) {
		return m.raw[:len(wire)], nil
	}
	if len(m.raw) >= HeaderSize+section {
		raw := append([]byte(nil), m.raw[:HeaderSize+section]...)
		binary.BigEndian.PutUint16(raw[2:4], uint16(section+4+integrityLength))
		return raw, nil
	}
	return nil, ErrTruncated
}

// AddFingerprint appends FINGERPRINT as the last attribute
// (RFC 8489 §14.7): CRC-32 of the message up to (but excluding) the
// FINGERPRINT attribute, XORed with 0x5354554E. The Length field used for
// the CRC covers the whole message including the FINGERPRINT attribute.
func (m *Message) AddFingerprint() error {
	if m.Count(AttrFingerprint) > 0 {
		return errors.New("stun: message already carries FINGERPRINT")
	}
	section := m.attributeSectionLength()
	if section+8 > MaxMessageSize {
		return ErrOversize
	}
	wire := make([]byte, HeaderSize+section)
	binary.BigEndian.PutUint16(wire[0:2], uint16(m.Type))
	binary.BigEndian.PutUint16(wire[2:4], uint16(section+8)) // length covers FINGERPRINT
	binary.BigEndian.PutUint32(wire[4:8], MagicCookie)
	copy(wire[8:20], m.TransactionID[:])
	offset := HeaderSize
	for _, attr := range m.Attributes {
		binary.BigEndian.PutUint16(wire[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(wire[offset+2:offset+4], uint16(len(attr.Value)))
		copy(wire[offset+4:], attr.Value)
		offset += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	crc := crc32.ChecksumIEEE(wire) ^ fingerprintXor
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, crc)
	m.Add(AttrFingerprint, value)
	return nil
}

// VerifyFingerprint checks the FINGERPRINT value. FINGERPRINT must be the
// last attribute (RFC 8489 §14.7). Parsed messages verify against their
// original wire bytes so exotic padding is preserved.
func (m *Message) VerifyFingerprint() (bool, error) {
	if m.Count(AttrFingerprint) == 0 {
		return false, ErrNoFingerprint
	}
	last := m.Attributes[len(m.Attributes)-1]
	if last.Type != AttrFingerprint {
		return false, ErrMalformed
	}
	if len(last.Value) != 4 {
		return false, ErrMalformed
	}
	section := 0
	for i := 0; i < len(m.Attributes)-1; i++ {
		section += 4 + ((len(m.Attributes[i].Value) + 3) &^ 3)
	}
	wire := make([]byte, HeaderSize+section)
	binary.BigEndian.PutUint16(wire[0:2], uint16(m.Type))
	binary.BigEndian.PutUint16(wire[2:4], uint16(section+8))
	binary.BigEndian.PutUint32(wire[4:8], MagicCookie)
	copy(wire[8:20], m.TransactionID[:])
	offset := HeaderSize
	for i := 0; i < len(m.Attributes)-1; i++ {
		attr := m.Attributes[i]
		binary.BigEndian.PutUint16(wire[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(wire[offset+2:offset+4], uint16(len(attr.Value)))
		copy(wire[offset+4:], attr.Value)
		offset += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	if len(m.raw) >= HeaderSize+section {
		// The raw wire's Length field is the final length including the
		// FINGERPRINT attribute; the CRC input must carry exactly the bytes
		// up to the FINGERPRINT attribute (excluded), so the raw prefix with
		// its final Length field is the authoritative input.
		wire = append([]byte(nil), m.raw[:HeaderSize+section]...)
	} else if len(m.raw) != 0 {
		return false, ErrTruncated
	}
	want := crc32.ChecksumIEEE(wire) ^ fingerprintXor
	got := binary.BigEndian.Uint32(last.Value)
	return got == want, nil
}
