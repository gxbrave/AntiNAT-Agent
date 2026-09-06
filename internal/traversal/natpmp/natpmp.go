// RFC 6886 NAT-PMP wire codec: the 12-byte MAP request / 16-byte MAP
// response and the 4-byte / 12-byte public-address exchange. Decoding is
// strict: exact length, echoed version and opcode (+128), and — for success
// responses — echoed internal port.
package natpmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// NAT-PMP constants (RFC 6886).
const (
	// Version is the NAT-PMP protocol version this client speaks.
	Version byte = 0

	// OpPublicAddress is the public-address request opcode (§3.3).
	OpPublicAddress byte = 0

	// ResponseOpBase is added to the request opcode to form the response
	// opcode.
	ResponseOpBase byte = 128

	// RequestSize / ResponseSize are the exact MAP wire lengths.
	RequestSize  = 12
	ResponseSize = 16
	// PublicRequestSize / PublicResponseSize are the public-address lengths.
	PublicRequestSize  = 4
	PublicResponseSize = 12

	// DefaultServerPort is the registered NAT-PMP port.
	DefaultServerPort uint16 = 5351
)

// Result codes (RFC 6886 §3.5). There are no transient codes: any non-zero
// result is definitive.
const (
	ResultSuccess            uint16 = 0
	ResultUnsupportedVersion uint16 = 1
	ResultNotAuthorized      uint16 = 2
	ResultNetworkFailure     uint16 = 3
	ResultOutOfResources     uint16 = 4
	ResultUnsupportedOpcode  uint16 = 5
)

// Codec errors.
var (
	ErrTruncated        = errors.New("natpmp: response truncated")
	ErrWrongVersion     = errors.New("natpmp: response version mismatch")
	ErrWrongOpcode      = errors.New("natpmp: response opcode mismatch")
	ErrInternalPort     = errors.New("natpmp: internal port mismatch in response")
	ErrBadPublicAddress = errors.New("natpmp: public address response is not IPv4")
)

// putUint16/putUint32/readUint16/readUint32 are shared by the codec and the
// fake-server tests.
func putUint16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
func putUint32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func readUint16(b []byte) uint16   { return binary.BigEndian.Uint16(b) }
func readUint32(b []byte) uint32   { return binary.BigEndian.Uint32(b) }

// buildMapRequest encodes one MAP request. The requested external port is a
// suggestion only: the response's assigned port is authoritative.
func buildMapRequest(req MapRequest) ([]byte, error) {
	if !req.Protocol.Valid() {
		return nil, fmt.Errorf("natpmp: unsupported MAP protocol %d", req.Protocol)
	}
	request := make([]byte, RequestSize)
	request[0] = Version
	request[1] = req.Protocol.opcode()
	// request[2:4] reserved
	putUint16(request[4:6], req.InternalPort)
	putUint16(request[6:8], req.RequestedExternalPort)
	putUint32(request[8:12], uint32(req.Lifetime/time.Second))
	return request, nil
}

// mapResponse is the decoded MAP response.
type mapResponse struct {
	ResultCode           uint16
	Epoch                uint32
	InternalPort         uint16
	AssignedExternalPort uint16
	LifetimeSeconds      uint32
}

// parseMapResponse decodes and validates a MAP response.
func parseMapResponse(packet []byte, wantOpcode byte, wantInternalPort uint16) (mapResponse, error) {
	var zero mapResponse
	if len(packet) < ResponseSize {
		return zero, fmt.Errorf("%w: %d bytes", ErrTruncated, len(packet))
	}
	if packet[0] != Version {
		return zero, fmt.Errorf("%w: got %d", ErrWrongVersion, packet[0])
	}
	if packet[1] != wantOpcode+ResponseOpBase {
		return zero, fmt.Errorf("%w: got %d want %d", ErrWrongOpcode, packet[1], wantOpcode+ResponseOpBase)
	}
	response := mapResponse{
		ResultCode:           readUint16(packet[2:4]),
		Epoch:                readUint32(packet[4:8]),
		InternalPort:         readUint16(packet[8:10]),
		AssignedExternalPort: readUint16(packet[10:12]),
		LifetimeSeconds:      readUint32(packet[12:16]),
	}
	if len(packet) != ResponseSize {
		return zero, fmt.Errorf("natpmp: trailing bytes after MAP response")
	}
	if response.ResultCode == ResultSuccess && response.InternalPort != wantInternalPort {
		return zero, fmt.Errorf("%w: got %d want %d", ErrInternalPort, response.InternalPort, wantInternalPort)
	}
	return response, nil
}

// publicResponse is the decoded public-address response.
type publicResponse struct {
	ResultCode uint16
	Epoch      uint32
	Address    netip.Addr
}

// parsePublicResponse decodes and validates a public-address response.
func parsePublicResponse(packet []byte) (publicResponse, error) {
	var zero publicResponse
	if len(packet) < PublicResponseSize {
		return zero, fmt.Errorf("%w: %d bytes", ErrTruncated, len(packet))
	}
	if packet[0] != Version {
		return zero, fmt.Errorf("%w: got %d", ErrWrongVersion, packet[0])
	}
	if packet[1] != OpPublicAddress+ResponseOpBase {
		return zero, fmt.Errorf("%w: got %d", ErrWrongOpcode, packet[1])
	}
	if len(packet) != PublicResponseSize {
		return zero, fmt.Errorf("natpmp: trailing bytes after public-address response")
	}
	address, ok := netip.AddrFromSlice(packet[8:12])
	if !ok || !address.Is4() {
		return zero, ErrBadPublicAddress
	}
	return publicResponse{
		ResultCode: readUint16(packet[2:4]),
		Epoch:      readUint32(packet[4:8]),
		Address:    address,
	}, nil
}
