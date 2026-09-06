// UPnP IGD client: discovery via SSDP, service resolution via the device
// description, mapping via SOAP. Ownership is BEST_EFFORT_QUERY_THEN_DELETE
// (v0.8 §3.4): before any delete the entry is re-queried and compared on
// external port, protocol, internal client, internal port and description;
// a third-party or mismatched entry is warned about and left alone, and the
// query/delete window is honestly acknowledged as TOCTOU. Permanent-only
// devices are unsupported by default because their mappings survive crashes.
package upnp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DefaultLease is the requested lease duration (v0.8 §3.5: 3600s requests,
// renewal near 50% lifetime is the manager's job).
const DefaultLease = time.Hour

// Client defaults.
const (
	defaultHTTPTimeout = 5 * time.Second
)

// Client maps ports through one IGD service. It holds no sockets; the HTTP
// client is injected and owned by the caller.
type Client struct {
	http  *http.Client
	world Service
	opts  ClientOptions
}

// ClientOptions tunes the client. Zero fields take defaults.
type ClientOptions struct {
	// Timeout bounds each SOAP/description HTTP round trip; default 5s.
	Timeout time.Duration
	// Now is the clock seam; default time.Now.
	Now func() time.Time
}

// NewClient builds a client for one resolved service.
func NewClient(client *http.Client, service Service, opts ClientOptions) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultHTTPTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	wrapped := *client
	wrapped.Timeout = opts.Timeout
	return &Client{http: &wrapped, world: service, opts: opts}
}

// World returns the resolved service for evidence records.
func (c *Client) World() Service { return c.world }

// Map acquires one port mapping.
//
// IGDv2 (AddAnyPortMapping): the requested port is a suggestion and the
// gateway returns the reserved port it assigned.
//
// IGDv1 (AddPortMapping): the response carries no port. With a requested
// port the client asks for it exactly; without one (or on a 718 conflict)
// it retries bounded random candidates (maxCandidateAttempts) and never
// scans the port space linearly. A granted lease of zero means the device
// ignored the lease: that is permanent-only territory and unsupported by
// default.
func (c *Client) Map(ctx context.Context, req MapRequest) (MapResult, error) {
	if req.Protocol != "TCP" && req.Protocol != "UDP" {
		return MapResult{}, fmt.Errorf("upnp: unsupported protocol %q", req.Protocol)
	}
	if req.Lease <= 0 {
		req.Lease = DefaultLease
	}
	randFn := req.Rand
	if randFn == nil {
		randFn = cryptoRandUint16
	}

	if c.world.IGDv2 {
		envelope := buildAddMapping(c.world, req, req.RequestedExternalPort)
		body, err := postSOAP(ctx, c.http, c.world, "AddAnyPortMapping", envelope)
		if err != nil {
			return MapResult{}, err
		}
		fields, err := parseSOAPResponse(body, "AddAnyPortMapping")
		if err != nil {
			var soapErr *SOAPError
			if errors.As(err, &soapErr) && soapErr.Code == errorCodePermanentLeaseOnly {
				return MapResult{}, ErrPermanentOnlyLease
			}
			return MapResult{}, err
		}
		portText, ok := fields["NewReservedPort"]
		if !ok {
			return MapResult{}, fmt.Errorf("%w: AddAnyPortMappingResponse lacks NewReservedPort", ErrMalformedSOAP)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return MapResult{}, fmt.Errorf("%w: NewReservedPort %q", ErrMalformedSOAP, portText)
		}
		return MapResult{
			Protocol:             req.Protocol,
			InternalAddress:      req.InternalAddress,
			InternalPort:         req.InternalPort,
			AssignedExternalPort: uint16(port),
			Lease:                req.Lease,
			Description:          req.Description,
		}, nil
	}

	// IGDv1: bounded candidate loop.
	lastErr := error(nil)
	for attempt := 0; attempt < maxCandidateAttempts; attempt++ {
		candidate := req.RequestedExternalPort
		if candidate == 0 || lastErr != nil {
			port, err := randFn()
			if err != nil {
				// A CSPRNG failure must never degrade to a fixed port.
				return MapResult{}, fmt.Errorf("upnp: random candidate port: %w", err)
			}
			if port < 1024 {
				port += 1024
			}
			candidate = port
		}
		envelope := buildAddMapping(c.world, req, candidate)
		body, err := postSOAP(ctx, c.http, c.world, "AddPortMapping", envelope)
		if err != nil {
			return MapResult{}, err
		}
		if _, err := parseSOAPResponse(body, "AddPortMapping"); err != nil {
			var soapErr *SOAPError
			if errors.As(err, &soapErr) {
				switch soapErr.Code {
				case errorCodePermanentLeaseOnly:
					return MapResult{}, ErrPermanentOnlyLease
				case errorCodeConflictInMapping:
					lastErr = soapErr // bounded retry with a new candidate
					continue
				case errorCodeInvalidAction, errorCodeActionFailed:
					return MapResult{}, soapErr
				}
				return MapResult{}, soapErr
			}
			return MapResult{}, err
		}
		// Success is not ownership: read back the entry the device actually
		// holds before adopting the candidate — a device may silently keep
		// a different mapping than the request asked for.
		entry, err := c.Query(ctx, candidate, req.Protocol)
		if err != nil {
			// The device accepted the add but the entry cannot be verified,
			// so it also cannot be safely located for deletion: fail with
			// the residue risk stated instead of pretending cleanup
			// happened.
			return MapResult{}, fmt.Errorf("upnp: post-add verification: %w (the created entry may outlive this call and must be reconciled)", err)
		}
		if entry == nil {
			return MapResult{}, fmt.Errorf("upnp: post-add verification: device holds no entry for port %d (it may have been created at another port)", candidate)
		}
		if entry.InternalPort == req.InternalPort && entry.InternalAddr == req.InternalAddress && entry.Description != req.Description {
			// The tuple is ours but the device mangled the description echo
			// (e.g. truncated it): the just-created entry is ours by tuple,
			// so delete it rather than leaking it.
			if deleteErr := c.deletePortMapping(ctx, candidate, req.Protocol); deleteErr != nil {
				return MapResult{}, errors.Join(errors.New("upnp: post-add verification: device mangled the description echo"), deleteErr)
			}
			return MapResult{}, fmt.Errorf("upnp: post-add verification: device mangled the description echo; the just-created entry was deleted")
		}
		if entry.InternalPort != req.InternalPort || entry.InternalAddr != req.InternalAddress {
			// A genuinely foreign entry holds the candidate port: never
			// touched, and our own entry — wherever the device put it — is
			// flagged for reconciliation.
			return MapResult{}, fmt.Errorf("upnp: post-add verification: %w (the created entry may outlive this call and must be reconciled)", ErrForeignMapping)
		}
		return MapResult{
			Protocol:             req.Protocol,
			InternalAddress:      req.InternalAddress,
			InternalPort:         req.InternalPort,
			AssignedExternalPort: candidate,
			Lease:                req.Lease,
			Description:          req.Description,
		}, nil
	}
	return MapResult{}, ErrNoMappingPort
}

// ExternalAddress fetches the gateway's WAN IPv4 via
// GetExternalIPAddress. Devices without the action surface the SOAP fault;
// callers fall back to STUN classification in that case.
func (c *Client) ExternalAddress(ctx context.Context) (netip.Addr, error) {
	envelope := buildExternalAddress(c.world)
	body, err := postSOAP(ctx, c.http, c.world, "GetExternalIPAddress", envelope)
	if err != nil {
		return netip.Addr{}, err
	}
	fields, err := parseSOAPResponse(body, "GetExternalIPAddress")
	if err != nil {
		return netip.Addr{}, err
	}
	text := fields["NewExternalIPAddress"]
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("upnp: gateway external address %q is not IPv4", text)
	}
	return addr, nil
}

// Query fetches one mapping entry as the gateway sees it. A missing entry
// returns (nil, nil); the caller treats an unexpected error as gateway
// restart evidence.
type mappingEntry struct {
	InternalPort uint16
	InternalAddr string
	Description  string
	LeaseSeconds uint64
}

func (c *Client) Query(ctx context.Context, externalPort uint16, protocol string) (*mappingEntry, error) {
	envelope := buildQueryMapping(c.world, externalPort, protocol)
	body, err := postSOAP(ctx, c.http, c.world, "GetSpecificPortMappingEntry", envelope)
	if err != nil {
		return nil, err
	}
	fields, err := parseSOAPResponse(body, "GetSpecificPortMappingEntry")
	if err != nil {
		// 714 NoSuchEntryInArray means the entry is gone (device restart).
		var soapErr *SOAPError
		if errors.As(err, &soapErr) && soapErr.Code == 714 {
			return nil, nil
		}
		return nil, err
	}
	entry := &mappingEntry{}
	if text, ok := fields["NewInternalPort"]; ok {
		if port, err := strconv.ParseUint(text, 10, 16); err == nil {
			entry.InternalPort = uint16(port)
		}
	}
	entry.InternalAddr = fields["NewInternalClient"]
	entry.Description = fields["NewPortMappingDescription"]
	if text, ok := fields["NewLeaseDuration"]; ok {
		if seconds, err := strconv.ParseUint(text, 10, 64); err == nil {
			entry.LeaseSeconds = seconds
		}
	}
	return entry, nil
}

// Delete releases the mapping with query-then-delete verification. The
// entry must match external port, protocol, internal client, internal port
// and description; anything else is ErrForeignMapping and is never deleted
// (best-effort ownership: the query/delete window is TOCTOU).
func (c *Client) Delete(ctx context.Context, mapping MapResult) error {
	if mapping.InternalPort == 0 || mapping.AssignedExternalPort == 0 {
		return ErrUnownedMapping
	}
	entry, err := c.Query(ctx, mapping.AssignedExternalPort, mapping.Protocol)
	if err != nil {
		return fmt.Errorf("upnp: delete pre-query: %w", err)
	}
	if entry == nil {
		// Already gone (device restarted and dropped state): nothing to do.
		return nil
	}
	if entry.InternalPort != mapping.InternalPort ||
		entry.InternalAddr != mapping.InternalAddress ||
		entry.Description != mapping.Description {
		return ErrForeignMapping
	}
	envelope := buildDeleteMapping(c.world, mapping.AssignedExternalPort, mapping.Protocol)
	return c.postDelete(ctx, envelope)
}

// deletePortMapping issues a bare DeletePortMapping for one external port.
// The query-then-delete discipline lives in Delete; this helper serves the
// paths that have already established ownership of the entry.
func (c *Client) deletePortMapping(ctx context.Context, externalPort uint16, protocol string) error {
	envelope := buildDeleteMapping(c.world, externalPort, protocol)
	return c.postDelete(ctx, envelope)
}

func (c *Client) postDelete(ctx context.Context, envelope string) error {
	body, err := postSOAP(ctx, c.http, c.world, "DeletePortMapping", envelope)
	if err != nil {
		return err
	}
	_, err = parseSOAPResponse(body, "DeletePortMapping")
	return err
}

func cryptoRandUint16() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// CSPRNG failure must not silently degrade to a fixed port.
		return 0, fmt.Errorf("upnp: candidate port entropy: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
