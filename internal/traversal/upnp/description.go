// Device-description fetch and XML walk. Security scope: the LOCATION URL
// must be a non-global address (SSDP is link-local), the fetch is one GET
// with redirects refused, the body is size-capped, and the control URL the
// device advertises must resolve against the LOCATION origin (same scheme,
// host and port). An SSDP response never sends the Agent to arbitrary HTTP
// servers.
package upnp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// maxDescriptionBytes caps the device description body (64 KiB is far above
// every real IGD description).
const maxDescriptionBytes = 64 * 1024

// Description errors.
var (
	ErrRedirectRefused       = errors.New("upnp: description redirect refused")
	ErrDescriptionTooLarge   = errors.New("upnp: description exceeds the size cap")
	ErrLocationOutOfScope    = errors.New("upnp: LOCATION address is not a local-scope address")
	ErrControlURLOutOfScope  = errors.New("upnp: control URL is outside the LOCATION origin")
	ErrDescriptionNotFound   = errors.New("upnp: no WAN IP/PPP connection service in description")
	ErrBadDescriptionURL     = errors.New("upnp: LOCATION is not a valid http(s) URL")
	ErrDescriptionNotXML     = errors.New("upnp: description is not well-formed XML")
	ErrDescriptionStatusCode = errors.New("upnp: description fetch returned a non-200 status")
)

// Service is one control-capable WAN connection service resolved from the
// device description.
type Service struct {
	// Type is the serviceType URN (WANIPConnection:2/1, WANPPPConnection:1).
	Type string
	// ControlURL is the absolute URL of the SOAP control endpoint, scoped
	// to the LOCATION origin.
	ControlURL string
	// IGDv2 records the service version used for the capability table.
	IGDv2 bool
	// DescriptionBase is the LOCATION origin the control URL is scoped to.
	DescriptionBase string
}

// IGDVersion returns 2 or 1 from the service type.
func (s Service) IGDVersion() int {
	if s.IGDv2 {
		return 2
	}
	return 1
}

// validateLocationScope refuses LOCATION URLs pointing at global addresses:
// SSDP advertisements arrive on the LAN and their description server must
// live on it. Loopback is allowed for lab topologies.
func validateLocationScope(location string) error {
	parsed, err := url.Parse(location)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("%w: %q", ErrBadDescriptionURL, location)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname LOCATION cannot be scope-verified without DNS; IGD
		// advertisements use literals, so refuse hostnames outright.
		return fmt.Errorf("%w: hostname %q", ErrLocationOutOfScope, host)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: %q", ErrLocationOutOfScope, host)
	}
	addr = addr.Unmap()
	// Non-unicast literals (unspecified, broadcast, multicast) are never a
	// description host, whatever their private/global class.
	if !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%w: %s is not a unicast host", ErrLocationOutOfScope, addr)
	}
	if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: %s is a global address", ErrLocationOutOfScope, addr)
	}
	return nil
}

// descriptionXML is the subset of the UPnP device description schema this
// client walks: nested device elements with their service lists.
type descriptionXML struct {
	Devices []descriptionDevice `xml:"device"`
}

type descriptionDevice struct {
	DeviceType string               `xml:"deviceType"`
	Services   []descriptionService `xml:"serviceList>service"`
	Devices    []descriptionDevice  `xml:"deviceList>device"`
}

type descriptionService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// FetchDescription fetches and walks the device description at location and
// returns the best WAN connection service (IGDv2 preferred over v1, IP over
// PPP).
func FetchDescription(ctx context.Context, client *http.Client, location string) (Service, error) {
	if err := validateLocationScope(location); err != nil {
		return Service{}, err
	}
	base, err := url.Parse(location)
	if err != nil {
		return Service{}, fmt.Errorf("%w: %q", ErrBadDescriptionURL, location)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return Service{}, fmt.Errorf("upnp: description request: %w", err)
	}
	fetch := *client
	fetch.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return ErrRedirectRefused
	}
	response, err := fetch.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRefused) {
			return Service{}, ErrRedirectRefused
		}
		return Service{}, fmt.Errorf("upnp: description fetch: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Service{}, fmt.Errorf("%w: %d", ErrDescriptionStatusCode, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDescriptionBytes+1))
	if err != nil {
		return Service{}, fmt.Errorf("upnp: description read: %w", err)
	}
	if len(body) > maxDescriptionBytes {
		return Service{}, ErrDescriptionTooLarge
	}

	var parsed descriptionXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return Service{}, fmt.Errorf("%w: %v", ErrDescriptionNotXML, err)
	}

	best := Service{DescriptionBase: location}
	bestRank := 99
	var scopeErr error
	var walk func(devices []descriptionDevice)
	walk = func(devices []descriptionDevice) {
		for _, device := range devices {
			for _, service := range device.Services {
				rank := -1
				switch service.ServiceType {
				case "urn:schemas-upnp-org:service:WANIPConnection:2":
					rank = 0
				case "urn:schemas-upnp-org:service:WANIPConnection:1":
					rank = 1
				case "urn:schemas-upnp-org:service:WANPPPConnection:1":
					rank = 2
				default:
					continue
				}
				if service.ControlURL == "" {
					continue
				}
				controlURL, err := resolveControlURL(base, service.ControlURL)
				if err != nil {
					// A qualifying service advertising a cross-origin
					// control URL is hostile: surface it, never silently
					// fetch it.
					scopeErr = err
					continue
				}
				if rank < bestRank {
					best = Service{
						Type:            service.ServiceType,
						ControlURL:      controlURL,
						IGDv2:           strings.HasSuffix(service.ServiceType, ":2"),
						DescriptionBase: location,
					}
					bestRank = rank
				}
			}
			walk(device.Devices)
		}
	}
	walk(parsed.Devices)
	if bestRank == 99 {
		if scopeErr != nil {
			return Service{}, scopeErr
		}
		return Service{}, ErrDescriptionNotFound
	}
	return best, nil
}

// resolveControlURL resolves the device's relative control URL against the
// LOCATION origin. Absolute URLs to another host are out of scope.
func resolveControlURL(base *url.URL, controlURL string) (string, error) {
	parsed, err := url.Parse(controlURL)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrControlURLOutOfScope, controlURL)
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "", fmt.Errorf("%w: %q is outside %q", ErrControlURLOutOfScope, controlURL, base.Host)
	}
	return resolved.String(), nil
}
