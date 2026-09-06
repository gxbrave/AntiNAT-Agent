// Package upnp implements the UPnP IGD subset the AntiNAT v1 gateway layer
// needs: interface-bound SSDP discovery with stable multi-IGD selection,
// scoped device-description fetches (no redirects, size caps, same-host
// control URLs), the IGDv1 AddPortMapping and IGDv2 AddAnyPortMapping SOAP
// actions with bounded random candidate retry, query-then-delete
// verification, and permanent-only lease detection. An arbitrary SSDP
// response must never turn the Agent into a general-purpose HTTP client.
package upnp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// --- SSDP response parsing and selection -----------------------------------

// R1: a valid M-SEARCH response parses into a gateway record.
func TestParseSSDPResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://10.0.0.1:5000/rootDesc.xml\r\n" +
		"SERVER: Linux/1.0 UPnP/1.0 miniupnpd/2.3.4\r\n" +
		"ST: urn:schemas-upnp-org:service:WANIPConnection:2\r\n" +
		"USN: uuid:2d80bf22-7b52-4e03-a76d-9b742e6df2a2::urn:schemas-upnp-org:service:WANIPConnection:2\r\n" +
		"\r\n"
	gateway, err := parseSSDPResponse([]byte(raw))
	if err != nil {
		t.Fatalf("parseSSDPResponse: %v", err)
	}
	if !strings.HasPrefix(gateway.USN, "uuid:2d80bf22") {
		t.Fatalf("USN = %q", gateway.USN)
	}
	if gateway.Location != "http://10.0.0.1:5000/rootDesc.xml" {
		t.Fatalf("LOCATION = %q", gateway.Location)
	}
	if gateway.SearchTarget != "urn:schemas-upnp-org:service:WANIPConnection:2" {
		t.Fatalf("ST = %q", gateway.SearchTarget)
	}
}

// R1b: garbage, non-200 and missing-field responses are rejected.
func TestParseSSDPResponseRejectsGarbage(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"not http", "hello world\r\n\r\n"},
		{"missing location", "HTTP/1.1 200 OK\r\nUSN: uuid:x\r\nST: st\r\n\r\n"},
		{"missing usn", "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/d.xml\r\nST: st\r\n\r\n"},
	}
	for _, tc := range cases {
		if _, err := parseSSDPResponse([]byte(tc.raw)); err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
	}
}

// R2: multiple IGDs dedupe by USN and select deterministically; a repeated
// advertisement never duplicates a candidate.
func TestGatewaySelectionStable(t *testing.T) {
	gateways := []Gateway{
		{USN: "uuid:c::urn:schemas-upnp-org:service:WANIPConnection:1", Location: "http://10.0.0.1:1/d.xml", SearchTarget: "urn:schemas-upnp-org:service:WANIPConnection:1"},
		{USN: "uuid:a::urn:schemas-upnp-org:service:WANIPConnection:2", Location: "http://10.0.0.2:2/d.xml", SearchTarget: "urn:schemas-upnp-org:service:WANIPConnection:2"},
		{USN: "uuid:a::urn:schemas-upnp-org:service:WANIPConnection:2", Location: "http://10.0.0.2:2/d.xml", SearchTarget: "urn:schemas-upnp-org:service:WANIPConnection:2"},
	}
	selected := SelectGateways(gateways)
	if len(selected) != 2 {
		t.Fatalf("selected %d gateways, want 2 after USN dedupe", len(selected))
	}
	// WANIPConnection:2 (IGDv2) outranks :1; ties break on USN order.
	if selected[0].USN != "uuid:a::urn:schemas-upnp-org:service:WANIPConnection:2" {
		t.Fatalf("first selection = %q, want the IGDv2 USN", selected[0].USN)
	}
	if selected[1].USN != "uuid:c::urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("second selection = %q", selected[1].USN)
	}
}

// --- device description fetch ----------------------------------------------

const deviceDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Lab Gateway</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <controlURL>/ctl/IPConn</controlURL>
                <SCPDURL>/scpd/IPConn</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`

// R3: the description fetch resolves the WANIPConnection control URL
// against the LOCATION origin: same scheme+host+port, absolute path.
func TestFetchDescriptionResolvesControlURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, deviceDescXML)
	}))
	defer server.Close()

	service, err := FetchDescription(t.Context(), http.DefaultClient, server.URL)
	if err != nil {
		t.Fatalf("FetchDescription: %v", err)
	}
	if service.Type != "urn:schemas-upnp-org:service:WANIPConnection:2" {
		t.Fatalf("service type = %q", service.Type)
	}
	if service.IGDVersion() != 2 {
		t.Fatalf("IGDVersion = %d, want 2", service.IGDVersion())
	}
	if service.ControlURL != server.URL+"/ctl/IPConn" {
		t.Fatalf("control URL = %q, want %q", service.ControlURL, server.URL+"/ctl/IPConn")
	}
}

// R3b: a control URL pointing at another host is out of scope and rejected:
// an SSDP response must not send the Agent to arbitrary HTTP servers.
func TestFetchDescriptionRejectsCrossOriginControlURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evil := strings.Replace(deviceDescXML, `<controlURL>/ctl/IPConn</controlURL>`,
			`<controlURL>http://203.0.113.9:8080/steal</controlURL>`, 1)
		fmt.Fprint(w, evil)
	}))
	defer server.Close()

	if _, err := FetchDescription(t.Context(), http.DefaultClient, server.URL); !errors.Is(err, ErrControlURLOutOfScope) {
		t.Fatalf("error = %v, want ErrControlURLOutOfScope", err)
	}
}

// R3c: redirects are refused: the fetch is one GET, never a redirect chain.
func TestFetchDescriptionRejectsRedirect(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, deviceDescXML)
	}))
	defer redirectTarget.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer server.Close()

	if _, err := FetchDescription(t.Context(), http.DefaultClient, server.URL); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("error = %v, want ErrRedirectRefused", err)
	}
}

// R3d: oversized descriptions are refused, never buffered unbounded.
func TestFetchDescriptionRejectsOversize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("A", maxDescriptionBytes+1))
	}))
	defer server.Close()

	if _, err := FetchDescription(t.Context(), http.DefaultClient, server.URL); !errors.Is(err, ErrDescriptionTooLarge) {
		t.Fatalf("error = %v, want ErrDescriptionTooLarge", err)
	}
}

// R3e: a LOCATION pointing at a public address is out of SSDP scope and
// rejected before any fetch: SSDP is a link-local protocol.
func TestValidateLocationScope(t *testing.T) {
	if err := validateLocationScope("http://10.0.0.1:5000/d.xml"); err != nil {
		t.Fatalf("private LOCATION rejected: %v", err)
	}
	if err := validateLocationScope("http://127.0.0.1:5000/d.xml"); err != nil {
		t.Fatalf("loopback LOCATION rejected: %v", err)
	}
	if err := validateLocationScope("http://8.8.8.8:5000/d.xml"); !errors.Is(err, ErrLocationOutOfScope) {
		t.Fatalf("global LOCATION must be refused, got %v", err)
	}
}

// --- SOAP actions ------------------------------------------------------------

// newTestIGD returns an IGD client pointed at a scripted control server.
// The handler receives the SOAP action name extracted from the SOAPACTION
// header plus the raw request.
func newTestIGD(t *testing.T, v2 bool, handler func(action string, r *http.Request, w http.ResponseWriter)) *Client {
	client, _ := newTestIGDService(t, v2, handler)
	return client
}

// newTestIGDService is newTestIGD with the resolved Service returned for
// adapter-level wiring.
func newTestIGDService(t *testing.T, v2 bool, handler func(action string, r *http.Request, w http.ResponseWriter)) (*Client, Service) {
	t.Helper()
	serviceType := "urn:schemas-upnp-org:service:WANIPConnection:1"
	if v2 {
		serviceType = "urn:schemas-upnp-org:service:WANIPConnection:2"
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		soapAction := r.Header.Get("SOAPACTION")
		soapAction = strings.Trim(soapAction, `"`)
		action := soapAction
		if i := strings.LastIndex(soapAction, "#"); i >= 0 {
			action = soapAction[i+1:]
		}
		handler(action, r, w)
	}))
	t.Cleanup(server.Close)
	service := Service{
		Type:       serviceType,
		ControlURL: server.URL + "/ctl/IPConn",
		IGDv2:      v2,
	}
	return NewClient(http.DefaultClient, service, ClientOptions{}), service
}

func soapOK(w http.ResponseWriter, action string, inner string) {
	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%sResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">%s</u:%sResponse></s:Body></s:Envelope>`, action, inner, action)
}

func writeSOAPFault(w http.ResponseWriter, code int, description string) {
	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, description)
}

// R4: IGDv2 AddAnyPortMapping sends the SOAP envelope and parses the
// reserved port from the response.
func TestAddAnyPortMappingReturnsReservedPort(t *testing.T) {
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		if action != "AddAnyPortMapping" {
			writeSOAPFault(w, 401, "Invalid Action")
			return
		}
		soapOK(w, "AddAnyPortMapping", `<NewReservedPort>55555</NewReservedPort>`)
	})

	result, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if err != nil {
		t.Fatalf("Map (IGDv2): %v", err)
	}
	if result.AssignedExternalPort != 55555 {
		t.Fatalf("reserved port = %d, want 55555", result.AssignedExternalPort)
	}
}

// R5: IGDv1 AddPortMapping returns no assigned port: accept_any retries
// bounded random candidates, never scanning the full port range.
func TestMapV1BoundedRandomRetry(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddPortMapping":
			mu.Lock()
			attempts++
			n := attempts
			mu.Unlock()
			if n <= 3 {
				writeSOAPFault(w, 718, "ConflictInMappingEntry")
				return
			}
			soapOK(w, "AddPortMapping", "")
		case "GetSpecificPortMappingEntry":
			// The post-add verification reads back the entry the device holds.
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>3111</NewInternalPort><NewInternalClient>10.0.0.2</NewInternalClient><NewPortMappingDescription>AntiNAT</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	tries := 0
	result, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		Lease: time.Hour, Description: "AntiNAT",
		Rand: func() (uint16, error) {
			tries++
			return uint16(40000 + tries), nil
		},
	})
	if err != nil {
		t.Fatalf("Map (IGDv1 bounded retry): %v", err)
	}
	if result.AssignedExternalPort != uint16(40004) {
		t.Fatalf("assigned port = %d, want the 4th candidate 40004", result.AssignedExternalPort)
	}
	if tries > maxCandidateAttempts {
		t.Fatalf("candidate attempts = %d, must stay within the bounded budget %d", tries, maxCandidateAttempts)
	}
}

// R5b: a device refusing every candidate exhausts the bounded budget and
// fails; it never scans the port space.
func TestMapV1BudgetExhausted(t *testing.T) {
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 718, "ConflictInMappingEntry")
	})

	tries := 0
	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		Lease: time.Hour, Description: "AntiNAT",
		Rand: func() (uint16, error) {
			tries++
			return uint16(40000 + tries), nil
		},
	})
	if !errors.Is(err, ErrNoMappingPort) {
		t.Fatalf("error = %v, want ErrNoMappingPort", err)
	}
	if tries != maxCandidateAttempts {
		t.Fatalf("candidate attempts = %d, want exactly the bounded budget %d", tries, maxCandidateAttempts)
	}
}

// R5c (NAT audit M4): IGDv1 success is verified before adoption — the
// client re-queries the entry it believes it created and adopts the
// device-side truth. An add the device did not record is a failure, never
// a recorded wrong port.
func TestMapV1VerifiesPostAddEntry(t *testing.T) {
	var mu sync.Mutex
	adds := 0
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddPortMapping":
			mu.Lock()
			adds++
			mu.Unlock()
			soapOK(w, "AddPortMapping", "")
		case "GetSpecificPortMappingEntry":
			// The device holds nothing at the candidate port.
			writeSOAPFault(w, 714, "NoSuchEntryInArray")
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if err == nil {
		t.Fatal("an add the device did not record must fail, never record an unverified port")
	}
	mu.Lock()
	defer mu.Unlock()
	if adds != 1 {
		t.Fatalf("adds = %d, want 1 (no blind retry after a verification failure)", adds)
	}
}

// R5d (NAT audit M4): a post-add query revealing a foreign entry refuses to
// adopt or touch it.
func TestMapV1PostAddForeignEntryFails(t *testing.T) {
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddPortMapping":
			soapOK(w, "AddPortMapping", "")
		case "GetSpecificPortMappingEntry":
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>9999</NewInternalPort><NewInternalClient>10.9.9.9</NewInternalClient><NewPortMappingDescription>someone-else</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if !errors.Is(err, ErrForeignMapping) {
		t.Fatalf("error = %v, want ErrForeignMapping", err)
	}
}

// R5e (NAT audit L3): a CSPRNG failure aborts the mapping — it must never
// degrade to a fixed candidate port.
func TestMapV1RandFailureAborts(t *testing.T) {
	var mu sync.Mutex
	adds := 0
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddPortMapping":
			mu.Lock()
			adds++
			mu.Unlock()
			soapOK(w, "AddPortMapping", "")
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		Lease: time.Hour, Description: "AntiNAT",
		Rand: func() (uint16, error) { return 0, errors.New("rng dead") },
	})
	if err == nil || !strings.Contains(err.Error(), "rng dead") {
		t.Fatalf("error = %v, want the CSPRNG failure surfaced", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if adds != 0 {
		t.Fatalf("adds = %d, want 0 (no candidate without randomness)", adds)
	}
}

// R4b (NAT audit M4): an IGDv2 device that only supports permanent leases
// (725) surfaces the same permanent-only classification as IGDv1.
func TestMapV2PermanentOnlyUnsupported(t *testing.T) {
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 725, "OnlyPermanentLeasesSupported")
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if !errors.Is(err, ErrPermanentOnlyLease) {
		t.Fatalf("error = %v, want ErrPermanentOnlyLease", err)
	}
}

// R6: a device that only supports permanent leases (errorCode 725) is
// unsupported by default: mappings must be lease-owned to be releasable.
func TestMapPermanentOnlyUnsupported(t *testing.T) {
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 725, "OnlyPermanentLeasesSupported")
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		Lease: time.Hour, Description: "AntiNAT",
	})
	if !errors.Is(err, ErrPermanentOnlyLease) {
		t.Fatalf("error = %v, want ErrPermanentOnlyLease", err)
	}
}

// R6b: other SOAP faults surface their UPnP error code.
func TestMapSOAPFault(t *testing.T) {
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 718, "ConflictInMappingEntry")
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	var soapErr *SOAPError
	if !errors.As(err, &soapErr) || soapErr.Code != 718 {
		t.Fatalf("error = %v, want SOAPError{718}", err)
	}
}

// R7: query-then-delete: Delete first verifies the entry belongs to us
// (external port, protocol, internal client, internal port, description) and
// only then sends DeletePortMapping.
func TestDeleteVerifiesOwnershipBeforeDelete(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetSpecificPortMappingEntry":
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>3111</NewInternalPort><NewInternalClient>10.0.0.2</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>AntiNAT</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		case "DeletePortMapping":
			soapOK(w, "DeletePortMapping", "")
		}
	})

	mapping := MapResult{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		AssignedExternalPort: 43111, Description: "AntiNAT", Lease: time.Hour,
	}
	if err := client.Delete(t.Context(), mapping); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(actions) != 2 || actions[0] != "GetSpecificPortMappingEntry" || actions[1] != "DeletePortMapping" {
		t.Fatalf("actions = %v, want query-then-delete", actions)
	}
}

// R7b: a mismatched entry (someone else's mapping) is never deleted: the
// best-effort policy warns and leaves the third-party entry alone.
func TestDeleteRefusesForeignMapping(t *testing.T) {
	var mu sync.Mutex
	deleteSent := false
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		mu.Lock()
		if action == "DeletePortMapping" {
			deleteSent = true
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		if action == "GetSpecificPortMappingEntry" {
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>9999</NewInternalPort><NewInternalClient>10.9.9.9</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>someone else</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>`)
		}
	})

	mapping := MapResult{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		AssignedExternalPort: 43111, Description: "AntiNAT", Lease: time.Hour,
	}
	err := client.Delete(t.Context(), mapping)
	if !errors.Is(err, ErrForeignMapping) {
		t.Fatalf("error = %v, want ErrForeignMapping", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if deleteSent {
		t.Fatal("a foreign mapping must never be deleted")
	}
}

// R7c: a delete for a mapping without an exact tuple is refused client-side.
func TestDeleteRefusesUnownedMapping(t *testing.T) {
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 501, "ActionFailed")
	})
	mapping := MapResult{InternalPort: 0, AssignedExternalPort: 43111}
	if err := client.Delete(t.Context(), mapping); !errors.Is(err, ErrUnownedMapping) {
		t.Fatalf("error = %v, want ErrUnownedMapping", err)
	}
}

// R8: the SOAP response size cap is enforced: oversized responses are
// refused, never buffered unbounded.
func TestSOAPResponseSizeCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintln(w, strings.Repeat("A", maxSOAPResponseBytes+1))
	}))
	defer server.Close()

	service := Service{Type: "urn:schemas-upnp-org:service:WANIPConnection:2", ControlURL: server.URL, IGDv2: true}
	client := NewClient(http.DefaultClient, service, ClientOptions{})
	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

// R9: device restart handling — a SOAP action failure carries the fault so
// the manager can classify a dead gateway and go stale.
func TestSOAPActionFailed(t *testing.T) {
	client := newTestIGD(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		writeSOAPFault(w, 501, "ActionFailed")
	})
	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	var soapErr *SOAPError
	if !errors.As(err, &soapErr) || soapErr.Code != 501 {
		t.Fatalf("error = %v, want SOAPError{501}", err)
	}
}

// R12 (NAT audit M5): one SSDP MX window is bounded by the context
// deadline, not only by its own MX wait — the detection attempt budget
// must be able to bound a full discovery.
func TestSearchTargetHonorsContextDeadline(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer packet.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	// No SSDP responder answers this loopback socket: the wait must end at
	// the context deadline, not run the full MX window.
	found, err := searchTarget(ctx, packet, "upnp:rootdevice", DiscoverOptions{
		InterfaceIP: netip.MustParseAddr("127.0.0.1"),
		Wait:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("searchTarget: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found = %v, want none on a silent socket", found)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("searchTarget ran %s, want it bounded by the 300ms context deadline", elapsed)
	}
}

// R13 (NAT audit M5): the default detection attempt budget fits a full
// three-target SSDP discovery, otherwise the UPnP attempt can never pass
// under the default configuration.
func TestDefaultAttemptTimeoutFitsSSDPDiscovery(t *testing.T) {
	budget := time.Duration(len(SearchTargets)) * (DefaultSearchWait + 500*time.Millisecond)
	if traversal.DefaultAttemptTimeout <= budget {
		t.Fatalf("DefaultAttemptTimeout = %s, want > %s so the UPnP attempt fits its discovery budget",
			traversal.DefaultAttemptTimeout, budget)
	}
}

// R3f (quality/security review L1): a SOAP POST that redirects is refused —
// the envelope carries the internal tuple, so a redirect would replay it to
// a foreign host. Pins postSOAP's CheckRedirect, which the description
// tests do not cover.
func TestSOAPPostRefusesRedirect(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		soapOK(w, "AddAnyPortMapping", `<NewReservedPort>43111</NewReservedPort>`)
	}))
	defer redirectTarget.Close()

	// The control server answers every POST with a redirect to the foreign
	// target; Map must surface the refusal, never follow it.
	redirectingControl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/steal", http.StatusFound)
	}))
	defer redirectingControl.Close()

	service := Service{
		Type:       "urn:schemas-upnp-org:service:WANIPConnection:2",
		ControlURL: redirectingControl.URL + "/ctl/IPConn",
		IGDv2:      true,
	}
	client := NewClient(http.DefaultClient, service, ClientOptions{})
	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT",
	})
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("error = %v, want ErrRedirectRefused (the POST must never be replayed)", err)
	}
}

// R5f (quality/security review L2): a post-add query revealing OUR tuple
// with a mangled description echo deletes the just-created entry instead of
// leaking it; a genuinely foreign tuple is never touched.
func TestMapV1MangledDescriptionEchoDeletesCreatedEntry(t *testing.T) {
	var mu sync.Mutex
	deleted := 0
	client := newTestIGD(t, false, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddPortMapping":
			soapOK(w, "AddPortMapping", "")
		case "GetSpecificPortMappingEntry":
			// Our tuple, but the device truncated the description echo
			// (miniupnpd-style).
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>3111</NewInternalPort><NewInternalClient>10.0.0.2</NewInternalClient><NewPortMappingDescription>AntiNAT uuid:trunc</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		case "DeletePortMapping":
			mu.Lock()
			deleted++
			mu.Unlock()
			soapOK(w, "DeletePortMapping", "")
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	_, err := client.Map(t.Context(), MapRequest{
		Protocol: "TCP", InternalAddress: "10.0.0.2", InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, Description: "AntiNAT uuid:truncated-by-device",
	})
	if err == nil {
		t.Fatal("a mangled description echo must fail the verification")
	}
	mu.Lock()
	defer mu.Unlock()
	if deleted != 1 {
		t.Fatalf("deletes = %d, want exactly 1 (the just-created entry must not leak)", deleted)
	}
}
