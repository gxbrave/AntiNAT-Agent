// SOAP control actions over HTTP POST: AddPortMapping (IGDv1),
// AddAnyPortMapping (IGDv2), GetSpecificPortMappingEntry and
// DeletePortMapping. Envelopes are built with strict field ordering, faults
// are parsed into SOAPError with the UPnP error code, and every response
// body is size-capped.
package upnp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// maxSOAPResponseBytes caps one SOAP response body (64 KiB).
const maxSOAPResponseBytes = 64 * 1024

// maxCandidateAttempts bounds the IGDv1 random candidate retry (v0.8 §3.3:
// bounded random retry, never a linear port scan).
const maxCandidateAttempts = 8

// Common UPnP error codes this client interprets.
const (
	errorCodeInvalidAction      = 401
	errorCodeActionFailed       = 501
	errorCodeConflictInMapping  = 718
	errorCodePermanentLeaseOnly = 725
)

// SOAP errors.
var (
	ErrResponseTooLarge   = errors.New("upnp: SOAP response exceeds the size cap")
	ErrMalformedSOAP      = errors.New("upnp: SOAP response is malformed")
	ErrUnownedMapping     = errors.New("upnp: mapping lacks an exact internal tuple; refusing to send")
	ErrForeignMapping     = errors.New("upnp: mapping entry does not belong to this client; refusing to delete")
	ErrNoMappingPort      = errors.New("upnp: gateway refused every bounded candidate port")
	ErrPermanentOnlyLease = errors.New("upnp: gateway only supports permanent leases; unsupported by default (crash residue risk)")
)

// SOAPError carries a UPnP errorCode/errorDescription pair.
type SOAPError struct {
	Code        int
	Description string
}

func (e *SOAPError) Error() string {
	return fmt.Sprintf("upnp: SOAP fault %d: %s", e.Code, e.Description)
}

// MapRequest is one port mapping request.
type MapRequest struct {
	Protocol              string // "TCP" or "UDP"
	InternalAddress       string // IPv4 literal
	InternalPort          uint16
	RequestedExternalPort uint16 // 0 = any (v2 picks; v1 retries candidates)
	Lease                 time.Duration
	Description           string
	Rand                  func() (uint16, error) // CSPRNG seam for tests; crypto/rand default
}

// MapResult is the mapping the gateway granted.
type MapResult struct {
	Protocol             string
	InternalAddress      string
	InternalPort         uint16
	AssignedExternalPort uint16
	// AssignedExternalAddress is filled from GetExternalIPAddress by the
	// adapter (the add actions do not return it) and stays invalid when the
	// device lacks that action.
	AssignedExternalAddress netip.Addr
	Lease                   time.Duration
	Description             string
}

// soapEnvelope is the request envelope skeleton.
const soapEnvelope = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>`

// soapFields is the decoded action-response field table.
type soapFields map[string]string

// soapField renders one SOAP argument. Values are XML-escaped by
// xml.EscapeText to keep device-supplied strings inert.
func soapField(name, value string) string {
	var escaped bytes.Buffer
	xml.EscapeText(&escaped, []byte(value))
	return "<" + name + ">" + escaped.String() + "</" + name + ">"
}

// soapFieldUint renders an unsigned integer argument.
func soapFieldUint(name string, value uint16) string {
	return soapField(name, strconv.FormatUint(uint64(value), 10))
}

// buildAddMapping renders AddPortMapping (v1) or AddAnyPortMapping (v2).
func buildAddMapping(service Service, req MapRequest, externalPort uint16) string {
	action := "AddPortMapping"
	if service.IGDv2 {
		action = "AddAnyPortMapping"
	}
	var fields strings.Builder
	fields.WriteString(soapField("NewRemoteHost", ""))
	fields.WriteString(soapFieldUint("NewExternalPort", externalPort))
	fields.WriteString(soapField("NewProtocol", req.Protocol))
	fields.WriteString(soapFieldUint("NewInternalPort", req.InternalPort))
	fields.WriteString(soapField("NewInternalClient", req.InternalAddress))
	fields.WriteString(soapField("NewEnabled", "1"))
	fields.WriteString(soapField("NewPortMappingDescription", req.Description))
	fields.WriteString(soapField("NewLeaseDuration", strconv.FormatUint(uint64(req.Lease/time.Second), 10)))
	return fmt.Sprintf(soapEnvelope, action, service.Type, fields.String(), action)
}

// buildExternalAddress renders GetExternalIPAddress.
func buildExternalAddress(service Service) string {
	return fmt.Sprintf(soapEnvelope, "GetExternalIPAddress", service.Type, "", "GetExternalIPAddress")
}

// buildQueryMapping renders GetSpecificPortMappingEntry.
func buildQueryMapping(service Service, externalPort uint16, protocol string) string {
	var fields strings.Builder
	fields.WriteString(soapField("NewRemoteHost", ""))
	fields.WriteString(soapFieldUint("NewExternalPort", externalPort))
	fields.WriteString(soapField("NewProtocol", protocol))
	return fmt.Sprintf(soapEnvelope, "GetSpecificPortMappingEntry", service.Type, fields.String(), "GetSpecificPortMappingEntry")
}

// buildDeleteMapping renders DeletePortMapping.
func buildDeleteMapping(service Service, externalPort uint16, protocol string) string {
	var fields strings.Builder
	fields.WriteString(soapField("NewRemoteHost", ""))
	fields.WriteString(soapFieldUint("NewExternalPort", externalPort))
	fields.WriteString(soapField("NewProtocol", protocol))
	return fmt.Sprintf(soapEnvelope, "DeletePortMapping", service.Type, fields.String(), "DeletePortMapping")
}

type soapFault struct {
	FaultCode   string          `xml:"faultcode"`
	FaultString string          `xml:"faultstring"`
	Detail      soapFaultDetail `xml:"detail"`
}

type soapFaultDetail struct {
	UPnPError soapUPnPError `xml:"UPnPError"`
}

type soapUPnPError struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}

// parseSOAPResponse decodes one SOAP envelope with a token walk: a Fault
// becomes *SOAPError, the first element inside Body must be the wanted
// action response, and its child elements are returned as a field table.
func parseSOAPResponse(body []byte, wantAction string) (soapFields, error) {
	if len(body) > maxSOAPResponseBytes {
		return nil, ErrResponseTooLarge
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	fields := soapFields{}
	inBody := false
	var actionName string
	var currentField string
	var currentValue strings.Builder
	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedSOAP, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "Body" && actionName == "" && currentField == "":
				inBody = true
				continue
			case inBody && actionName == "" && t.Name.Local == "Fault":
				var fault soapFault
				if err := decoder.DecodeElement(&fault, &t); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrMalformedSOAP, err)
				}
				return nil, &SOAPError{
					Code:        fault.Detail.UPnPError.ErrorCode,
					Description: fault.Detail.UPnPError.ErrorDescription,
				}
			case inBody && actionName == "":
				if t.Name.Local != wantAction+"Response" {
					return nil, fmt.Errorf("%w: got element %q want %q", ErrMalformedSOAP, t.Name.Local, wantAction+"Response")
				}
				actionName = t.Name.Local
			case actionName != "":
				currentField = t.Name.Local
				currentValue.Reset()
			}
		case xml.CharData:
			if currentField != "" {
				currentValue.Write(t)
			}
		case xml.EndElement:
			switch {
			case currentField != "" && t.Name.Local == currentField:
				fields[currentField] = strings.TrimSpace(currentValue.String())
				currentField = ""
			case t.Name.Local == actionName:
				return fields, nil
			case t.Name.Local == "Body":
				return nil, fmt.Errorf("%w: no %sResponse element", ErrMalformedSOAP, wantAction)
			}
		}
	}
	return nil, ErrMalformedSOAP
}

// postSOAP sends one SOAP action POST to the service control URL and returns
// the response body (size-capped).
func postSOAP(ctx context.Context, client *http.Client, service Service, action, envelope string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, service.ControlURL, bytes.NewReader([]byte(envelope)))
	if err != nil {
		return nil, fmt.Errorf("upnp: SOAP request: %w", err)
	}
	request.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	request.Header.Set("SOAPACTION", fmt.Sprintf("%q", service.Type+"#"+action))
	// The SOAP envelope carries the internal tuple: a redirect would replay
	// it to a foreign host, so the control POST refuses redirects exactly
	// like the description fetch does.
	redirectRefused := *client
	redirectRefused.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("%w: SOAP redirect to %s", ErrRedirectRefused, req.URL)
	}
	response, err := redirectRefused.Do(request)
	if err != nil {
		return nil, fmt.Errorf("upnp: SOAP %s: %w", action, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSOAPResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("upnp: SOAP %s read: %w", action, err)
	}
	if len(body) > maxSOAPResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}
