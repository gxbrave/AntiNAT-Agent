// Same-tuple STUN observation for the traversal manager (v0.8 §3.1 step 6,
// §4.2): the manager's upstream observation must be sourced from the
// forward's own bound tuple. The observer refuses any request without a
// same-tuple dialer — an observation from a foreign socket classifies a
// different NAT binding and would misattribute its mapped endpoint to the
// forward's layer evidence.
package stun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// ErrNoSameTupleDialer refuses an observation that cannot be sourced from
// the forward's own tuple.
var ErrNoSameTupleDialer = errors.New("stun: no same-tuple dialer for the forward's bound tuple")

// NewManagerObserver returns the traversal manager's STUN observation
// function wired to this package's transport-correct Binding exchange: it
// dials the STUN server through the manager-provided same-tuple dialer and
// reads the mapped endpoint from XOR-MAPPED-ADDRESS.
func NewManagerObserver() traversal.StunObserveFunc {
	return func(ctx context.Context, req traversal.StunObserveRequest) (netip.AddrPort, error) {
		if req.Dial == nil {
			return netip.AddrPort{}, ErrNoSameTupleDialer
		}
		timeout := req.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		conn, err := req.Dial(ctx, req.Server.String())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("stun: same-tuple dial %s: %w", req.Server, err)
		}
		defer conn.Close()
		return observeMappedOverConn(ctx, conn, req.Server, timeout)
	}
}
