package agent

import (
	"context"
	"net/netip"
	"sync"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

type mutableRouteTable struct {
	mu         sync.RWMutex
	gateway    netip.Addr
	iface      string
	hasDefault bool
	addrs      []traversal.IPv4Address
}

func (m *mutableRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gateway, m.iface, m.hasDefault, nil
}

func (m *mutableRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]traversal.IPv4Address(nil), m.addrs...), nil
}

type blockingShutdownClient struct {
	unblock chan struct{}
}

func (c *blockingShutdownClient) Connect(context.Context) error                     { return nil }
func (c *blockingShutdownClient) SendMessage(context.Context, string, []byte) error { return nil }
func (c *blockingShutdownClient) Close()                                            {}
func (c *blockingShutdownClient) Shutdown()                                         {}
func (c *blockingShutdownClient) Wait()                                             { <-c.unblock }
