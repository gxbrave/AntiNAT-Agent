// P14 repair-1 M2 race oracle: dataPlane.recover reads d.cfg.Journal/Mappers
// with NO lock while a liveness reboot (rebuildTraversal) re-publishes
// d.cfg.Mappers/StunObserver/StunSource under dataPlane.mu. Before the fix the
// unlocked d.cfg.Mappers read on the recover path raced the rebuild write — the
// exact discipline P12W repair applied to newStunOnlyActor/runDetection. The
// -race detector is the oracle: with the config-snapshot fix this is race-free,
// and it fails loudly if a future change reintroduces an unlocked d.cfg read on
// the recover path.
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func TestDataPlaneRecoverConcurrentWithMappersRebuildNoDataRace(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	d := newDataPlane(dataPlaneConfig{
		Store:   st,
		Journal: st.MappingJournal(),
		Mappers: map[traversal.MappingLayerKind]traversal.GatewayMapper{},
		Clock:   time.Now,
	})
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	// Simulated liveness rebuild: republish fresh Mappers under dataPlane.mu
	// exactly as rebuildTraversal does. This is the WRITER the recover path used
	// to race by reading d.cfg.Mappers with no lock.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d.mu.Lock()
			d.cfg.Mappers = map[traversal.MappingLayerKind]traversal.GatewayMapper{}
			d.mu.Unlock()
		}
	}()

	ctx := context.Background()
	for i := 0; i < 200; i++ {
		if _, err := d.recover(ctx); err != nil {
			t.Fatalf("recover pass %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}
