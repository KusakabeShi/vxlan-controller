package client

import (
	"bytes"
	"log"

	"vxlan-controller/pkg/types"

	pb "vxlan-controller/proto"
)

// selectAuthority picks the best Controller from the synced ones.
// Criteria (in order):
// 1. ClientCount DESC
// 2. LastClientChange ASC (older = more stable)
// 3. ControllerID ASC (deterministic tiebreak)
func (c *Client) selectAuthority() *types.ControllerID {
	type candidate struct {
		id   types.ControllerID
		view *ControllerView
	}

	var candidates []candidate
	for id, cc := range c.Controllers {
		if cc.Synced {
			candidates = append(candidates, candidate{id: id, view: cc.State})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	best := candidates[0]
	for _, cand := range candidates[1:] {
		if cand.view.ClientCount > best.view.ClientCount {
			best = cand
			continue
		}
		if cand.view.ClientCount == best.view.ClientCount {
			if cand.view.LastClientChange.Before(best.view.LastClientChange) {
				best = cand
				continue
			}
			if cand.view.LastClientChange.Equal(best.view.LastClientChange) {
				if bytes.Compare(cand.id[:], best.id[:]) < 0 {
					best = cand
				}
			}
		}
	}

	id := best.id
	return &id
}

// authoritySelectLoop waits for init_timeout then selects authority,
// and continues to re-evaluate when synced state changes.
func (c *Client) authoritySelectLoop() {
	// Wait for init_timeout
	select {
	case <-c.initDone:
	case <-c.ctx.Done():
		return
	}

	log.Printf("[Client] init_timeout elapsed, selecting authority controller")

	c.mu.Lock()
	auth := c.selectAuthority()
	if auth != nil {
		c.AuthorityCtrl = auth
		log.Printf("[Client] selected authority controller: %s", auth.Hex()[:8])
	} else {
		log.Printf("[Client] no synced controller available for authority selection")
	}
	c.mu.Unlock()

	// Notify FDB reconciler
	c.notifyFDB()

	// Run initial probe now that authority is selected.
	// The controller's sync_new_client_debounce probe fires before init_timeout,
	// so it gets dropped. We need to probe immediately after init.
	if auth != nil {
		go c.executeProbe(&pb.ControllerProbeRequest{
			ProbeId:           1,
			ProbeTimeoutMs:    2000,
			ProbeTimes:        3,
			InProbeIntervalMs: 100,
		})
	}

	// Continue monitoring for authority changes
	for {
		select {
		case <-c.authorityChangeCh:
			c.mu.Lock()
			newAuth := c.selectAuthority()
			changed := false
			if newAuth == nil && c.AuthorityCtrl != nil {
				changed = true
				c.AuthorityCtrl = nil
				log.Printf("[Client] authority controller lost")
			} else if newAuth != nil && (c.AuthorityCtrl == nil || *newAuth != *c.AuthorityCtrl) {
				changed = true
				c.AuthorityCtrl = newAuth
				log.Printf("[Client] authority controller changed to %s", newAuth.Hex()[:8])
			}
			c.mu.Unlock()

			if changed {
				c.notifyFDB()
			}
		case <-c.ctx.Done():
			return
		}
	}
}
