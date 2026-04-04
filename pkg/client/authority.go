package client

import (
	"context"
	"sort"
	"time"

	pb "vxlan-controller/proto"
	"vxlan-controller/pkg/types"
)

func (c *Client) authoritySelectLoop(ctx context.Context) {
	timer := time.NewTimer(c.cfg.InitTimeout.D)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	for {
		c.selectAuthority()
		select {
		case <-ctx.Done():
			return
		case <-c.authNotifyCh:
			// re-evaluate
		case <-time.After(5 * time.Second):
		}
	}
}

func (c *Client) selectAuthority() {
	type cand struct {
		id types.ControllerID
		clientCount uint32
		lastChange int64
	}
	var cands []cand
	c.mu.Lock()
	for id, ctrl := range c.controllers {
		ctrl.mu.Lock()
		synced := ctrl.Synced && ctrl.View != nil && ctrl.View.Raw != nil
		var cc uint32
		var lc int64
		if synced {
			cc = ctrl.View.Raw.GetClientCount()
			lc = ctrl.View.Raw.GetLastClientChangeUnixNs()
		}
		ctrl.mu.Unlock()
		if synced {
			cands = append(cands, cand{id: id, clientCount: cc, lastChange: lc})
		}
	}
	var prev *types.ControllerID
	if c.authority != nil {
		cp := *c.authority
		prev = &cp
	}
	c.mu.Unlock()

	if len(cands) == 0 {
		return
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].clientCount != cands[j].clientCount {
			return cands[i].clientCount > cands[j].clientCount
		}
		if cands[i].lastChange != cands[j].lastChange {
			return cands[i].lastChange < cands[j].lastChange
		}
		return types.CompareClientID(types.ClientID(cands[i].id), types.ClientID(cands[j].id)) < 0
	})

	newID := cands[0].id
	if prev != nil && *prev == newID {
		return
	}

	var pending *pb.ControllerProbeRequest
	c.mu.Lock()
	c.authority = &newID
	if c.pendingProbe != nil {
		pending = c.pendingProbe[newID]
		delete(c.pendingProbe, newID)
	}
	c.mu.Unlock()
	selectNonBlocking(c.fdbNotifyCh)
	if pending != nil {
		go c.runProbe(pending)
	}
}
