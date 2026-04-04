package client

import (
	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	pb "vxlan-controller/proto"
	"vxlan-controller/pkg/types"
)

func (c *Client) sendFullLocalStateToController(ctrlID types.ControllerID) error {
	c.mu.Lock()
	ctrl := c.controllers[ctrlID]
	entries := make([]*pb.MacIpEntry, 0, len(c.localRoutes))
	for _, e := range c.localRoutes {
		if e == nil || len(e.Mac) != 6 {
			continue
		}
		entries = append(entries, e)
	}
	c.mu.Unlock()

	if ctrl == nil {
		return nil
	}
	batch := &pb.RouteUpdateBatch{}
	for _, e := range entries {
		batch.Updates = append(batch.Updates, &pb.RouteUpdate{Op: pb.RouteUpdate_OP_ADD, Entry: e})
	}
	if len(batch.Updates) == 0 {
		return nil
	}
	b, err := proto.Marshal(batch)
	if err != nil {
		return err
	}
	return ctrl.Send(protocol.MsgRouteUpdate, b)
}
