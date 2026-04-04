package client

import (
	"context"
	"errors"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

func (c *Client) commUDPReadLoop(ctx context.Context, af types.AFName, rt *AFRuntime) {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := rt.CommUDP.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		msgType, plain, _, err := protocol.ReadUDPPacket(pkt, rt.FindCommSession)
		if err != nil {
			continue
		}
		if msgType != protocol.MsgMulticastDeliver {
			continue
		}
		var d pb.MulticastDeliver
		if err := proto.Unmarshal(plain, &d); err != nil {
			continue
		}
		if len(d.Frame) == 0 {
			continue
		}
		select {
		case c.tapInjectCh <- d.Frame:
		default:
			// drop
		}
	}
}
