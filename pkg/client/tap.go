package client

import (
	"log"
	"net"
	"os"
	"time"
	"unsafe"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"

	pb "vxlan-controller/proto"

	"golang.org/x/sys/unix"
)

const (
	tapDeviceName   = "tap-inject"
	maxBroadcastPPS = 100
)

// openTapDevice opens /dev/net/tun with IFF_TAP | IFF_NO_PI.
func openTapDevice(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [40]byte
	copy(ifr[:16], []byte(name))
	flags := uint16(0x0002 | 0x1000) // IFF_TAP | IFF_NO_PI
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return nil, errno
	}

	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

// tapReadLoop reads broadcast/multicast frames from tap-inject and forwards to controller.
func (c *Client) tapReadLoop() {
	if c.TapFD == nil {
		return
	}

	buf := make([]byte, 65536)
	tokens := float64(maxBroadcastPPS)
	lastRefill := time.Now()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.TapFD.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				log.Printf("[Client] tap read error: %v", err)
				continue
			}
		}

		if n < 14 {
			continue
		}

		now := time.Now()
		elapsed := now.Sub(lastRefill).Seconds()
		tokens += elapsed * float64(maxBroadcastPPS)
		if tokens > float64(maxBroadcastPPS) {
			tokens = float64(maxBroadcastPPS)
		}
		lastRefill = now

		if tokens < 1 {
			continue
		}
		tokens--

		frame := make([]byte, n)
		copy(frame, buf[:n])

		if frame[0]&0x01 == 0 {
			continue
		}

		c.forwardBroadcast(frame)
	}
}

func (c *Client) forwardBroadcast(frame []byte) {
	fwd := &pb.MulticastForward{
		SourceClientId: c.ClientID[:],
		Payload:        frame,
	}
	data, err := proto.Marshal(fwd)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.AuthorityCtrl == nil {
		return
	}

	cc, ok := c.Controllers[*c.AuthorityCtrl]
	if !ok || cc.ActiveAF == "" {
		return
	}

	afCfg, ok := c.Config.AFSettings[cc.ActiveAF]
	if !ok {
		return
	}

	afc, ok := cc.AFConns[cc.ActiveAF]
	if !ok || afc.UDPSession == nil || afc.CommUDPConn == nil {
		return
	}

	for _, ctrl := range afCfg.Controllers {
		if types.ClientID(ctrl.PubKey) == *c.AuthorityCtrl {
			addr := &net.UDPAddr{
				IP:   ctrl.Addr.Addr().AsSlice(),
				Port: int(ctrl.Addr.Port()),
			}
			protocol.WriteUDPPacket(afc.CommUDPConn, addr, afc.UDPSession, protocol.MsgMulticastForward, data)
			break
		}
	}
}

// tapWriteLoop receives broadcast frames from the controller and injects into bridge.
func (c *Client) tapWriteLoop() {
	if c.TapFD == nil {
		return
	}

	for {
		select {
		case frame := <-c.tapInjectCh:
			if _, err := c.TapFD.Write(frame); err != nil {
				log.Printf("[Client] tap write error: %v", err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}
