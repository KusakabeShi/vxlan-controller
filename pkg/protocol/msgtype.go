package protocol

type MsgType byte

const (
	// Handshake
	MsgHandshakeInit MsgType = 0x01
	MsgHandshakeResp MsgType = 0x02

	// Client → Controller (TCP)
	MsgClientRegister MsgType = 0x10
	MsgRouteUpdate    MsgType = 0x11
	MsgProbeResults   MsgType = 0x12

	// Controller → Client (TCP)
	MsgControllerState        MsgType = 0x20
	MsgControllerStateUpdate  MsgType = 0x21
	MsgControllerProbeRequest MsgType = 0x22

	// Broadcast relay (UDP, communication channel)
	MsgMulticastForward MsgType = 0x30
	MsgMulticastDeliver MsgType = 0x31

	// Probe (UDP, probe channel)
	MsgProbeRequest  MsgType = 0x40
	MsgProbeResponse MsgType = 0x41
)

