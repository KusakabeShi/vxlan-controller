package client

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tapName = "tap-inject"

type TapDevice struct {
	Name string
	f    *os.File
}

func OpenTap(name string) (*TapDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifreq := make([]byte, 40) // IFNAMSIZ + flags etc; enough for TUNSETIFF
	copy(ifreq, []byte(name))
	flags := uint16(unix.IFF_TAP | unix.IFF_NO_PI)
	binary.LittleEndian.PutUint16(ifreq[16:18], flags)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, errno
	}
	// Ensure the device reports carrier up so the bridge port is not put into "disabled"
	// state (NO-CARRIER TAP ports don't participate in flooding/forwarding).
	_ = unix.IoctlSetInt(fd, unix.TUNSETCARRIER, 1)
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	return &TapDevice{Name: name, f: f}, nil
}

func (t *TapDevice) Read(p []byte) (int, error) {
	if t == nil || t.f == nil {
		return 0, errors.New("tap closed")
	}
	return t.f.Read(p)
}

func (t *TapDevice) Write(p []byte) (int, error) {
	if t == nil || t.f == nil {
		return 0, errors.New("tap closed")
	}
	return t.f.Write(p)
}

func (t *TapDevice) Close() error {
	if t == nil || t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}
