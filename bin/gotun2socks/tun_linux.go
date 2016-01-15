package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	IFF_TUN   = 0x0001
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func openTunDevice(name string) (*os.File, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return nil, err
	}
	return file, nil
}
