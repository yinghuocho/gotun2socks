package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TAPWIN32_MAX_REG_SIZE    = 256
	TUNTAP_COMPONENT_ID_0901 = "tap0901"
	TUNTAP_COMPONENT_ID_0801 = "tap0801"
	NETWORK_KEY              = `SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	ADAPTER_KEY              = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

var (
	TAP_IOCTL_GET_MTU          = tap_control_code(3, 0)
	TAP_IOCTL_SET_MEDIA_STATUS = tap_control_code(6, 0)
	TAP_IOCTL_CONFIG_TUN       = tap_control_code(10, 0)
)

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

func tap_control_code(request, method uint32) uint32 {
	return ctl_code(34, request, method, 0)
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}

	l := len(b) / 2
	u16 := make([]uint16, l)
	for i := 0; i < l; i += 1 {
		u16[i] = uint16(b[2*i]) + (uint16(b[2*i+1]) << 8)
	}
	return windows.UTF16ToString(u16)
}

func getTuntapName(componentId string) (string, error) {
	keyName := fmt.Sprintf(NETWORK_KEY+"\\%s\\Connection", componentId)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyName, registry.READ)
	if err != nil {
		key.Close()
		return "", err
	}
	var bufLength uint32 = TAPWIN32_MAX_REG_SIZE
	buf := make([]byte, bufLength)
	name, _ := windows.UTF16FromString("Name")
	var valtype uint32
	err = windows.RegQueryValueEx(
		windows.Handle(key),
		&name[0],
		nil,
		&valtype,
		&buf[0],
		&bufLength,
	)
	if err != nil {
		key.Close()
		return "", err
	}
	s := decodeUTF16(buf)
	return s, nil
}

func getTuntapComponentId() (string, error) {
	adapters, err := registry.OpenKey(registry.LOCAL_MACHINE, ADAPTER_KEY, registry.READ)
	if err != nil {
		return "", err
	}
	var i uint32
	for i = 0; i < 1000; i++ {
		var name_length uint32 = TAPWIN32_MAX_REG_SIZE
		buf := make([]uint16, name_length)
		if err = windows.RegEnumKeyEx(
			windows.Handle(adapters),
			i,
			&buf[0],
			&name_length,
			nil,
			nil,
			nil,
			nil); err != nil {
			return "", err
		}
		key_name := windows.UTF16ToString(buf[:])
		adapter, err := registry.OpenKey(adapters, key_name, registry.READ)
		if err != nil {
			continue
		}
		name, _ := windows.UTF16FromString("ComponentId")
		name2, _ := windows.UTF16FromString("NetCfgInstanceId")
		var valtype uint32
		var component_id = make([]byte, TAPWIN32_MAX_REG_SIZE)
		var componentLen = uint32(len(component_id))
		if err = windows.RegQueryValueEx(
			windows.Handle(adapter),
			&name[0],
			nil,
			&valtype,
			&component_id[0],
			&componentLen); err != nil {
			continue
		}

		id := decodeUTF16(component_id)
		if id == TUNTAP_COMPONENT_ID_0901 || id == TUNTAP_COMPONENT_ID_0801 {
			var valtype uint32
			var netCfgInstanceId = make([]byte, TAPWIN32_MAX_REG_SIZE)
			var netCfgInstanceIdLen = uint32(len(netCfgInstanceId))
			if err = windows.RegQueryValueEx(
				windows.Handle(adapter),
				&name2[0],
				nil,
				&valtype,
				&netCfgInstanceId[0],
				&netCfgInstanceIdLen); err != nil {
				return "", err
			}
			s := decodeUTF16(netCfgInstanceId)
			log.Printf("device component id: %s", s)
			adapter.Close()
			adapters.Close()
			return s, nil
		}
		adapter.Close()
	}
	adapters.Close()
	return "", errors.New("not found component id")
}

func openTunDevice(name, addr, gw, mask string) (io.ReadWriteCloser, error) {
	componentId, err := getTuntapComponentId()
	if err != nil {
		return nil, err
	}
	devId, _ := windows.UTF16FromString(fmt.Sprintf(`\\.\Global\%s.tap`, componentId))
	fd, err := windows.CreateFile(
		&devId[0],
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED,
		//windows.FILE_ATTRIBUTE_SYSTEM,
		0)
	if err != nil {
		return nil, err
	}

	// set connect.
	inBuffer := []byte("\x01\x00\x00\x00")
	var returnLen uint32
	err = windows.DeviceIoControl(
		fd,
		TAP_IOCTL_SET_MEDIA_STATUS,
		&inBuffer[0],
		uint32(len(inBuffer)),
		&inBuffer[0],
		uint32(len(inBuffer)),
		&returnLen,
		nil,
	)
	if err != nil {
		windows.Close(fd)
		return nil, err
	}

	// config address
	tunAddr := net.ParseIP(addr).To4()
	tunMask := net.ParseIP(mask).To4()
	tunNet := tunAddr.Mask(net.IPv4Mask(tunMask[0], tunMask[1], tunMask[2], tunMask[3])).To4()
	configTunParam := append(tunAddr, tunNet...)
	configTunParam = append(configTunParam, tunMask...)
	err = windows.DeviceIoControl(
		fd,
		TAP_IOCTL_CONFIG_TUN,
		&configTunParam[0],
		uint32(len(configTunParam)),
		&configTunParam[0],
		uint32(len(configTunParam)),
		&returnLen,
		nil,
	)
	if err != nil {
		windows.Close(fd)
		return nil, err
	}

	// netsh
	devName, err := getTuntapName(componentId)
	if err != nil {
		windows.Close(fd)
		return nil, err
	}
	log.Printf("device name: %s", devName)
	cmd := exec.Command("netsh", "interface", "ip", "set", "address", devName, "static", addr, mask, gw, "1")
	err = cmd.Run()
	if err != nil {
		windows.Close(fd)
		return nil, err
	}

	return newWinTapDev(fd), nil
}

type winTapDev struct {
	fd          windows.Handle
	rOverlapped windows.Overlapped
	wOverlapped windows.Overlapped
}

func newWinTapDev(fd windows.Handle) *winTapDev {
	rOverlapped := windows.Overlapped{}
	rEvent, _ := windows.CreateEvent(nil, 0, 0, nil)
	rOverlapped.HEvent = windows.Handle(rEvent)

	wOverlapped := windows.Overlapped{}
	wEvent, _ := windows.CreateEvent(nil, 0, 0, nil)
	wOverlapped.HEvent = windows.Handle(wEvent)

	dev := &winTapDev{
		fd:          fd,
		rOverlapped: rOverlapped,
		wOverlapped: wOverlapped,
	}
	return dev
}

func (dev *winTapDev) Read(data []byte) (int, error) {
	var done uint32
	for {
		dev.rOverlapped.Offset = 0
		dev.rOverlapped.OffsetHigh = 0
		err := windows.ReadFile(dev.fd, data, &done, &dev.rOverlapped)
		if err != nil {
			if err != windows.ERROR_IO_PENDING {
				return 0, err
			} else {
				windows.WaitForSingleObject(dev.rOverlapped.HEvent, windows.INFINITE)
			}
		}
		if done != 0 {
			// discard IPv6 packets
			if data[0]&0xf0 == 0x60 {
				continue
			} else {
				return int(done), nil
			}
		}
	}
}

func (dev *winTapDev) Write(data []byte) (int, error) {
	var written uint32
	dev.wOverlapped.Offset = 0
	dev.wOverlapped.OffsetHigh = 0
	err := windows.WriteFile(dev.fd, data, &written, &dev.wOverlapped)
	if err != nil {
		if err != windows.ERROR_IO_PENDING {
			return 0, err
		} else {
			windows.WaitForSingleObject(dev.wOverlapped.HEvent, windows.INFINITE)
		}
	}
	n := int(written)
	if n != len(data) {
		return n, fmt.Errorf("write %d bytes, return %d", len(data), n)
	} else {
		return n, nil
	}
}

func (dev *winTapDev) Close() error {
	return windows.Close(dev.fd)
}
