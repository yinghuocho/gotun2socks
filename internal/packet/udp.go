package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

var (
	udpPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &UDP{}
		},
	}
)

func NewUDP() *UDP {
	var zero UDP
	udp := udpPool.Get().(*UDP)
	*udp = zero
	return udp
}

func ReleaseUDP(udp *UDP) {
	// clear internal slice references
	udp.Payload = nil
	udpPool.Put(udp)
}

func ParseUDP(pkt []byte, udp *UDP) error {
	udp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	udp.DstPort = binary.BigEndian.Uint16(pkt[2:4])
	udp.Length = binary.BigEndian.Uint16(pkt[4:6])
	udp.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	udp.Payload = pkt[8:]

	return nil
}

func (udp *UDP) Serialize(hdr []byte, full []byte) error {
	if len(hdr) != 8 {
		return fmt.Errorf("incorrect buffer size: %d buffer given, 8 needed", len(hdr))
	}
	binary.BigEndian.PutUint16(hdr, uint16(udp.SrcPort))
	binary.BigEndian.PutUint16(hdr[2:], uint16(udp.DstPort))
	udp.Length = uint16(len(udp.Payload)) + 8
	binary.BigEndian.PutUint16(hdr[4:], udp.Length)
	hdr[6] = 0
	hdr[7] = 0
	udp.Checksum = Checksum(full)
	binary.BigEndian.PutUint16(hdr[6:], udp.Checksum)
	return nil
}
