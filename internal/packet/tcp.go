package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

type TCPOption struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

type TCP struct {
	SrcPort                                    uint16
	DstPort                                    uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	Options                                    []TCPOption
	opts                                       [4]TCPOption
	Padding                                    []byte
	Payload                                    []byte

	headerLength int
}

var (
	tcpPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &TCP{}
		},
	}
)

func NewTCP() *TCP {
	var zero TCP
	tcp := tcpPool.Get().(*TCP)
	*tcp = zero
	return tcp
}

func ReleaseTCP(tcp *TCP) {
	// clear internal slice references
	for _, opt := range tcp.Options {
		opt.OptionData = nil
	}
	tcp.Options = nil
	tcp.Padding = nil
	tcp.Payload = nil

	tcpPool.Put(tcp)
}

func ParseTCP(pkt []byte, tcp *TCP) error {
	tcp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	tcp.DstPort = binary.BigEndian.Uint16(pkt[2:4])
	tcp.Seq = binary.BigEndian.Uint32(pkt[4:8])
	tcp.Ack = binary.BigEndian.Uint32(pkt[8:12])
	tcp.DataOffset = pkt[12] >> 4
	tcp.FIN = pkt[13]&0x01 != 0
	tcp.SYN = pkt[13]&0x02 != 0
	tcp.RST = pkt[13]&0x04 != 0
	tcp.PSH = pkt[13]&0x08 != 0
	tcp.ACK = pkt[13]&0x10 != 0
	tcp.URG = pkt[13]&0x20 != 0
	tcp.ECE = pkt[13]&0x40 != 0
	tcp.CWR = pkt[13]&0x80 != 0
	tcp.NS = pkt[12]&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(pkt[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(pkt[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(pkt[18:20])
	tcp.Options = tcp.opts[:0]
	if tcp.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", tcp.DataOffset)
	}
	dataStart := int(tcp.DataOffset) * 4
	if dataStart > len(pkt) {
		return errors.New("TCP data offset greater than packet length")
	}
	tcp.Payload = pkt[dataStart:]
	// From here on, data points just to the header options.
	rest := pkt[20:dataStart]
	for len(rest) > 0 {
		if tcp.Options == nil {
			// Pre-allocate to avoid allocating a slice.
			tcp.Options = tcp.opts[:0]
		}
		tcp.Options = append(tcp.Options, TCPOption{OptionType: rest[0]})
		opt := &tcp.Options[len(tcp.Options)-1]
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			tcp.Padding = rest[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = rest[1]
			if opt.OptionLength < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.OptionLength)
			} else if int(opt.OptionLength) > len(rest) {
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.OptionLength, len(pkt))
			}
			opt.OptionData = rest[2:opt.OptionLength]
		}
		rest = rest[opt.OptionLength:]
	}

	tcp.headerLength = int(tcp.DataOffset * 4)
	return nil
}

func (tcp *TCP) HeaderLength() int {
	if tcp.headerLength == 0 {
		optionLength := 0
		for _, o := range tcp.Options {
			switch o.OptionType {
			case 0, 1:
				optionLength += 1
			default:
				optionLength += 2 + len(o.OptionData)
			}
		}
		tcp.Padding = lotsOfZeros[:optionLength%4]
		tcp.headerLength = len(tcp.Padding) + optionLength + 20
		tcp.DataOffset = uint8(tcp.headerLength / 4)
	}

	return tcp.headerLength
}

func (tcp *TCP) flagsAndOffset() uint16 {
	f := uint16(tcp.DataOffset) << 12
	if tcp.FIN {
		f |= 0x0001
	}
	if tcp.SYN {
		f |= 0x0002
	}
	if tcp.RST {
		f |= 0x0004
	}
	if tcp.PSH {
		f |= 0x0008
	}
	if tcp.ACK {
		f |= 0x0010
	}
	if tcp.URG {
		f |= 0x0020
	}
	if tcp.ECE {
		f |= 0x0040
	}
	if tcp.CWR {
		f |= 0x0080
	}
	if tcp.NS {
		f |= 0x0100
	}
	return f
}

func (tcp *TCP) Serialize(hdr []byte, full []byte) error {
	if tcp.HeaderLength() != len(hdr) {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), tcp.HeaderLength())
	}
	binary.BigEndian.PutUint16(hdr, uint16(tcp.SrcPort))
	binary.BigEndian.PutUint16(hdr[2:], uint16(tcp.DstPort))
	binary.BigEndian.PutUint32(hdr[4:], tcp.Seq)
	binary.BigEndian.PutUint32(hdr[8:], tcp.Ack)
	binary.BigEndian.PutUint16(hdr[12:], tcp.flagsAndOffset())
	binary.BigEndian.PutUint16(hdr[14:], tcp.Window)
	binary.BigEndian.PutUint16(hdr[18:], tcp.Urgent)
	start := 20
	for _, o := range tcp.Options {
		hdr[start] = o.OptionType
		switch o.OptionType {
		case 0, 1:
			start++
		default:
			o.OptionLength = uint8(len(o.OptionData) + 2)
			hdr[start+1] = o.OptionLength
			copy(hdr[start+2:start+len(o.OptionData)+2], o.OptionData)
			start += int(o.OptionLength)
		}
	}
	copy(hdr[start:], tcp.Padding)

	hdr[16] = 0
	hdr[17] = 0
	tcp.Checksum = Checksum(full)
	binary.BigEndian.PutUint16(hdr[16:], tcp.Checksum)
	return nil
}
