package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137

	IPv4_PSEUDO_LENGTH int = 12
)

type IPv4 struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
	Padding    []byte
	Payload    []byte

	headerLength int
}

var (
	ipv4Pool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &IPv4{}
		},
	}

	globalIPID uint32
)

func ReleaseIPv4(ip4 *IPv4) {
	// clear internal slice references
	ip4.SrcIP = nil
	ip4.DstIP = nil
	ip4.Options = nil
	ip4.Padding = nil
	ip4.Payload = nil

	ipv4Pool.Put(ip4)
}

func NewIPv4() *IPv4 {
	var zero IPv4
	ip4 := ipv4Pool.Get().(*IPv4)
	*ip4 = zero
	return ip4
}

func IPID() uint16 {
	return uint16(atomic.AddUint32(&globalIPID, 1) & 0x0000ffff)
}

func ParseIPv4(pkt []byte, ip4 *IPv4) error {
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])

	ip4.Version = uint8(pkt[0]) >> 4
	ip4.IHL = uint8(pkt[0]) & 0x0F
	ip4.TOS = pkt[1]
	ip4.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip4.Id = binary.BigEndian.Uint16(pkt[4:6])
	ip4.Flags = uint8(flagsfrags >> 13)
	ip4.FragOffset = flagsfrags & 0x1FFF
	ip4.TTL = pkt[8]
	ip4.Protocol = IPProtocol(pkt[9])
	ip4.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	ip4.SrcIP = pkt[12:16]
	ip4.DstIP = pkt[16:20]

	if ip4.Length < 20 {
		return fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip4.Length)
	}
	if ip4.IHL < 5 {
		return fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip4.IHL)
	}
	if int(ip4.IHL*4) > int(ip4.Length) {
		return fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip4.IHL, ip4.Length)
	}
	if int(ip4.IHL)*4 > len(pkt) {
		return fmt.Errorf("Not all IP header bytes available")
	}
	ip4.Payload = pkt[ip4.IHL*4:]
	rest := pkt[20 : ip4.IHL*4]
	// Pull out IP options
	for len(rest) > 0 {
		if ip4.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			ip4.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: rest[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip4.Options = append(ip4.Options, opt)
			ip4.Padding = rest[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = rest[1]
			opt.OptionData = rest[2:opt.OptionLength]
		}
		if len(rest) >= int(opt.OptionLength) {
			rest = rest[opt.OptionLength:]
		} else {
			return fmt.Errorf("IP option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
		}
		ip4.Options = append(ip4.Options, opt)
	}
	return nil
}

func (ip *IPv4) PseudoHeader(buf []byte, proto IPProtocol, dataLen int) error {
	if len(buf) != IPv4_PSEUDO_LENGTH {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(buf), IPv4_PSEUDO_LENGTH)
	}
	copy(buf[0:4], ip.SrcIP)
	copy(buf[4:8], ip.DstIP)
	buf[8] = 0
	buf[9] = byte(proto)
	binary.BigEndian.PutUint16(buf[10:], uint16(dataLen))
	return nil
}

func (ip *IPv4) HeaderLength() int {
	if ip.headerLength == 0 {
		optionLength := uint8(0)
		for _, opt := range ip.Options {
			switch opt.OptionType {
			case 0:
				// this is the end of option lists
				optionLength++
			case 1:
				// this is the padding
				optionLength++
			default:
				optionLength += opt.OptionLength

			}
		}
		// make sure the options are aligned to 32 bit boundary
		if (optionLength % 4) != 0 {
			optionLength += 4 - (optionLength % 4)
		}
		ip.IHL = 5 + (optionLength / 4)
		ip.headerLength = int(optionLength) + 20
	}
	return ip.headerLength
}

func (ip *IPv4) flagsfrags() (ff uint16) {
	ff |= uint16(ip.Flags) << 13
	ff |= ip.FragOffset
	return
}

func (ip *IPv4) Serialize(hdr []byte, dataLen int) error {
	if len(hdr) != ip.HeaderLength() {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), ip.HeaderLength())
	}
	hdr[0] = (ip.Version << 4) | ip.IHL
	hdr[1] = ip.TOS
	ip.Length = uint16(ip.headerLength + dataLen)
	binary.BigEndian.PutUint16(hdr[2:], ip.Length)
	binary.BigEndian.PutUint16(hdr[4:], ip.Id)
	binary.BigEndian.PutUint16(hdr[6:], ip.flagsfrags())
	hdr[8] = ip.TTL
	hdr[9] = byte(ip.Protocol)
	copy(hdr[12:16], ip.SrcIP)
	copy(hdr[16:20], ip.DstIP)

	curLocation := 20
	// Now, we will encode the options
	for _, opt := range ip.Options {
		switch opt.OptionType {
		case 0:
			// this is the end of option lists
			hdr[curLocation] = 0
			curLocation++
		case 1:
			// this is the padding
			hdr[curLocation] = 1
			curLocation++
		default:
			hdr[curLocation] = opt.OptionType
			hdr[curLocation+1] = opt.OptionLength

			// sanity checking to protect us from buffer overrun
			if len(opt.OptionData) > int(opt.OptionLength-2) {
				return fmt.Errorf("option length is smaller than length of option data")
			}
			copy(hdr[curLocation+2:curLocation+int(opt.OptionLength)], opt.OptionData)
			curLocation += int(opt.OptionLength)
		}
	}
	hdr[10] = 0
	hdr[11] = 0
	ip.Checksum = Checksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:], ip.Checksum)
	return nil
}

