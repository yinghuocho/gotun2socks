package gotun2socks

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/yinghuocho/gosocks"
	"github.com/yinghuocho/gotun2socks/internal/packet"
)

const (
	MTU = 1500
)

var (
	localSocksDialer *gosocks.SocksDialer = &gosocks.SocksDialer{
		Auth:    &gosocks.AnonymousClientAuthenticator{},
		Timeout: 1 * time.Second,
	}

	_, ip1, _ = net.ParseCIDR("10.0.0.0/8")
	_, ip2, _ = net.ParseCIDR("172.16.0.0/12")
	_, ip3, _ = net.ParseCIDR("192.168.0.0/24")
)

type Tun2Socks struct {
	dev            io.ReadWriteCloser
	devAddr        string
	devGW          string
	localSocksAddr string
	publicOnly     bool

	writerStopCh chan bool
	writeCh      chan interface{}

	tcpConnTrackLock sync.Mutex
	tcpConnTrackMap  map[string]*tcpConnTrack

	udpConnTrackLock sync.Mutex
	udpConnTrackMap  map[string]*udpConnTrack

	dnsServers []string
	cache      *dnsCache
}

func isPrivate(ip net.IP) bool {
	return ip1.Contains(ip) || ip2.Contains(ip) || ip3.Contains(ip)
}

func dialLocalSocks(localAddr string) (*gosocks.SocksConn, error) {
	return localSocksDialer.Dial(localAddr)
}

func New(dev io.ReadWriteCloser, devAddr string, devGW string, localSocksAddr string, dnsServers []string, publicOnly bool, enableDnsCache bool) *Tun2Socks {
	t2s := &Tun2Socks{
		dev:             dev,
		devAddr:         devAddr,
		devGW:           devGW,
		localSocksAddr:  localSocksAddr,
		publicOnly:      publicOnly,
		writerStopCh:    make(chan bool, 10),
		writeCh:         make(chan interface{}, 10000),
		tcpConnTrackMap: make(map[string]*tcpConnTrack),
		udpConnTrackMap: make(map[string]*udpConnTrack),
		dnsServers:      dnsServers,
	}
	if enableDnsCache {
		t2s.cache = &dnsCache{
			storage: make(map[string]*dnsCacheEntry),
		}
	}
	return t2s
}

func (t2s *Tun2Socks) Stop() {
	t2s.writerStopCh <- true
	t2s.dev.Close()
	sendStopMarker(t2s.devAddr+":2222", t2s.devGW+":2222", []byte{2, 2, 2, 2})

	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()
	for _, tcpTrack := range t2s.tcpConnTrackMap {
		close(tcpTrack.quitByOther)
	}

	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()
	for _, udpTrack := range t2s.udpConnTrackMap {
		close(udpTrack.quitByOther)
	}
}

func sendStopMarker(laddr, raddr string, buf []byte) {
	local, _ := net.ResolveUDPAddr("udp", laddr)
	svr, _ := net.ResolveUDPAddr("udp", raddr)
	conn, err := net.DialUDP("udp", local, svr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write(buf)
}

func (t2s *Tun2Socks) Run() {
	// writer
	go func() {
		for {
			select {
			case pkt := <-t2s.writeCh:
				switch pkt.(type) {
				case *tcpPacket:
					tcp := pkt.(*tcpPacket)
					t2s.dev.Write(tcp.wire)
					releaseTCPPacket(tcp)
				case *udpPacket:
					udp := pkt.(*udpPacket)
					t2s.dev.Write(udp.wire)
					releaseUDPPacket(udp)
				}
			case <-t2s.writerStopCh:
				log.Printf("quit tun2socks writer")
				return
			}
		}
	}()

	// reader
	var buf [MTU]byte
	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP
	for {
		n, e := t2s.dev.Read(buf[:])
		if e != nil {
			// TODO: stop at critical error
			log.Printf("read packet error: %s", e)
			return
		}
		data := buf[:n]
		e = packet.ParseIPv4(data, &ip)
		if e != nil {
			log.Printf("error to parse IPv4: %s", e)
			continue
		}
		if ip.DstIP.String() == t2s.devAddr {
			log.Println("gotun2socks received stop marker, return")
			return
		}
		if t2s.publicOnly {
			if !ip.DstIP.IsGlobalUnicast() {
				continue
			}
			if isPrivate(ip.DstIP) && ip.DstIP.String() != t2s.devGW {
				continue
			}
		}

		switch ip.Protocol {
		case packet.IPProtocolTCP:
			e = packet.ParseTCP(ip.Payload, &tcp)
			if e != nil {
				log.Printf("error to parse TCP: %s", e)
				continue
			}
			t2s.tcp(data, &ip, &tcp)

		case packet.IPProtocolUDP:
			e = packet.ParseUDP(ip.Payload, &udp)
			if e != nil {
				log.Printf("error to parse UDP: %s", e)
				continue
			}
			if ip.DstIP.String() == t2s.devGW && udp.DstPort == 2222 && bytes.Compare(udp.Payload, []byte{2, 2, 2, 2}) == 0 {
				log.Println("gotun2socks received stop marker, return")
				return
			}
			t2s.udp(data, &ip, &udp)

		default:
			// Unsupported packets
			log.Printf("Unsupported packet: protocol %d", ip.Protocol)
		}
	}
}
