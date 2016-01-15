package gotun2socks

import (
	"log"
	"os"
	"sync"
	"syscall"
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
		Timeout: time.Second,
	}
)

type Tun2Socks struct {
	dev            *os.File
	localSocksAddr string

	writerStopCh chan bool
	readerStopCh chan bool
	writeCh      chan interface{}

	tcpConnTrackLock sync.Mutex
	tcpConnTrackMap  map[string]*tcpConnTrack

	udpConnTrackLock sync.Mutex
	udpConnTrackMap  map[string]*udpConnTrack
}

func dialLocalSocks(localAddr string) (*gosocks.SocksConn, error) {
	return localSocksDialer.Dial(localAddr)
}

func New(dev *os.File, localSocksAddr string) *Tun2Socks {
	return &Tun2Socks{
		dev:             dev,
		localSocksAddr:  localSocksAddr,
		writerStopCh:    make(chan bool, 10),
		readerStopCh:    make(chan bool, 10),
		writeCh:         make(chan interface{}, 10000),
		tcpConnTrackMap: make(map[string]*tcpConnTrack),
		udpConnTrackMap: make(map[string]*udpConnTrack),
	}
}

func (t2s *Tun2Socks) Stop() {
	t2s.readerStopCh <- true
	t2s.writerStopCh <- true

	t2s.dev.Close()

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

func (t2s *Tun2Socks) Run() {
	syscall.SetNonblock(int(t2s.dev.Fd()), false)

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
		select {
		case <-t2s.readerStopCh:
			return
		default:
			n, e := t2s.dev.Read(buf[:])
			if e != nil {
				// TODO: stop at critical error
				log.Printf("read packet error: %s", e)
				continue
			}
			e = packet.ParseIPv4(buf[:n], &ip)
			if e != nil {
				log.Printf("error to parse IPv4: %s", e)
				continue
			}
			switch ip.Protocol {
			case packet.IPProtocolTCP:
				e = packet.ParseTCP(ip.Payload, &tcp)
				if e != nil {
					log.Printf("error to parse TCP: %s", e)
					continue
				}
				t2s.tcp(buf[:n], &ip, &tcp)

			case packet.IPProtocolUDP:
				e = packet.ParseUDP(ip.Payload, &udp)
				if e != nil {
					log.Printf("error to parse UDP: %s", e)
					continue
				}
				t2s.udp(buf[:n], &ip, &udp)

			default:
				// Unsupported packets
				log.Printf("Unsupported packet: protocol %d", ip.Protocol)
			}
		}
	}
}
