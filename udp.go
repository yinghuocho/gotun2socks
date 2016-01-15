package gotun2socks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/yinghuocho/gosocks"
	"github.com/yinghuocho/gotun2socks/internal/packet"
)

type udpPacket struct {
	ip     *packet.IPv4
	udp    *packet.UDP
	mtuBuf []byte
	wire   []byte
}

type udpConnTrack struct {
	t2s *Tun2Socks
	id  string

	tunWriteCh  chan<- interface{}
	quitBySelf  chan bool
	quitByOther chan bool

	socksWriteCh chan *udpPacket
	socksClosed  chan bool

	localSocksAddr string
	socksConn      *gosocks.SocksConn

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

var (
	udpPacketPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &udpPacket{}
		},
	}
)

func newUDPPacket() *udpPacket {
	return udpPacketPool.Get().(*udpPacket)
}

func releaseUDPPacket(pkt *udpPacket) {
	packet.ReleaseIPv4(pkt.ip)
	packet.ReleaseUDP(pkt.udp)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
	udpPacketPool.Put(pkt)
}

func udpConnID(ip *packet.IPv4, udp *packet.UDP) string {
	return strings.Join([]string{
		ip.SrcIP.String(),
		fmt.Sprintf("%d", udp.SrcPort),
		ip.DstIP.String(),
		fmt.Sprintf("%d", udp.DstPort),
	}, "|")
}

func copyUDPPacket(raw []byte, ip *packet.IPv4, udp *packet.UDP) *udpPacket {
	iphdr := packet.NewIPv4()
	udphdr := packet.NewUDP()
	pkt := newUDPPacket()
	if len(udp.Payload) == 0 {
		// shallow copy headers
		// for now, we don't need deep copy if no payload
		*iphdr = *ip
		*udphdr = *udp
		pkt.ip = iphdr
		pkt.udp = udphdr
	} else {
		// get a block of buffer, make a deep copy
		buf := newBuffer()
		n := copy(buf, raw)
		pkt.mtuBuf = buf
		pkt.wire = buf[:n]
		packet.ParseIPv4(pkt.wire, iphdr)
		packet.ParseUDP(iphdr.Payload, udphdr)
		pkt.ip = iphdr
		pkt.udp = udphdr
	}
	return pkt
}

func (ut *udpConnTrack) send(data []byte) {
	ip := packet.NewIPv4()
	udp := packet.NewUDP()

	ip.Version = 4
	ip.SrcIP = ut.remoteIP
	ip.DstIP = ut.localIP
	ip.TTL = 64
	ip.Protocol = packet.IPProtocolUDP

	udp.SrcPort = ut.remotePort
	udp.DstPort = ut.localPort
	udp.Payload = data

	pkt := newUDPPacket()
	pkt.ip = ip
	pkt.udp = udp

	buf := newBuffer()
	pkt.mtuBuf = buf

	payloadL := len(udp.Payload)
	payloadStart := MTU - payloadL
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], udp.Payload)
	}
	udpHL := 8
	udpStart := payloadStart - udpHL
	pseduoStart := udpStart - packet.IPv4_PSEUDO_LENGTH
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:udpStart], packet.IPProtocolUDP, udpHL+payloadL)
	udp.Serialize(pkt.mtuBuf[udpStart:payloadStart], pkt.mtuBuf[pseduoStart:])
	ipHL := ip.HeaderLength()
	ipStart := udpStart - ipHL
	ip.Serialize(pkt.mtuBuf[ipStart:udpStart], udpHL+payloadL)

	pkt.wire = pkt.mtuBuf[ipStart:]

	ut.tunWriteCh <- pkt
	// log.Printf("<-- [UDP][%s]", ut.id)
}

func (ut *udpConnTrack) run() {
	// connect to socks
	var e error
	for i := 0; i < 2; i++ {
		ut.socksConn, e = dialLocalSocks(ut.localSocksAddr)
		if e != nil {
			log.Printf("fail to connect SOCKS proxy: %s", e)
		} else {
			// need to finish handshake in 2 mins
			ut.socksConn.SetDeadline(time.Now().Add(time.Minute * 2))
			break
		}
	}
	if ut.socksConn == nil {
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}

	// create one UDP to recv/send packets
	socksAddr := ut.socksConn.LocalAddr().(*net.TCPAddr)
	udpBind, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   socksAddr.IP,
		Port: 0,
		Zone: socksAddr.Zone,
	})
	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}

	// socks request/reply
	_, e = gosocks.WriteSocksRequest(ut.socksConn, &gosocks.SocksRequest{
		Cmd:      gosocks.SocksCmdUDPAssociate,
		HostType: gosocks.SocksIPv4Host,
		DstHost:  "0.0.0.0",
		DstPort:  0,
	})
	if e != nil {
		log.Printf("error to send socks request: %s", e)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}
	reply, e := gosocks.ReadSocksReply(ut.socksConn)
	if e != nil {
		log.Printf("error to read socks reply: %s", e)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}
	if reply.Rep != gosocks.SocksSucceeded {
		log.Printf("socks connect request fail, retcode: %d", reply.Rep)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}
	relayAddr := gosocks.SocksAddrToNetAddr("udp", reply.BndHost, reply.BndPort).(*net.UDPAddr)

	ut.socksConn.SetDeadline(time.Time{})
	// monitor socks TCP connection
	go gosocks.ConnMonitor(ut.socksConn, ut.socksClosed)
	// read UDP packets from relay
	chRelayUDP := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(udpBind, chRelayUDP)

	for {
		t := time.NewTimer(2 * time.Minute)
		select {
		// pkt from relay
		case pkt, ok := <-chRelayUDP:
			if !ok {
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				return
			}
			if pkt.Addr.String() != relayAddr.String() {
				continue
			}
			udpReq, err := gosocks.ParseUDPRequest(pkt.Data)
			if err != nil {
				log.Printf("error to parse UDP request from relay: %s", err)
				continue
			}
			if udpReq.Frag != gosocks.SocksNoFragment {
				continue
			}
			ut.send(udpReq.Data)

		// pkt from tun
		case pkt := <-ut.socksWriteCh:
			req := &gosocks.UDPRequest{
				Frag:     0,
				HostType: gosocks.SocksIPv4Host,
				DstHost:  pkt.ip.DstIP.String(),
				DstPort:  uint16(pkt.udp.DstPort),
				Data:     pkt.udp.Payload,
			}
			datagram := gosocks.PackUDPRequest(req)
			_, err := udpBind.WriteToUDP(datagram, relayAddr)
			releaseUDPPacket(pkt)
			if err != nil {
				log.Printf("error to send UDP packet to relay: %s", err)
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				return
			}

		case <-ut.socksClosed:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			return

		case <-t.C:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			return

		case <-ut.quitByOther:
			ut.socksConn.Close()
			udpBind.Close()
			return
		}
		t.Stop()
	}
}

func (ut *udpConnTrack) newPacket(pkt *udpPacket) {
	select {
	case <-ut.quitByOther:
	case <-ut.quitBySelf:
	case ut.socksWriteCh <- pkt:
		// log.Printf("--> [UDP][%s]", ut.id)
	}
}

func (t2s *Tun2Socks) clearUDPConnTrack(id string) {
	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()

	delete(t2s.udpConnTrackMap, id)
	log.Printf("tracking %d UDP connections", len(t2s.udpConnTrackMap))
}

func (t2s *Tun2Socks) getUDPConnTrack(id string, ip *packet.IPv4, udp *packet.UDP) *udpConnTrack {
	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()

	track := t2s.udpConnTrackMap[id]
	if track != nil {
		return track
	} else {
		track := &udpConnTrack{
			t2s:          t2s,
			id:           id,
			tunWriteCh:   t2s.writeCh,
			socksWriteCh: make(chan *udpPacket, 100),
			socksClosed:  make(chan bool),
			quitBySelf:   make(chan bool),
			quitByOther:  make(chan bool),

			localPort:  udp.SrcPort,
			remotePort: udp.DstPort,

			localSocksAddr: t2s.localSocksAddr,
		}
		track.localIP = make(net.IP, len(ip.SrcIP))
		copy(track.localIP, ip.SrcIP)
		track.remoteIP = make(net.IP, len(ip.DstIP))
		copy(track.remoteIP, ip.DstIP)

		t2s.udpConnTrackMap[id] = track
		go track.run()
		log.Printf("tracking %d UDP connections", len(t2s.udpConnTrackMap))
		return track
	}
}

func (t2s *Tun2Socks) udp(raw []byte, ip *packet.IPv4, udp *packet.UDP) {
	connID := udpConnID(ip, udp)
	pkt := copyUDPPacket(raw, ip, udp)
	track := t2s.getUDPConnTrack(connID, ip, udp)
	track.newPacket(pkt)
}
