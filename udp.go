package gotun2socks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

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

	toTunCh     chan<- interface{}
	quitBySelf  chan bool
	quitByOther chan bool

	fromTunCh   chan *udpPacket
	socksClosed chan bool

	localSocksAddr string
	socksConn      *gosocks.SocksConn

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

var (
	udpPacketPool = &sync.Pool{
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

	// make a deep copy
	var buf []byte
	if len(raw) <= MTU {
		buf = newBuffer()
		pkt.mtuBuf = buf
	} else {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	pkt.wire = buf[:n]
	packet.ParseIPv4(pkt.wire, iphdr)
	packet.ParseUDP(iphdr.Payload, udphdr)
	pkt.ip = iphdr
	pkt.udp = udphdr

	return pkt
}

func responsePacket(local net.IP, remote net.IP, lPort uint16, rPort uint16, respPayload []byte) (*udpPacket, []*ipPacket) {
	ipid := packet.IPID()

	ip := packet.NewIPv4()
	udp := packet.NewUDP()

	ip.Version = 4
	ip.Id = ipid
	ip.SrcIP = make(net.IP, len(remote))
	copy(ip.SrcIP, remote)
	ip.DstIP = make(net.IP, len(local))
	copy(ip.DstIP, local)
	ip.TTL = 64
	ip.Protocol = packet.IPProtocolUDP

	udp.SrcPort = rPort
	udp.DstPort = lPort
	udp.Payload = respPayload

	pkt := newUDPPacket()
	pkt.ip = ip
	pkt.udp = udp

	pkt.mtuBuf = newBuffer()
	payloadL := len(udp.Payload)
	payloadStart := MTU - payloadL
	// if payload too long, need fragment, only part of payload put to mtubuf[28:]
	if payloadL > MTU-28 {
		ip.Flags = 1
		payloadStart = 28
	}
	udpHL := 8
	udpStart := payloadStart - udpHL
	pseduoStart := udpStart - packet.IPv4_PSEUDO_LENGTH
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:udpStart], packet.IPProtocolUDP, udpHL+payloadL)
	// udp length and checksum count on full payload
	udp.Serialize(pkt.mtuBuf[udpStart:payloadStart], pkt.mtuBuf[pseduoStart:payloadStart], udp.Payload)
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], udp.Payload)
	}
	ipHL := ip.HeaderLength()
	ipStart := udpStart - ipHL
	// ip length and checksum count on actual transmitting payload
	ip.Serialize(pkt.mtuBuf[ipStart:udpStart], udpHL+(MTU-payloadStart))
	pkt.wire = pkt.mtuBuf[ipStart:]

	if ip.Flags == 0 {
		return pkt, nil
	}
	// generate fragments
	frags := genFragments(ip, (MTU-20)/8, respPayload[MTU-28:])
	return pkt, frags
}

func (ut *udpConnTrack) send(data []byte) {
	pkt, fragments := responsePacket(ut.localIP, ut.remoteIP, ut.localPort, ut.remotePort, data)
	ut.toTunCh <- pkt
	if fragments != nil {
		for _, frag := range fragments {
			ut.toTunCh <- frag
		}
	}
}

func (ut *udpConnTrack) run() {
	// connect to socks
	var e error
	for i := 0; i < 2; i++ {
		ut.socksConn, e = dialLocalSocks(ut.localSocksAddr)
		if e != nil {
			log.Printf("fail to connect SOCKS proxy: %s", e)
		} else {
			// need to finish handshake in 1 mins
			ut.socksConn.SetDeadline(time.Now().Add(time.Minute * 1))
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
	quitUDP := make(chan bool)
	chRelayUDP := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(udpBind, chRelayUDP, quitUDP)

	start := time.Now()
	for {
		var t *time.Timer
		if ut.t2s.isDNS(ut.remoteIP.String(), ut.remotePort) {
			t = time.NewTimer(10 * time.Second)
		} else {
			t = time.NewTimer(2 * time.Minute)
		}
		select {
		// pkt from relay
		case pkt, ok := <-chRelayUDP:
			if !ok {
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				close(quitUDP)
				return
			}
			if pkt.Addr.String() != relayAddr.String() {
				log.Printf("response relayed from %s, expect %s", pkt.Addr.String(), relayAddr.String())
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
			if ut.t2s.isDNS(ut.remoteIP.String(), ut.remotePort) {
				// DNS-without-fragment only has one request-response
				end := time.Now()
				ms := end.Sub(start).Nanoseconds() / 1000000
				log.Printf("DNS session response received: %d ms", ms)
				if ut.t2s.cache != nil {
					ut.t2s.cache.store(udpReq.Data)
				}
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				close(quitUDP)
				return
			}

		// pkt from tun
		case pkt := <-ut.fromTunCh:
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
				close(quitUDP)
				return
			}

		case <-ut.socksClosed:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			close(quitUDP)
			return

		case <-t.C:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			close(quitUDP)
			return

		case <-ut.quitByOther:
			log.Printf("udpConnTrack quitByOther")
			ut.socksConn.Close()
			udpBind.Close()
			close(quitUDP)
			return
		}
		t.Stop()
	}
}

func (ut *udpConnTrack) newPacket(pkt *udpPacket) {
	select {
	case <-ut.quitByOther:
	case <-ut.quitBySelf:
	case ut.fromTunCh <- pkt:
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
			t2s:         t2s,
			id:          id,
			toTunCh:     t2s.writeCh,
			fromTunCh:   make(chan *udpPacket, 100),
			socksClosed: make(chan bool),
			quitBySelf:  make(chan bool),
			quitByOther: make(chan bool),

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
	var buf [1024]byte
	var done bool

	// first look at dns cache
	if t2s.cache != nil && t2s.isDNS(ip.DstIP.String(), udp.DstPort) {
		answer := t2s.cache.query(udp.Payload)
		if answer != nil {
			data, e := answer.PackBuffer(buf[:])
			if e == nil {
				resp, fragments := responsePacket(ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort, data)
				go func(first *udpPacket, frags []*ipPacket) {
					t2s.writeCh <- first
					if frags != nil {
						for _, frag := range frags {
							t2s.writeCh <- frag
						}
					}
				}(resp, fragments)
				done = true
			}
		}
	}

	// then open a udpConnTrack to forward
	if !done {
		connID := udpConnID(ip, udp)
		pkt := copyUDPPacket(raw, ip, udp)
		track := t2s.getUDPConnTrack(connID, ip, udp)
		track.newPacket(pkt)
	}
}

type dnsCacheEntry struct {
	msg *dns.Msg
	exp time.Time
}

type dnsCache struct {
	servers []string
	mutex   sync.Mutex
	storage map[string]*dnsCacheEntry
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }

func cacheKey(q dns.Question) string {
	return string(append([]byte(q.Name), packUint16(q.Qtype)...))
}

func (t2s *Tun2Socks) isDNS(remoteIP string, remotePort uint16) bool {
	if remotePort != 53 {
		return false
	}
	for _, s := range t2s.dnsServers {
		if s == remoteIP {
			return true
		}
	}
	return false
}

func (c *dnsCache) query(payload []byte) *dns.Msg {
	request := new(dns.Msg)
	e := request.Unpack(payload)
	if e != nil {
		return nil
	}
	if len(request.Question) == 0 {
		return nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := cacheKey(request.Question[0])
	entry := c.storage[key]
	if entry == nil {
		return nil
	}
	if time.Now().After(entry.exp) {
		delete(c.storage, key)
		return nil
	}
	entry.msg.Id = request.Id
	return entry.msg
}

func (c *dnsCache) store(payload []byte) {
	resp := new(dns.Msg)
	e := resp.Unpack(payload)
	if e != nil {
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		return
	}
	if len(resp.Question) == 0 || len(resp.Answer) == 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := cacheKey(resp.Question[0])
	log.Printf("cache DNS response for %s", key)
	c.storage[key] = &dnsCacheEntry{
		msg: resp,
		exp: time.Now().Add(time.Duration(resp.Answer[0].Header().Ttl) * time.Second),
	}
}
