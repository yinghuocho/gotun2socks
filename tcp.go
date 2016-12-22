package gotun2socks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yinghuocho/gosocks"
	"github.com/yinghuocho/gotun2socks/internal/packet"
)

type tcpPacket struct {
	ip     *packet.IPv4
	tcp    *packet.TCP
	mtuBuf []byte
	wire   []byte
}

type tcpState byte

const (
	// simplified server-side tcp states
	CLOSED      tcpState = 0x0
	SYN_RCVD    tcpState = 0x1
	ESTABLISHED tcpState = 0x2
	FIN_WAIT_1  tcpState = 0x3
	FIN_WAIT_2  tcpState = 0x4
	CLOSING     tcpState = 0x5
	LAST_ACK    tcpState = 0x6
	TIME_WAIT   tcpState = 0x7

	MAX_RECV_WINDOW int = 65535
	MAX_SEND_WINDOW int = 65535
)

type tcpConnTrack struct {
	t2s *Tun2Socks
	id  string

	input        chan *tcpPacket
	toTunCh      chan<- interface{}
	fromSocksCh  chan []byte
	toSocksCh    chan *tcpPacket
	socksCloseCh chan bool
	quitBySelf   chan bool
	quitByOther  chan bool

	localSocksAddr string
	socksConn      *gosocks.SocksConn

	// tcp context
	state tcpState
	// sequence I should use to send next segment
	// also as ack I expect in next received segment
	nxtSeq uint32
	// sequence I want in next received segment
	rcvNxtSeq uint32
	// what I have acked
	lastAck uint32

	// flow control
	recvWindow  int32
	sendWindow  int32
	sendWndCond *sync.Cond
	// recvWndCond *sync.Cond

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

var (
	tcpPacketPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &tcpPacket{}
		},
	}
)

func tcpflagsString(tcp *packet.TCP) string {
	s := []string{}
	if tcp.SYN {
		s = append(s, "SYN")
	}
	if tcp.RST {
		s = append(s, "RST")
	}
	if tcp.FIN {
		s = append(s, "FIN")
	}
	if tcp.ACK {
		s = append(s, "ACK")
	}
	if tcp.PSH {
		s = append(s, "PSH")
	}
	if tcp.URG {
		s = append(s, "URG")
	}
	if tcp.ECE {
		s = append(s, "ECE")
	}
	if tcp.CWR {
		s = append(s, "CWR")
	}
	return strings.Join(s, ",")
}

func tcpstateString(state tcpState) string {
	switch state {
	case CLOSED:
		return "CLOSED"
	case SYN_RCVD:
		return "SYN_RCVD"
	case ESTABLISHED:
		return "ESTABLISHED"
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case FIN_WAIT_2:
		return "FIN_WAIT_2"
	case CLOSING:
		return "CLOSING"
	case LAST_ACK:
		return "LAST_ACK"
	case TIME_WAIT:
		return "TIME_WAIT"
	}
	return ""
}

func newTCPPacket() *tcpPacket {
	return tcpPacketPool.Get().(*tcpPacket)
}

func releaseTCPPacket(pkt *tcpPacket) {
	packet.ReleaseIPv4(pkt.ip)
	packet.ReleaseTCP(pkt.tcp)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
	tcpPacketPool.Put(pkt)
}

func copyTCPPacket(raw []byte, ip *packet.IPv4, tcp *packet.TCP) *tcpPacket {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()
	pkt := newTCPPacket()

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
	packet.ParseTCP(iphdr.Payload, tcphdr)
	pkt.ip = iphdr
	pkt.tcp = tcphdr

	return pkt
}

func tcpConnID(ip *packet.IPv4, tcp *packet.TCP) string {
	return strings.Join([]string{
		ip.SrcIP.String(),
		fmt.Sprintf("%d", tcp.SrcPort),
		ip.DstIP.String(),
		fmt.Sprintf("%d", tcp.DstPort),
	}, "|")
}

func packTCP(ip *packet.IPv4, tcp *packet.TCP) *tcpPacket {
	pkt := newTCPPacket()
	pkt.ip = ip
	pkt.tcp = tcp

	buf := newBuffer()
	pkt.mtuBuf = buf

	payloadL := len(tcp.Payload)
	payloadStart := MTU - payloadL
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], tcp.Payload)
	}
	tcpHL := tcp.HeaderLength()
	tcpStart := payloadStart - tcpHL
	pseduoStart := tcpStart - packet.IPv4_PSEUDO_LENGTH
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:tcpStart], packet.IPProtocolTCP, tcpHL+payloadL)
	tcp.Serialize(pkt.mtuBuf[tcpStart:payloadStart], pkt.mtuBuf[pseduoStart:])
	ipHL := ip.HeaderLength()
	ipStart := tcpStart - ipHL
	ip.Serialize(pkt.mtuBuf[ipStart:tcpStart], tcpHL+payloadL)
	pkt.wire = pkt.mtuBuf[ipStart:]
	return pkt
}

func rst(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, seq uint32, ack uint32, payloadLen uint32) *tcpPacket {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.DstIP = srcIP
	iphdr.SrcIP = dstIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.DstPort = srcPort
	tcphdr.SrcPort = dstPort
	tcphdr.Window = uint16(MAX_RECV_WINDOW)
	tcphdr.RST = true
	tcphdr.ACK = true
	tcphdr.Seq = 0

	// RFC 793:
	// "If the incoming segment has an ACK field, the reset takes its sequence
	// number from the ACK field of the segment, otherwise the reset has
	// sequence number zero and the ACK field is set to the sum of the sequence
	// number and segment length of the incoming segment. The connection remains
	// in the CLOSED state."
	tcphdr.Ack = seq + payloadLen
	if tcphdr.Ack == seq {
		tcphdr.Ack += 1
	}
	if ack != 0 {
		tcphdr.Seq = ack
	}
	return packTCP(iphdr, tcphdr)
}

func rstByPacket(pkt *tcpPacket) *tcpPacket {
	return rst(pkt.ip.SrcIP, pkt.ip.DstIP, pkt.tcp.SrcPort, pkt.tcp.DstPort, pkt.tcp.Seq, pkt.tcp.Ack, uint32(len(pkt.tcp.Payload)))
}

func (tt *tcpConnTrack) changeState(nxt tcpState) {
	// log.Printf("### [%s -> %s]", tcpstateString(tt.state), tcpstateString(nxt))
	tt.state = nxt
}

func (tt *tcpConnTrack) validAck(pkt *tcpPacket) bool {
	ret := (pkt.tcp.Ack == tt.nxtSeq)
	if !ret {
		// log.Printf("WARNING: invalid ack: recvd: %d, expecting: %d", pkt.tcp.Ack, tt.nxtSeq)
	}
	return ret
}

func (tt *tcpConnTrack) validSeq(pkt *tcpPacket) bool {
	ret := (pkt.tcp.Seq == tt.rcvNxtSeq)
	if !ret {
		// log.Printf("WARNING: invalid seq: recvd: %d, expecting: %d", pkt.tcp.Seq, tt.rcvNxtSeq)
		// if (tt.rcvNxtSeq - pkt.tcp.Seq) == 1 && tt.state == ESTABLISHED {
		// 	log.Printf("(probably a keep-alive message)")
		// }
	}
	return ret
}

func (tt *tcpConnTrack) relayPayload(pkt *tcpPacket) bool {
	payloadLen := uint32(len(pkt.tcp.Payload))
	select {
	case tt.toSocksCh <- pkt:
		tt.rcvNxtSeq += payloadLen

		// reduce window when recved
		wnd := atomic.LoadInt32(&tt.recvWindow)
		wnd -= int32(payloadLen)
		if wnd < 0 {
			wnd = 0
		}
		atomic.StoreInt32(&tt.recvWindow, wnd)

		return true
	case <-tt.socksCloseCh:
		return false
	}
}

func (tt *tcpConnTrack) send(pkt *tcpPacket) {
	// log.Printf("<-- [TCP][%s][%s][seq:%d][ack:%d][payload:%d]", tt.id, tcpflagsString(pkt.tcp), pkt.tcp.Seq, pkt.tcp.Ack, len(pkt.tcp.Payload))
	if pkt.tcp.ACK {
		tt.lastAck = pkt.tcp.Ack
	}
	tt.toTunCh <- pkt
}

func (tt *tcpConnTrack) synAck(syn *tcpPacket) {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.SYN = true
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	tcphdr.Options = []packet.TCPOption{{2, 4, []byte{0x5, 0xb4}}}

	synAck := packTCP(iphdr, tcphdr)
	tt.send(synAck)
	// SYN counts 1 seq
	tt.nxtSeq += 1
}

func (tt *tcpConnTrack) finAck() {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.FIN = true
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	finAck := packTCP(iphdr, tcphdr)
	tt.send(finAck)
	// FIN counts 1 seq
	tt.nxtSeq += 1
}

func (tt *tcpConnTrack) ack() {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	ack := packTCP(iphdr, tcphdr)
	tt.send(ack)
}

func (tt *tcpConnTrack) payload(data []byte) {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.ACK = true
	tcphdr.PSH = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq
	tcphdr.Payload = data

	pkt := packTCP(iphdr, tcphdr)
	tt.send(pkt)
	// adjust seq
	tt.nxtSeq = tt.nxtSeq + uint32(len(data))
}

// stateClosed receives a SYN packet, tries to connect the socks proxy, gives a
// SYN/ACK if success, otherwise RST
func (tt *tcpConnTrack) stateClosed(syn *tcpPacket) (continu bool, release bool) {
	var e error
	for i := 0; i < 2; i++ {
		tt.socksConn, e = dialLocalSocks(tt.localSocksAddr)
		if e != nil {
			log.Printf("fail to connect SOCKS proxy: %s", e)
		} else {
			// no timeout
			tt.socksConn.SetDeadline(time.Time{})
			break
		}
	}
	if tt.socksConn == nil {
		resp := rstByPacket(syn)
		tt.toTunCh <- resp.wire
		// log.Printf("<-- [TCP][%s][RST]", tt.id)
		return false, true
	}
	// context variables
	tt.rcvNxtSeq = syn.tcp.Seq + 1
	tt.nxtSeq = 1

	tt.synAck(syn)
	tt.changeState(SYN_RCVD)
	return true, true
}

func (tt *tcpConnTrack) tcpSocks2Tun(dstIP net.IP, dstPort uint16, conn net.Conn, readCh chan<- []byte, writeCh <-chan *tcpPacket, closeCh chan bool) {
	_, e := gosocks.WriteSocksRequest(conn, &gosocks.SocksRequest{
		Cmd:      gosocks.SocksCmdConnect,
		HostType: gosocks.SocksIPv4Host,
		DstHost:  dstIP.String(),
		DstPort:  dstPort,
	})
	if e != nil {
		log.Printf("error to send socks request: %s", e)
		conn.Close()
		close(closeCh)
		return
	}
	reply, e := gosocks.ReadSocksReply(conn)
	if e != nil {
		log.Printf("error to read socks reply: %s", e)
		conn.Close()
		close(closeCh)
		return
	}
	if reply.Rep != gosocks.SocksSucceeded {
		log.Printf("socks connect request fail, retcode: %d", reply.Rep)
		conn.Close()
		close(closeCh)
		return
	}
	// writer
	go func() {
	loop:
		for {
			select {
			case <-closeCh:
				break loop
			case pkt := <-writeCh:
				conn.Write(pkt.tcp.Payload)

				// increase window when processed
				wnd := atomic.LoadInt32(&tt.recvWindow)
				wnd += int32(len(pkt.tcp.Payload))
				if wnd > int32(MAX_RECV_WINDOW) {
					wnd = int32(MAX_RECV_WINDOW)
				}
				atomic.StoreInt32(&tt.recvWindow, wnd)

				releaseTCPPacket(pkt)
			}
		}
	}()

	// reader
	for {
		var buf [MTU - 40]byte

		// tt.sendWndCond.L.Lock()
		var wnd int32
		var cur int32
		wnd = atomic.LoadInt32(&tt.sendWindow)

		if wnd <= 0 {
			for wnd <= 0 {
				tt.sendWndCond.L.Lock()
				tt.sendWndCond.Wait()
				wnd = atomic.LoadInt32(&tt.sendWindow)
			}
			tt.sendWndCond.L.Unlock()
		}

		cur = wnd
		if cur > MTU-40 {
			cur = MTU - 40
		}
		// tt.sendWndCond.L.Unlock()

		n, e := conn.Read(buf[:cur])
		if e != nil {
			log.Printf("error to read from socks: %s", e)
			conn.Close()
			break
		} else {
			b := make([]byte, n)
			copy(b, buf[:n])
			readCh <- b

			// tt.sendWndCond.L.Lock()
			nxt := wnd - int32(n)
			if nxt < 0 {
				nxt = 0
			}
			// if sendWindow does not equal to wnd, it is already updated by a
			// received pkt from TUN
			atomic.CompareAndSwapInt32(&tt.sendWindow, wnd, nxt)
			// tt.sendWndCond.L.Unlock()
		}
	}
	close(closeCh)
}

// stateSynRcvd expects a ACK with matching ack number,
func (tt *tcpConnTrack) stateSynRcvd(pkt *tcpPacket) (continu bool, release bool) {
	// rst to packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		if !pkt.tcp.RST {
			resp := rstByPacket(pkt)
			tt.toTunCh <- resp
			// log.Printf("<-- [TCP][%s][RST] continue", tt.id)
		}
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	continu = true
	release = true
	tt.changeState(ESTABLISHED)
	go tt.tcpSocks2Tun(tt.remoteIP, uint16(tt.remotePort), tt.socksConn, tt.fromSocksCh, tt.toSocksCh, tt.socksCloseCh)
	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			// pkt hands to socks writer
			release = false
		}
	}
	return
}

func (tt *tcpConnTrack) stateEstablished(pkt *tcpPacket) (continu bool, release bool) {
	// ack if sequence is not expected
	if !tt.validSeq(pkt) {
		tt.ack()
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	continu = true
	release = true
	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			// pkt hands to socks writer
			release = false
		}
	}
	if pkt.tcp.FIN {
		tt.rcvNxtSeq += 1
		tt.finAck()
		tt.changeState(LAST_ACK)
		tt.socksConn.Close()
	}
	return
}

func (tt *tcpConnTrack) stateFinWait1(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence, state unchanged
	if !tt.validSeq(pkt) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	if pkt.tcp.FIN {
		tt.rcvNxtSeq += 1
		tt.ack()
		if pkt.tcp.ACK && tt.validAck(pkt) {
			tt.changeState(TIME_WAIT)
			return false, true
		} else {
			tt.changeState(CLOSING)
			return true, true
		}
	} else {
		tt.changeState(FIN_WAIT_2)
		return true, true
	}
}

func (tt *tcpConnTrack) stateFinWait2(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-FIN non-ACK packets
	if !pkt.tcp.ACK || !pkt.tcp.FIN {
		return true, true
	}
	tt.rcvNxtSeq += 1
	tt.ack()
	tt.changeState(TIME_WAIT)
	return false, true
}

func (tt *tcpConnTrack) stateClosing(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	tt.changeState(TIME_WAIT)
	return false, true
}

func (tt *tcpConnTrack) stateLastAck(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	// connection ends
	tt.changeState(CLOSED)
	return false, true
}

func (tt *tcpConnTrack) newPacket(pkt *tcpPacket) {
	select {
	case <-tt.quitByOther:
	case <-tt.quitBySelf:
	case tt.input <- pkt:
	}
}

func (tt *tcpConnTrack) updateSendWindow(pkt *tcpPacket) {
	// tt.sendWndCond.L.Lock()
	atomic.StoreInt32(&tt.sendWindow, int32(pkt.tcp.Window))
	tt.sendWndCond.Signal()
	// tt.sendWndCond.L.Unlock()
}

func (tt *tcpConnTrack) run() {
	for {
		var ackTimer *time.Timer
		var timeout *time.Timer = time.NewTimer(5 * time.Minute)

		var ackTimeout <-chan time.Time
		var socksCloseCh chan bool
		var fromSocksCh chan []byte
		// enable some channels only when the state is ESTABLISHED
		if tt.state == ESTABLISHED {
			socksCloseCh = tt.socksCloseCh
			fromSocksCh = tt.fromSocksCh
			ackTimer = time.NewTimer(10 * time.Millisecond)
			ackTimeout = ackTimer.C
		}

		select {
		case pkt := <-tt.input:
			// log.Printf("--> [TCP][%s][%s][%s][seq:%d][ack:%d][payload:%d]", tt.id, tcpstateString(tt.state), tcpflagsString(pkt.tcp), pkt.tcp.Seq, pkt.tcp.Ack, len(pkt.tcp.Payload))
			var continu, release bool

			tt.updateSendWindow(pkt)
			switch tt.state {
			case CLOSED:
				continu, release = tt.stateClosed(pkt)
			case SYN_RCVD:
				continu, release = tt.stateSynRcvd(pkt)
			case ESTABLISHED:
				continu, release = tt.stateEstablished(pkt)
			case FIN_WAIT_1:
				continu, release = tt.stateFinWait1(pkt)
			case FIN_WAIT_2:
				continu, release = tt.stateFinWait2(pkt)
			case CLOSING:
				continu, release = tt.stateClosing(pkt)
			case LAST_ACK:
				continu, release = tt.stateLastAck(pkt)
			}
			if release {
				releaseTCPPacket(pkt)
			}
			if !continu {
				if tt.socksConn != nil {
					tt.socksConn.Close()
				}
				close(tt.quitBySelf)
				tt.t2s.clearTCPConnTrack(tt.id)
				return
			}

		case <-ackTimeout:
			if tt.lastAck < tt.rcvNxtSeq {
				// have something to ack
				tt.ack()
			}

		case data := <-fromSocksCh:
			tt.payload(data)

		case <-socksCloseCh:
			tt.finAck()
			tt.changeState(FIN_WAIT_1)

		case <-timeout.C:
			if tt.socksConn != nil {
				tt.socksConn.Close()
			}
			close(tt.quitBySelf)
			tt.t2s.clearTCPConnTrack(tt.id)
			return

		case <-tt.quitByOther:
			// who closes this channel should be responsible to clear track map
			log.Printf("tcpConnTrack quitByOther")
			if tt.socksConn != nil {
				tt.socksConn.Close()
			}
			return
		}
		timeout.Stop()
		if ackTimer != nil {
			ackTimer.Stop()
		}
	}
}

func (t2s *Tun2Socks) createTCPConnTrack(id string, ip *packet.IPv4, tcp *packet.TCP) *tcpConnTrack {
	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()

	track := &tcpConnTrack{
		t2s:          t2s,
		id:           id,
		toTunCh:      t2s.writeCh,
		input:        make(chan *tcpPacket, 10000),
		fromSocksCh:  make(chan []byte, 100),
		toSocksCh:    make(chan *tcpPacket, 100),
		socksCloseCh: make(chan bool),
		quitBySelf:   make(chan bool),
		quitByOther:  make(chan bool),

		sendWindow:  int32(MAX_SEND_WINDOW),
		recvWindow:  int32(MAX_RECV_WINDOW),
		sendWndCond: &sync.Cond{L: &sync.Mutex{}},

		localPort:      tcp.SrcPort,
		remotePort:     tcp.DstPort,
		localSocksAddr: t2s.localSocksAddr,
		state:          CLOSED,
	}
	track.localIP = make(net.IP, len(ip.SrcIP))
	copy(track.localIP, ip.SrcIP)
	track.remoteIP = make(net.IP, len(ip.DstIP))
	copy(track.remoteIP, ip.DstIP)

	t2s.tcpConnTrackMap[id] = track
	go track.run()
	log.Printf("tracking %d TCP connections", len(t2s.tcpConnTrackMap))
	return track
}

func (t2s *Tun2Socks) getTCPConnTrack(id string) *tcpConnTrack {
	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()

	return t2s.tcpConnTrackMap[id]
}

func (t2s *Tun2Socks) clearTCPConnTrack(id string) {
	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()

	delete(t2s.tcpConnTrackMap, id)
	log.Printf("tracking %d TCP connections", len(t2s.tcpConnTrackMap))
}

func (t2s *Tun2Socks) tcp(raw []byte, ip *packet.IPv4, tcp *packet.TCP) {
	connID := tcpConnID(ip, tcp)
	track := t2s.getTCPConnTrack(connID)
	if track != nil {
		pkt := copyTCPPacket(raw, ip, tcp)
		track.newPacket(pkt)
	} else {
		// ignore RST, if there is no track of this connection
		if tcp.RST {
			// log.Printf("--> [TCP][%s][%s]", connID, tcpflagsString(tcp))
			return
		}
		// return a RST to non-SYN packet
		if !tcp.SYN {
			// log.Printf("--> [TCP][%s][%s]", connID, tcpflagsString(tcp))
			resp := rst(ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, uint32(len(tcp.Payload)))
			t2s.writeCh <- resp
			// log.Printf("<-- [TCP][%s][RST]", connID)
			return
		}
		pkt := copyTCPPacket(raw, ip, tcp)
		track := t2s.createTCPConnTrack(connID, ip, tcp)
		track.newPacket(pkt)
	}
}
