// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"log"
	"net"
	"sync"
	"time"

	"selfproxy/utils"
)

/*
udp + **trusted** transmission

Conn is a generic stream-oriented network connection.
Multiple goroutines may invoke methods on a Conn simultaneously.

TODO: bypass ISP QoS
*/
type (
	header_bit_domain byte
	// as header.
	TDPpreamble struct {
		SEQ, ACK    uint32
		CurrWinCond uint64
		BitsDomain  byte
		PromiseTime [5]byte
	}

	// as conn entity.
	TDPconn struct {
		Quidx     uint32
		Addr      net.Addr
		seq_st    uint32
		seq_ofs   uint32
		ack_st    uint32
		ack_ofs   uint32
		shakehand uint32
		// I think the info of control domain need changing all the time
		// so that no one can easily launch an attack.
		xor_key []byte

		ref_time      uint32
		ref_time_unit uint8

		RecvBuf *[]byte
		SendBuf *[]byte
	}
	// as listener?
	TDP struct {
		GlobalConn    net.UDPConn
		GlobalShunter int

		sucideSign   bool
		protect_lock sync.RWMutex

		handshake_cnt    int
		setup_cnt        int
		priority_inverse map[net.Addr]int
		halfsync_inverse map[net.Addr]int
		halfsync_queue   *[]TDPconn // incoming flow asking for service
		accept_queue     *[]TDPconn // flow that are queueing for interacting with application
	}
)

const (
	_typ              header_bit_domain = 128
	_ack              header_bit_domain = 64
	_rst              header_bit_domain = 32
	_syn              header_bit_domain = 16
	_fin              header_bit_domain = 8
	_pms              header_bit_domain = 4
	_shield_time_mask                   = uint8(0xF8)
	_ns               header_bit_domain = 0
	_us               header_bit_domain = 1
	_ms               header_bit_domain = 2
	_sec              header_bit_domain = 3

	GroupSize       int    = 64
	AcceptQueueSize int    = 1024
	RECV_ALL        uint64 = ^uint64(0)
)

/*
The windows size or group size is intensionally fixed to 64 for simplifying
the process of adjusting windows size, congestion control and fast retransmission first defined in TCP.
And the tcp preamble will be tailored and reduced for maintaining trusted transmission.

For synchronizing flood:

	Ping-pong operation is required for measuring approximately RTT to form a promised Time windows.
	If any communication parties violates against the time windows they promised or the time windows is irrational,
	the receiver can immediately abort connection or add ip to blacklist if necessary.

For finishing scanning:

	Firewall can handle this well by ignoring. Or all the ports send rst packet.

For TCP-Land attack:

	Firewall can detect this malicious network-flow.

For interference attacked via forged packets (Eg. forged and malicious ack, rst):

	key agreement after setting up connection is cruial since key affords with the protective capability of
	obsuring and de-obsuring control domain in packet between communication parties.

	Though there may be inevitable overhead of extra consumption on memory...

				  +-----------------------> I think the possibility of lossing all sending windows is impossible
		  4 bytes |    d c
	4 bytes       |    0 1                     0-63 s   6 bits, should not more than 1 minute? since we are not communicate via starlink.
	n    n        |     b b b b b b            0-1023ms 10 bits
	_u    u    uint64   i i i i i i            0-1023us 10 bits
	_ m    m   8 bytes  t t t t t t            0-1023ns 10 bits - 2 = 8 bit
	_  b    b  ?                    5 bytes for
	+----+----+--------+-+-+-+-+-+-+----+
	|S   |A   |current |t|a|r|s|f|p|Prom|
	|  E |  C | group  |y|c|s|y|i|m|ise-| remained 1 byte and 6 bits (14 bits)
	|   Q|   K|recv-num|p|k|t|n|n|s|time|     may be we can utilize for resizing the send and recv window?
	+----+----+--------+-+-+-+-+-+-+----+	or as SessionKey seed?

TODO: define the maximum time and ensure the adequate bit for representation.
Eg. 1 min 30 s ==> 90 s, 600 ms, 999 ns

	30 s 65 ms 74 us 110 ns => 30_000_000_000 => 30065074 us, still too big
								   65_000_000 => 30065 ms > 65535
									   74_000 => 30 s imprecise and hard to determine the MITM.
									 	  110

This preamble can be compressed after successfully handshake.

		4 bytes
	4 bytes
	n     n
	_u     u   unsigned
	_ m     m  8 bytes    B Y T E
	_  b     b
	+----+----+--------+-+-+-+-+-+---+
	|S   |A   |current |t|a|r|s|f|tim|
	|  E |  C |  group |y|c|s|y|i|e-u|
	|   Q|   K|recv-num|p|k|t|n|n|nit|
	+----+----+--------+-+-+-+-+-+---+
*/
// return the bytes representation of header.
func (tdph *TDPpreamble) Bytes() []byte {
	res1 := utils.Uint32ToBytesInLittleEndian(tdph.SEQ)
	res2 := utils.Uint32ToBytesInLittleEndian(tdph.ACK)
	res3 := utils.Uint64ToBytesInLittleEndian(tdph.CurrWinCond)

	res1 = append(res1, res2...)
	res1 = append(res1, res3...)
	res1 = append(res1, tdph.BitsDomain)

	return res1
}

func (tdp *TDP) pingRequest() bool {
	/*
		tdp.ref_time = uint32(ref_time)
		tdp.ref_time_unit = byte('m') // standard form.
	*/
	return true
}

func (tdp *TDP) Accept() {
}

func (tdp *TDP) Close() {
}

func (tdp *TDP) Addr() {
}

// bizarre implementation...
func (tdp *TDP) SafeReadSucideSign() bool {
	tdp.protect_lock.RLock()
	defer tdp.protect_lock.RUnlock()
	res := tdp.sucideSign
	return res
}

func (tdp *TDP) SafeFlipSucideSign() {
	tdp.protect_lock.Lock()
	defer tdp.protect_lock.Unlock()
	tdp.sucideSign = !tdp.sucideSign
}

func (tdp *TDP) initSucideSign() {
	tdp.protect_lock.Lock()
	defer tdp.protect_lock.Unlock()
	tdp.sucideSign = true
}

func (tdp *TDP) fastResend(idx int, status [8]byte) {
	functor := func(counter int, now byte) {
		for i := 0; i < 8; i++ {
			if (now>>i)&1 == 1 {
				continue
			}
			ptr := (*tdp.accept_queue)[idx]
			tdp.GlobalConn.WriteToUDP([]byte{(*ptr.SendBuf)[counter*8+i]}, ptr.Addr.(*net.UDPAddr))
		}
	}
	for i := 0; i < 8; i++ {
		functor(idx, status[i])
	}
}

func (tdp *TDP) ParseConn(addr net.Addr, msg []byte) (bool, string) {
	val, ok := tdp.priority_inverse[addr]
	if ok {
		// has been in accept_queue. Since the control domain has been seal by
		ack := (*tdp.accept_queue)[val].ack_st + (*tdp.accept_queue)[val].ack_ofs
		seq := (*tdp.accept_queue)[val].seq_st + (*tdp.accept_queue)[val].seq_ofs
		Seq, Ack := utils.BytesToUint32([4]byte(msg[:4])), utils.BytesToUint32([4]byte(msg[4:8]))
		if Seq != seq+1 || Ack != ack {
			return false, ""
		}
	} else {
		// first come in
	}

	curr_num := msg[8:16]
	ctl_bits := header_bit_domain(msg[16])
	switch ctl_bits {
	case _typ | _syn | _pms:
	case _typ | _ack | _syn | _pms:
	case _typ | _ack:
	case _ack:
		// I am not sure...
		tdp.fastResend(tdp.priority_inverse[addr], [8]byte(curr_num))
	case _typ | _rst:
		// remove packet from all queue
	case _typ | _fin:
		//
	case _typ | _fin | _ack:
	default:
		// drop invalid packet or determine whether removing the conn.
		return false, ""
	}
	return false, ""
}

func (tdp *TDP) InflowShunter() {
	msgBuf := make([]byte, 1024)
	tdp.initSucideSign()
	for tdp.SafeReadSucideSign() {

		_, addr, err := tdp.GlobalConn.ReadFromUDP(msgBuf)
		if err != nil {
			log.Println(err)
			continue
		}
		flag, _type := tdp.ParseConn(addr, msgBuf)
		// parse and validate the msgBuf, attempt to shunt the flow after executing this decision.
		if !flag {
			// drop this.
			continue
		}
		switch _type {
		case "handshake":
			(*tdp.halfsync_queue)[tdp.handshake_cnt] = TDPconn{Addr: addr, Quidx: uint32(tdp.handshake_cnt)}
			tdp.handshake_cnt += 1
		case "setup":
			(*tdp.accept_queue)[tdp.setup_cnt] = TDPconn{Addr: addr, Quidx: uint32(tdp.setup_cnt)}
			tdp.handshake_cnt += 1
		case "data":

		default:
			continue
		}
		// TODO: tdp.accept_queue
		// tdp.halfsync_queue
		// how to shift the operation? it seems that go handle can make this.
	}
}

/* ---------------------------------- TDPconn -------------------------------------------- */
func (tdp *TDPconn) wrapHeader(domain_bit header_bit_domain) ([]byte, error) {
	var header TDPpreamble
	/*
		if tdp.shakehand == 0 {
			_tmp := [4]byte{}
			cnt, err := rand.Read(_tmp[:])
			if cnt != 4 {
				return []byte(``), err
			}
			tdp.seq_st = utils.BytesToUint32(_tmp)
			tdp.seq_ofs, tdp.ack_st, tdp.ack_ofs = 0, 0, 0
			header.PromiseTime = tdp.ref_time
		}
		header.SEQ = tdp.seq_st + tdp.seq_ofs
		header.ACK = tdp.ack_st + tdp.ack_ofs
		header.BitsDomain = byte(domain_bit)
	*/
	return header.Bytes(), nil
}

// trusted read
func (tdp *TDPconn) Read(b []byte) (n int, err error) {
	return 0, nil
}

// trusted write
func (tdp *TDPconn) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (tdp *TDPconn) Close() error {
	return nil
}

func (tdp *TDPconn) LocalAddr() net.Addr {
	return nil
}

func (tdp *TDPconn) RemoteAddr() net.Addr {
	return nil
}

func (tdp *TDPconn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (tdp *TDPconn) SetDeadline(t time.Time) error {
	return nil
}

func (tdp *TDPconn) SetReadDeadline(t time.Time) error {
	return nil
}
