// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
	"time"

	cryptoprotect "bingoproxy/cryptoProtect"
	"bingoproxy/utils"
)

/*
udp + **trusted** transmission
TODO: validate on real machine and see whether this protocol is able to bypass ISP QoS

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

                            +----> I think the possibility of lossing all sending windows is impossible
		          4 bytes   |   d c
	         4 bytes        |   0 1                     0-1023 s 10 bits 1000*1000
	         n    n         |    b b b b b b b b        0-1023ms 10 bits 1000
	         _u    u     uint64  i i i i i i i i        0-1023us 10 bits => (0, 0x3D095DD7) us => (u)int32
	         _ m    m    8 bytes t t t t t t t t
	  4 bytes_  b    b   ?                           4bytes 3 byte
	+--------+----+----+--------+-+-+-+-+-+-+-+-+ -+-+----+-----+
	|assigned|S   |A   |current |t|a|r|r|s|f|p|-| -|-|Prom|seed4|
	|        |  E |  C | group  |y|c|c|s|y|i|m|-| -|-|ise-|obsc-|
	|uniqueID|   Q|   K|recv-num|p|k|k|t|n|n|s|-| -|-|time|uring|
	+--------+----+----+--------+-+-+-+-+-+-+-+-+ -+-+----+-----+

TODO: define the maximum time and ensure the adequate bit for representation.
Eg. 1 min 30 s ==> 90 s, 600 ms,

    30 s 65 ms 74 us => 30_000_000_000 => 30 s imprecise and hard to determine the MITM.
                            65_000_000 => 30065 ms > 65535

Assume the sec domain can not exccedd 5 sec.
    5 s 65 ms 74 us  => 5_000_000_000 => 5 s imprecise and hard to determine the MITM.
	                       65_000_000 => 5065 ms
                               74_000 => 5065074 us, still too big

This preamble can ought to be compressed after a successfully handshake.

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
		Addr        net.Addr
		Quidx       uint32
		seq_st      uint32
		seq_ofs     uint32
		ack_st      uint32
		ack_ofs     uint32
		Ifshakehand byte
		// I think the info of control domain need to change all the time
		// so that no one can easily launch an attack.
		Xor_key [3]byte

		Ref_time      uint32
		Ref_time_unit uint8

		RecvBuf *[]byte
		SendBuf *[]byte
	}

	// as listener?
	TDP struct {
		GlobalConn    net.UDPConn
		GlobalShunter int

		sucideSign      bool
		lock4sucideSign sync.RWMutex

		halfSync_lock    sync.RWMutex
		handshake_cnt    int
		established_lock sync.RWMutex
		setup_cnt        int

		priority_inverse map[uint32]uint32
		halfsync_inverse map[uint32]uint32
		halfsync_queue   *[]TDPconn // incoming flow asking for service
		accept_queue     *[]TDPconn // flow that are queueing for interacting with application
	}
)

const (
	_typ            header_bit_domain = 128
	_ack            header_bit_domain = 64
	_rck            header_bit_domain = 32
	_rst            header_bit_domain = 16
	_syn            header_bit_domain = 8
	_fin            header_bit_domain = 4
	_pms            header_bit_domain = 2
	GroupSize       int               = 64
	AcceptQueueSize int               = 1024
	RECV_ALL        uint64            = ^uint64(0)
)

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

func (tdp *TDP) Accept() {
}

func (tdp *TDP) Close() {
	curr := tdp.SafeReadSucideSign()
	if curr {
		tdp.SafeFlipSucideSign()
	}
	// TODO: free sources.
}

func (tdp *TDP) Addr() {
}

// read the sucide sign of udp listener
func (tdp *TDP) SafeReadSucideSign() bool {
	tdp.lock4sucideSign.RLock()
	defer tdp.lock4sucideSign.RUnlock()
	res := tdp.sucideSign
	return res
}

// flip the sucide sign of udp listener
func (tdp *TDP) SafeFlipSucideSign() {
	tdp.lock4sucideSign.Lock()
	defer tdp.lock4sucideSign.Unlock()
	tdp.sucideSign = !tdp.sucideSign
}

// init the sucide sign of udp listener
func (tdp *TDP) initSucideSign() {
	tdp.lock4sucideSign.Lock()
	defer tdp.lock4sucideSign.Unlock()
	tdp.sucideSign = true
}

func (tdp *TDP) fastResend(idx uint32, status [8]byte) {
	functor := func(counter uint32, now byte) {
		var i uint32
		for i = 0; i < 8; i++ {
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

func (tdp *TDP) semantemeInCtrlDomain(id uint32, surpass_ack [8]byte, bits header_bit_domain) (bool, string) {
	switch bits {
	case _ack:
		tdp.fastResend(tdp.priority_inverse[id], surpass_ack)
		return true, "data"
	case _typ | _rst:
		// remove packet from all queue
		return true, "reset"
	case _typ | _fin:
		// actively disconnect with counterpart.
		return true, "finish-1"
	case _typ | _fin | _ack:
		// response from counterpart.
		return true, "finish-2"
	default:
		// drop invalid packet or determine whether removing the conn.
		return false, ""
	}
}

func (tdp *TDP) ParseConn(addr net.Addr, msg []byte) (bool, string) {
	if len(msg) < 4+4+4+8+1 {
		return false, ""
	}

	var (
		extented_algebra = func(inp [3]byte, oup []byte) {
			for i := 0; i < 3; i++ {
				oup[i] = inp[i]
			}
			for i := 3; i < 17; i++ {
				oup[i] = ((oup[i-1] << 1) + (^oup[i-3] << 5) + cryptoprotect.S_Box[oup[i-2]]) & 0xFF
			}
			for i := 0; i < 3; i++ {
				inp[i] = oup[16-i]
			}
		}
		xorer_with_limit = func(inp, oup []byte, l, r int) {
			for i := l; i < r; i++ {
				oup[i] ^= inp[i-4]
			}
		}
	)
	__seq, __ack := [4]byte(msg[4:8]), [4]byte(msg[8:12])
	id := utils.BytesToUint32([4]byte(msg[:4]))
	_ctrl_bits := header_bit_domain(msg[20])

	val, ok := tdp.priority_inverse[id]
	if ok {
		/* has been in accept_queue. So the control domain has been sealed. */
		_curr_num := [8]byte(msg[12:20])

		session_key := (*tdp.accept_queue)[val].Xor_key
		_17_exkey := make([]byte, 17)
		extented_algebra(session_key, _17_exkey)
		xorer_with_limit(_17_exkey, __seq[:], 4, 8)
		xorer_with_limit(_17_exkey, __ack[:], 8, 12)
		xorer_with_limit(_17_exkey, _curr_num[:], 12, 20)
		(*tdp.accept_queue)[val].Xor_key = session_key

		ack := (*tdp.accept_queue)[val].ack_st + (*tdp.accept_queue)[val].ack_ofs
		seq := (*tdp.accept_queue)[val].seq_st + (*tdp.accept_queue)[val].seq_ofs

		Seq, Ack := utils.BytesToUint32(__seq), utils.BytesToUint32(__ack)
		if Seq != seq+1 || Ack != ack+1 {
			// TODO: turn this over mind
			return false, ""
		}

		flag, _type := tdp.semantemeInCtrlDomain(val, _curr_num, _ctrl_bits)
		if !flag {
			return false, ""
		}
		switch _type {
		case `reset`:
			return true, _type
		}

	}
	switch _ctrl_bits {
	case _typ | _syn | _pms:
		ping_ref, valid := PingWithoutPrint(addr.String(), 3, 5, 5)
		if !valid || len(msg) < 4+4+4+8+1+4+3 {
			// suspect: mischief
			return false, ""
		}
		promise_time := msg[21:25]
		sec := int64(promise_time[0]) | (int64(promise_time[1]&0x3) << 8)
		mil := int64(promise_time[1]>>2) | (int64(promise_time[2]&0xF) << 8)
		mic := int64(promise_time[2]>>4) | int64(promise_time[3]&0x3F)
		us := mic + mil*1000 + sec*1000000

		if utils.AbsMinusInt(us, ping_ref)*2 >= ping_ref*3 /* || us > 5sec */ {
			return false, ""
		}
		assigned_id := make([]byte, 4)
		rand.Read(assigned_id)
		curr_id := utils.BytesToUint32([4]byte(assigned_id))

		tdp.halfSync_lock.Lock()
		(*tdp.halfsync_queue)[tdp.handshake_cnt].Ref_time = uint32(ping_ref)
		tdp.halfsync_inverse[curr_id] = uint32(tdp.handshake_cnt)
		tdp.handshake_cnt += 1
		tdp.halfSync_lock.Unlock()
		// It is the first time to flow in. check and verified the promised time and attempt to allocate.
		// seed := msg[25:28]
		// TODO: Need to write back (ack, promiseTime, id, seed) and generate sessionKey.
		return true, "synchronous-1"
	case _typ | _ack | _syn | _pms:
		// TODO: the two parties need generate session key.
		return true, "synchronous-2"
	case _typ | _ack:
		return true, "synchronous-3"
	case _typ | _rst:
		// a new connection attempt to reset connection?
		return true, `reset`
	default:
		return false, ``
	}
}

func (tdp *TDP) Listen(udpType string, port uint16) error {
	var choice net.IP
	switch udpType {
	case "udp":
		choice = []byte{127, 0, 0, 1}
	case "udp6":
		choice = net.IPv6loopback
	}
	conn, err := net.ListenUDP(udpType, &net.UDPAddr{IP: choice, Port: int(port)})
	if err != nil {
		return err
	}
	tdp.GlobalConn = *conn
	return nil
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
		if !flag {
			// drop this.
			continue
		}
		switch _type {
		case "handshake":
			tdp.halfSync_lock.Lock()
			(*tdp.halfsync_queue)[tdp.handshake_cnt] = TDPconn{Addr: addr, Quidx: uint32(tdp.handshake_cnt)}
			tdp.handshake_cnt += 1
			tdp.halfSync_lock.Unlock()
		case "setup":
			tdp.established_lock.Lock()
			(*tdp.accept_queue)[tdp.setup_cnt] = TDPconn{Addr: addr, Quidx: uint32(tdp.setup_cnt)}
			tdp.handshake_cnt += 1
			tdp.established_lock.Unlock()
		case "data":
			// TODO
		}
	}
}

/* ---------------------------------- TDPconn -------------------------------------------- */

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
