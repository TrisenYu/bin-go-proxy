// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utils "bingoproxy/utils"
)

/*
udp + **trusted** transmission
TODO:
	write a concrete and specific unit test and validate on real machine and see whether this protocol is able to bypass ISP QoS


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
     2B   4 bytes_  b    b   ?                           4bytes 3 byte
    +---+--------+----+----+--------+-+-+-+-+-+-+-+-+ -+-+----+-----+
    |L  |assigned|S   |A   |current |t|a|r|r|s|f|p|-| -|-|Prom|seed4|
    | E |        |  E |  C | group  |y|c|c|s|y|i|m|-| -|-|ise-|obsc-|
    |  N|uniqueID|   Q|   K|recv-num|p|k|k|t|n|n|s|-| -|-|time|uring|
    +---+--------+----+----+--------+-+-+-+-+-+-+-+-+ -+-+----+-----+

	 2 + 4 + 4 + 4 + 8 + 1 + 4 + 3 = 30
Eg. 1 min 30 s ==> 90 s, 600 ms,

    30 s 65 ms 74 us => 30_000_000_000 => 30 s imprecise and hard to determine the MITM.
                            65_000_000 => 30065 ms > 65535

Assume the sec domain can not exccedd 5 sec.
    5 s 65 ms 74 us  => 5_000_000_000 => 5 s imprecise and hard to determine the MITM.
	                       65_000_000 => 5065 ms
                               74_000 => 5065074 us, still too big

This preamble can ought to be compressed after a successfully handshake.

inflow may be invalid or valid.
For the valid parts, the critera are defined by basic semanteme and methods to prevent or mitigate:
	(syn|fin)-DDos attack, MITM, eg. eavesdrop/faisfy/masquerade communication parties.

	- 0000 + SEQ + 0000 + 0000_0000 + _typ | _syn | _pms + promisedTimeVal(less than 5 seconds) + Seed:
		represent the willing of establishing a connection with current host.
		seed is used for protecting the subsequent messages.

	- ID + SEQ + ACK + 0000_0000 + _typ | _syn | _pms | _ack + promisedTimeVal(less than 5 seconds as well) + Seed:
		positive response of request for establishing a connection.
		Before sending, any sender should validate the legitimacy of timeval from source.
		At most record the generated id, initial seq, ack, refPing and seed after passing the last stage.

	- 0000 + 0000 + ACK + 0000_0000 + _typ | _rst ==> certain udp addr of instigator:
		abort the connection without any explanation
		any sender uses this before removing abstract and malicious items from queues.

	- ID + SEQ + ACK + 0000_0000 + _typ | _ack + first_payload(optional but not recommanded):
		connection has been set up.
	========================== no timeout-retransmission stage during first handshake ===========================

	- ID + SEQ + ACK + curr_ack_cond + _ack + payload:
		sender needs resending the packet according to curr_ack_cond and wait for SEQ + x.
		x is the last tag identified from curr_ack_cond.
		receiver should check whether this packet is late or not.
	- ID + SEQ + ACK + curr_ack_cond + _rck + payload:
		a retransmitted packet after timeout.
		receiver should check whether this packet has been received.

1                  1                         N
read_loop => parser(classifier) => handler1, handler2, handler3.
                 1
handlerx => innerEventSurveiller
	1. feed the old connections or let it push a new timeoutEvent to the EventQueue.
		maybe we can encapsulate an channel for later corresponding flow ?
	2. Proactively remove the connection in half-sync queue or accepted queue in certain stage.

innerEventSurveiller: remove timeout connections according to the item storing in the queue or just ignore.

N               1
handlerx => LazySafeWrite

*/

type (
	_bits_       byte
	_sync_state_ byte

	TDPConn struct {
		Addr        *net.UDPAddr
		ID, RefTime uint32
		Seq, Ack    uint32
		XorKey      [3]byte
		SBuf, RBuf  *[]byte
		AdmitChan   chan struct{}
	}
	TDPTimeoutID struct {
		CID uint32 // remote-connection-ID
		PID uint32 // packet seq
		/*
			the state of different timeout.
			- `t` for syncx timeout
			- `p` for packet timeout
		*/
		State byte
	}
	TDPMapKey struct {
		choice, idx uint32
	}
	TDPManager struct {
		Listener           *net.UDPConn // read packet from infinite loop as a listener.
		WriterLock         sync.Mutex   // protect the write side. WriteTo(msg, addr)
		SucideReadSign     atomic.Bool
		SucideParseSign    atomic.Bool
		SucideHalfSyncSign atomic.Bool
		SucideAcceptedSign atomic.Bool
		SucideEventSign    atomic.Bool
		InnerQueueCnt      [2]atomic.Int64
		InnerQueue         sync.Map // [2]map[uint32]*EtdpConn => map{_sync_state, cnt} => *EtdpConn
		IDreverser         sync.Map // [2]map[uint32]uint32 => map{_sync_state, EtdpConn -> ID} => cnt
		EventHandler       *EventNotifyQueue
		ParserQueue        *AddrMessageQueue // (read-flow, addr) enqueue parser for further works.
		HalfSyncQueue      *ReverseIDMessageQueue
		AcceptedQueue      *ReverseIDMessageQueue
	}
)

const (
	TYP _bits_ = 128
	SYN _bits_ = 64
	ACK _bits_ = 32
	RCK _bits_ = 16
	RST _bits_ = 8
	FIN _bits_ = 4
	PMS _bits_ = 2
)

const (
	SYNC1 _sync_state_ = iota
	SYNC2
	SYNC3 // connected.
	FISH1
	FISH2 // end of connection.
)

func (tdp *TDPConn) SyncTimeout(expired time.Duration) interface{} {
	timer := time.NewTimer(expired)
	select {
	case <-timer.C:
		return TDPTimeoutID{CID: tdp.ID, State: byte('t')}
	case res := <-tdp.AdmitChan:
		return res
	}
}

func (tdp *TDPManager) DeleteItemInQueue(item TDPMapKey) {
	tdp.InnerQueue.Delete(item)
}

func (tdp *TDPManager) DeleteIdxInMap(idx TDPMapKey) {
	tdp.IDreverser.Delete(idx)
}

// read the sucide sign of udp listener
func (tdp *TDPManager) SafeReadSucideReadSign() bool {
	return tdp.SucideReadSign.Load()
}

// flip the sucide sign of udp listener
func (tdp *TDPManager) SafeFlipSucideReadSign() {
	var choice bool
	if tdp.SafeReadSucideReadSign() {
		choice = false
	} else {
		choice = true
	}
	tdp.SucideReadSign.Store(choice)
}

// init the sucide sign of udp listener
func (tdp *TDPManager) InitSucideReadSign() {
	tdp.SucideReadSign.Store(true)
}

// read the sucide sign of parser
func (tdp *TDPManager) SafeReadSucideParseSign() bool {
	return tdp.SucideParseSign.Load()
}

// flip the sucide sign of parser
func (tdp *TDPManager) SafeFlipSucideParseSign() {
	var choice bool
	if tdp.SafeReadSucideParseSign() {
		choice = false
	} else {
		choice = true
	}
	tdp.SucideParseSign.Store(choice)
}

// init the sucide sign of parser
func (tdp *TDPManager) InitSucideParseSign() {
	tdp.SucideParseSign.Store(true)
}

// read the sucide sign of half-sync-queue
func (tdp *TDPManager) SafeReadSucideHalfSyncSign() bool {
	return tdp.SucideHalfSyncSign.Load()
}

// flip the sucide sign of half-sync-queue
func (tdp *TDPManager) SafeFlipSucideHalfSyncSign() {
	var choice bool
	if tdp.SafeReadSucideHalfSyncSign() {
		choice = false
	} else {
		choice = true
	}
	tdp.SucideHalfSyncSign.Store(choice)
}

// init the sucide sign of half-sync-queue
func (tdp *TDPManager) InitSucideHalfSyncSign() {
	tdp.SucideHalfSyncSign.Store(true)
}

// read the sucide sign of accepted-queue
func (tdp *TDPManager) SafeReadSucideAcceptedSign() bool {
	return tdp.SucideAcceptedSign.Load()
}

// flip the sucide sign of accepted-queue
func (tdp *TDPManager) SafeFlipSucideAcceptedSign() {
	var choice bool
	if tdp.SafeReadSucideAcceptedSign() {
		choice = false
	} else {
		choice = true
	}
	tdp.SucideAcceptedSign.Store(choice)
}

// init the sucide sign of accepted-queue
func (tdp *TDPManager) InitSucideAcceptedSign() {
	tdp.SucideAcceptedSign.Store(true)
}

// initialize the udpListener.
func (tdp *TDPManager) InitLocalListener(udptype string, port uint16) (err error) {
	tdp.Listener, err = net.ListenUDP(udptype,
		&net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: int(port),
		})
	return
}

func (tdp *TDPManager) ReadFlow() {
	buf := make([]byte, 1024)
	for tdp.SafeReadSucideReadSign() {
		cnt, addr, err := tdp.Listener.ReadFromUDP(buf)
		if cnt <= 0 || err != nil {
			continue
		}
		var inp []byte
		copy(inp, buf[:cnt])
		tdp.ParserQueue.PushBack(AddrMessage{Addr: addr, Msg: inp})
	}
}

// function for order writing.
func (tdp *TDPManager) SafeWriteAny(msg []byte, addr *net.UDPAddr) (uint32, error) {
	tdp.WriterLock.Lock()
	cnt, err := tdp.Listener.WriteTo(msg, addr)
	tdp.WriterLock.Unlock()
	return uint32(cnt), err
}

func (tdp *TDPManager) AcceptedHandler() {
	// accept-sync loop.
	for tdp.SafeReadSucideAcceptedSign() {
		ac_msg := tdp.AcceptedQueue.PopFront()
		idx, msg := ac_msg.Idx, ac_msg.Msg
		// conn := tdp.InnerQueue[SYNC1][idx]
		log.Println(idx, msg)
	}
}

func (tdp *TDPManager) HalfSyncHandler() {
	// fetch from half-sync queue.
	for tdp.SafeReadSucideHalfSyncSign() {
		hs_msg := tdp.AcceptedQueue.PopFront()
		idx, msg := hs_msg.Idx, hs_msg.Msg
		// TODO
		log.Println(idx, msg)
	}
}

func (tdp *TDPManager) RookieHandler(addr *net.UDPAddr, msg []byte) {
	lena := utils.BytesToUint16([2]byte(msg[:2]))
	if lena != 2+4+4+4+8+1+ /*promisedTimeVal*/ 4+ /*CryptoSeed*/ 3 {
		return // drop this packet.
	}
	/* advancedAck := msg[14:22] */
	ctrl_bits := _bits_(msg[22])
	switch ctrl_bits {
	case TYP | SYN | PMS:
		ping_ref, valid := PingWithoutPrint(addr.String(), 3, 5, 5)
		// the validation of accessibility.
		if !valid {
			return
		}
		// TODO: seed := [3]byte(msg[27:30])
		pms_val := msg[23:27]
		sec := int64(pms_val[0]) | (int64(pms_val[1]&0x3) << 8)
		mil := int64(pms_val[1]>>2) | (int64(pms_val[2]&0xF) << 8)
		mic := int64(pms_val[2]>>4) | int64(pms_val[3]&0x3F)
		us := mic + mil*1000 + sec*1000000

		if utils.AbsMinusInt(us, ping_ref)*2 >= ping_ref*3 {
			// semanteme validation failed.
			return
		}
		seq := msg[6:10]
		assigned_id := make([]byte, 4)
	regain:
		rand.Read(assigned_id)
		curr_id := utils.BytesToUint32([4]byte(assigned_id))
		_, ok := tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC1), idx: curr_id})
		if ok {
			goto regain
		}
		_, ok = tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC2), idx: curr_id})
		if ok {
			goto regain
		}
		mean_time := uint32((ping_ref + us)) >> 1
		// TODO: adjust time if necessary.
		// 		 md5.Sum(seq||addr.string()||refTime)[4:] as seq.
		// 		 Generate seed for the sender.
		record := TDPConn{
			Addr:    addr,
			ID:      curr_id,
			RefTime: mean_time,
			Seq:     utils.BytesToUint32([4]byte(seq)),
			Ack:     utils.BytesToUint32([4]byte(seq)),
		}
		// the packet should seal the assign ID and seed for subsequent usage.

		// TODO: CNT 限制。
		tdp.InnerQueueCnt[0].Add(1)
		cnt := tdp.InnerQueueCnt[0].Load()
		tdp.IDreverser.Store(TDPMapKey{choice: uint32(SYNC1), idx: curr_id}, cnt)
		tdp.InnerQueue.Store(TDPMapKey{choice: uint32(SYNC1), idx: uint32(cnt)}, &record)

		go func() {
			// TODO: SafeWriteBack TYP | SYN | ACK | PMS.
			tdp.EventHandler.PushBack(
				record.SyncTimeout(time.Duration(record.RefTime) * time.Microsecond))
		}()
	default:
		return
	}
}

func (tdp *TDPManager) EventAnalyzer() {
	for {
		tdp.EventHandler.PopFront()
	}
}

func (tdp *TDPManager) Parser() {
	for tdp.SafeReadSucideParseSign() {
		_msg := tdp.ParserQueue.PopFront()
		msg, addr := _msg.Msg, _msg.Addr
		if msg == nil || len(msg) <= 2+4+4+4+8+1 {
			continue
		}

		id := utils.BytesToUint32([4]byte(msg[2:6]))
		// TODO: if there are any risks generated from tons of concurrency
		// 		 caused by malicious or undeliberate operation ?

		/* condition-1: accepted */
		_idx, ok := tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC2), idx: id})
		if ok {
			var inp []byte
			idx := _idx.(uint32)
			copy(inp, msg)
			go func() { tdp.AcceptedQueue.PushBack(ReverseIDMessage{idx, inp}) }()
			continue
		}

		/* condition-2: half-connected */
		_idx, ok = tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC1), idx: id})
		if ok {
			// TODO: update addr if necessary.
			var inp []byte
			idx := _idx.(uint32)
			copy(inp, msg)
			go func() { tdp.HalfSyncQueue.PushBack(ReverseIDMessage{idx, inp}) }()
			continue
		}

		/* condition-3: first come in. */
		go func() { tdp.RookieHandler(addr, msg) }()
	}
}

func (tdp *TDPManager) Comprehensive() {
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		/* listening to die signal and turn on sucide sign. */
		// TODO
		wg.Done()
	}()
	go func() {
		/* parse-loop */
		tdp.Parser()
		wg.Done()
	}()
	go func() {
		/* halfsync-loop */
		tdp.HalfSyncHandler()
		wg.Done()
	}()
	go func() {
		/* accepted-loop*/
		tdp.AcceptedHandler()
		wg.Done()
	}()
	tdp.ReadFlow()
	wg.Wait()
}

func (tdp *TDPConn) Write(b []byte) (cnt int, err error) {
	// TODO
	return
}

func (tdp *TDPConn) Read() (cnt int, err error) {
	// TODO
	return
}
