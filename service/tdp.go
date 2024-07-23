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
	_tdp_bits_   byte
	_sync_state_ byte

	TDPPacket struct {
		ChNotify chan struct{}
		Msg      []byte
	}

	TDPConn struct {
		Addr        *net.UDPAddr
		Local       *net.UDPConn
		ID, RefTime uint32
		Seq, Ack    uint32
		XorKey      [3]byte
		SBuf, RBuf  []TDPPacket // for sendbuf and receive buffer, both of them need to set deadline for each packet.
		AdmitChan   chan struct{}
		ShouldDie   chan struct{} // due to connection timeout or other urgent events
	}
	TDPTimeoutID struct {
		/*
			the state of different timeout.
			- `t` for syncx timeout
			- `p` for packet timeout
		*/
		State uint32
		QID   uint32 // which queue should current tdp  be in
		CID   uint32 // remote-connection-ID
		PID   uint32 // packet seq
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
		/*
			[2]map[uint32]uint32 =>
			map{_sync_state, EtdpConn -> ID} => the sequential cnt of connection in halfsync queue or accepted queue.
		*/
		IDreverser    sync.Map
		EventHandler  *TDPQueue // *EventNotifyQueue
		ParserQueue   *TDPQueue // *AddrMessageQueue // (read-flow, addr) enqueue parser for further works.
		HalfSyncQueue *TDPQueue // *ReverseIDMessageQueue
		AcceptedQueue *TDPQueue // *ReverseIDMessageQueue
	}
)

const (
	TYP _tdp_bits_ = 0b10000000 // distinguish the type of packet (control or merely data)
	SYN _tdp_bits_ = 0b01000000 // synchronize for connection
	ACK _tdp_bits_ = 0b00100000 // acknowledge for packet
	RCK _tdp_bits_ = 0b00010000 // re-acknowledge for packet
	RST _tdp_bits_ = 0b00001000 // reset current connection
	FIN _tdp_bits_ = 0b00000100 // finish current connection
	PMS _tdp_bits_ = 0b00000010 // promise time for next packet
	ARV _tdp_bits_ = 0b00000001 // flag: the final packet of one message has arrived.
	// maybe we should define the last bit for notifying that the final message has arrived.
	// we also wants to maintain alive connections by some mechanisms.

	ConnectionTimeout uint32 = 1953853300 // utils.BytesToUint32([4]byte([]byte("tout")))
	PacketTimeout     uint32 = 1953853296 // utils.BytesToUint32([4]byte([]byte("pout")))

	MAXNUM_OF_CONN  = 1024
	MAXNUM_OF_EVENT = 8192
)

const (
	SYNC1_1 _sync_state_ = iota
	SYNC2                // connected.
	SYNC1_2
	FISH1
	FISH2 // end of connection.
)

func (tdp *TDPConn) SyncTimeout(qid _sync_state_, expired time.Duration) interface{} {
	timer := time.NewTimer(expired)
	select {
	case <-timer.C:
		return TDPTimeoutID{CID: tdp.ID, QID: uint32(qid), State: ConnectionTimeout}
	case res := <-tdp.AdmitChan:
		timer.Stop()
		return res
	}
}

func (tdp *TDPConn) PacketTimeout(
	qid _sync_state_,
	isInSendBuf bool,
	packetID uint32,
	expired time.Duration,
) interface{} {
	timer := time.NewTimer(expired)
	var target_ch chan struct{}
	if isInSendBuf {
		target_ch = tdp.SBuf[packetID].ChNotify
	} else {
		target_ch = tdp.RBuf[packetID].ChNotify
	}
	select {
	case <-timer.C:
		return TDPTimeoutID{QID: uint32(qid), CID: tdp.ID, PID: packetID, State: ConnectionTimeout}
	case res := <-target_ch:
		timer.Stop()
		return res
	}
}

func (tdp *TDPManager) InitQueues() {
	tdp.ParserQueue.Init(MAXNUM_OF_CONN)
	tdp.EventHandler.Init(MAXNUM_OF_EVENT)
	tdp.HalfSyncQueue.Init(MAXNUM_OF_CONN)
	tdp.AcceptedQueue.Init(MAXNUM_OF_CONN)
}

func (tdp *TDPManager) DeleteItemInQueue(item TDPMapKey) {
	tdp.InnerQueue.Delete(item)
}

func (tdp *TDPManager) DeleteIdxInReverseMap(idx TDPMapKey) {
	tdp.IDreverser.Delete(idx)
}

// read the sucide sign of udp listener
func (tdp *TDPManager) SafeReadSucideReadSign() bool {
	return tdp.SucideReadSign.Load()
}

// flip the sucide sign of udp listener
func (tdp *TDPManager) SafeFlipSucideReadSign() {
	tdp.SucideReadSign.Store(!tdp.SafeReadSucideReadSign())
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
	tdp.SucideParseSign.Store(!tdp.SafeReadSucideParseSign())
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
	tdp.SucideHalfSyncSign.Store(!tdp.SafeReadSucideHalfSyncSign())
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
	tdp.SucideAcceptedSign.Store(!tdp.SafeReadSucideAcceptedSign())
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

// read udp-flow and pass the content to parser to identify what the packet wants to convey.
func (tdp *TDPManager) ReadFlow() {
	buf := make([]byte, 1024)
	// ? as if the aggregate memory consumption will blow up...
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

func ReverseIDMessagefunctor(inp TDPItem) ReverseIDMessage {
	switch x := inp.(type) {
	case ReverseIDMessage:
		return x
	default:
		return ReverseIDMessage{Idx: 0, Msg: nil}
	}
}

func (tdp *TDPManager) AcceptedHandler() {
	// accept-sync loop.
	for tdp.SafeReadSucideAcceptedSign() {
		ac_msg := tdp.AcceptedQueue.PopFront()

		_msg := ReverseIDMessagefunctor(ac_msg)
		if _msg.Idx == 0 && _msg.Msg == nil {
			continue
		}
		obj, ok1 := tdp.InnerQueue.Load(TDPMapKey{choice: uint32(SYNC2), idx: _msg.Idx})
		tdpConn, ok2 := obj.(*TDPConn)
		if !ok1 || !ok2 {
			continue
		}

		msg := _msg.Msg
		ctrl_bits := _tdp_bits_(msg[22])
		switch ctrl_bits {
		case TYP | RST:
			// TODO: prevent malicious attack from unknown sources.
			clear(tdpConn.SBuf)
			clear(tdpConn.RBuf)
		case TYP | FIN:

		case TYP | FIN | ACK:

		case TYP | ACK:
			// check for

		case TYP | FIN | RCK:

		case RCK:
			// todo: feed data-timeout-channel

		case ACK:
			// todo: feed data-timeout-channel
		default:
			continue
		}
		// TODO: unseal from weak-encrypt domain and then check seq, ack.
		tdpConn.AdmitChan <- struct{}{}

	}
}

func (tdp *TDPManager) HalfSyncHandler() {
	// fetch from half-sync queue.
	for tdp.SafeReadSucideHalfSyncSign() {
		halfsync_msg := tdp.HalfSyncQueue.PopFront()
		_msg := ReverseIDMessagefunctor(halfsync_msg)
		if _msg.Idx == 0 && _msg.Msg == nil {
			return
		}
		obj, ok1 := tdp.InnerQueue.Load(TDPMapKey{choice: uint32(SYNC1_1), idx: _msg.Idx})
		tdpConn, ok2 := obj.(*TDPConn)
		if !ok1 || !ok2 {
			continue
		}

		msg := _msg.Msg
		ctrl_bits := _tdp_bits_(msg[22])
		switch ctrl_bits {
		case TYP | RST:
			// 验证身份后结束。
			// check and remove.
		case TYP | SYN | ACK | PMS:
			// we have already had pingRefTime.
			lena := utils.BytesToUint16([2]byte(msg[:2]))
			if lena != 22+1+4 {
				return
			}

			pms_val := msg[23:27]
			sec := int64(pms_val[0]) | (int64(pms_val[1]&0x3) << 8)
			mil := int64(pms_val[1]>>2) | (int64(pms_val[2]&0xF) << 8)
			mic := int64(pms_val[2]>>4) | int64(pms_val[3]&0x3F)
			us := mic + mil*1000 + sec*1000000
			if utils.AbsMinusInt(us, int64(tdpConn.RefTime))*2 >= int64(tdpConn.RefTime)*3 {
				return // semanteme validation failed.
			}

			seq, ack := utils.BytesToUint32([4]byte(msg[2:6])), utils.BytesToUint32([4]byte(msg[6:10]))
			if tdpConn.Ack+1 != ack && tdpConn.Seq+1 != seq {
				return
			}
			tdpConn.Seq += 1
			tdpConn.Ack += 1
			mean_time := (int64(tdpConn.RefTime) + us) / 2
			// we will seal the packet with seed from now on.

			// next-packet: ack, but we still need a raw ack
			go func() {
				tdp.EventHandler.PushBack(
					tdpConn.SyncTimeout(SYNC1_1, time.Duration(mean_time)*time.Microsecond))
			}()
		case TYP | ACK:
			// connection build-up for reader/server side.
			// pop connection from half-sync-queue and add it to accepted queue.

			// next-packet: ack.
		case ACK:
			// connection build-up to writer/client side.
			// pop connection from half-sync-queue and add it to accepted queue.

			// no action anymore.
		default:
			continue
		}

		tdpConn.AdmitChan <- struct{}{}
	}
}

func (tdp *TDPManager) RookieHandler(addr *net.UDPAddr, msg []byte) {
	lena := utils.BytesToUint16([2]byte(msg[:2]))
	if lena != 2+4+4+4+8+1+ /*promisedTimeVal*/ 4+ /*CryptoSeed*/ 3 {
		return // drop this.
	}
	// TODO: checksum for consistency.
	/* advancedAck := msg[14:22] */
	ctrl_bits := _tdp_bits_(msg[22])
	switch ctrl_bits {
	case TYP | SYN | PMS:
		ping_ref, valid := PingWithoutPrint(addr.String(), 3, 5, 5)
		// the validation of accessibility.
		if !valid {
			return
		}
		// TODO: seed Agreement := [3]byte(msg[27:30])
		pms_val := msg[23:27]
		sec := int64(pms_val[0]) | (int64(pms_val[1]&0x3) << 8)
		mil := int64(pms_val[1]>>2) | (int64(pms_val[2]&0xF) << 8)
		mic := int64(pms_val[2]>>4) | int64(pms_val[3]&0x3F)
		us := mic + mil*1000 + sec*1000000

		if utils.AbsMinusInt(us, ping_ref)*2 >= ping_ref*3 {
			return // semanteme validation failed.
		}
		seq := msg[6:10]
		assigned_id := make([]byte, 4)
	regain:
		rand.Read(assigned_id)
		curr_conn_id := utils.BytesToUint32([4]byte(assigned_id))
		_, ok := tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC1_1), idx: curr_conn_id})
		if ok {
			goto regain
		}
		_, ok = tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC2), idx: curr_conn_id})
		if ok {
			goto regain
		}
		mean_time := uint32((ping_ref + us)) >> 1
		// TODO: adjust pingRefTime by Cybernetics algorithm when necessary.
		record := TDPConn{
			Addr:    addr,
			Local:   tdp.Listener,
			ID:      curr_conn_id,
			RefTime: mean_time,
			Seq:     utils.BytesToUint32([4]byte(seq)),
			// TODO: set the seq by md5.Sum(seq||addr.string()||refTime)[4:] as seq.
			Ack: utils.BytesToUint32([4]byte(seq)),
			// Generate seed for the sender.
		}

		// TODO: CNT 限制。
		tdp.InnerQueueCnt[SYNC1_1].Add(1)
		cnt := tdp.InnerQueueCnt[SYNC1_1].Load()
		tdp.IDreverser.Store(TDPMapKey{choice: uint32(SYNC1_1), idx: curr_conn_id}, cnt)
		tdp.InnerQueue.Store(TDPMapKey{choice: uint32(SYNC1_1), idx: uint32(cnt)}, &record)

		go func() {
			// TODO: SafeWriteBack TYP | SYN | ACK | PMS.
			tdp.EventHandler.PushBack(
				record.SyncTimeout(SYNC1_1, time.Duration(record.RefTime)*time.Microsecond))
		}()
	default:
		return
	}
}

func (tdp *TDPManager) timeoutClassifier(inp TDPTimeoutID) {
	tmp := TDPMapKey{choice: inp.QID, idx: inp.CID}
	_cnt, ok1 := tdp.IDreverser.Load(tmp)
	cnt, ok2 := _cnt.(uint32)
	if !ok1 || !ok2 {
		return
	}
	switch inp.State {
	case ConnectionTimeout:
		tdp.DeleteIdxInReverseMap(tmp)
		tdp.DeleteItemInQueue(TDPMapKey{choice: inp.QID, idx: cnt})
	case PacketTimeout:
		_conn_handler, ok := tdp.InnerQueue.Load(TDPMapKey{choice: tmp.choice, idx: cnt})
		if !ok {
			return
		}
		conn_handler, ok := _conn_handler.(*TDPConn)
		if !ok {
			return
		}
		// TODO: alternate msg.
		// resend packet and set rck bit.
		tdp.SafeWriteAny([]byte(`hello world`),
			conn_handler.Addr)
	}
}

func (tdp *TDPManager) EventAnalyzer() {
	for tdp.SucideEventSign.Load() {
		_item := tdp.EventHandler.PopFront()
		switch item := _item.(type) {
		default:
		case TDPTimeoutID:
			tdp.timeoutClassifier(item)
		}
	}
}

func (tdp *TDPManager) parserFunctor(msg []byte, addr *net.UDPAddr) {
	if msg == nil || len(msg) <= 2+4+4+4+8+1 {
		return
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
		return
	}

	/* condition-2: half-connected */
	_idx, ok = tdp.IDreverser.Load(TDPMapKey{choice: uint32(SYNC1_1), idx: id})
	if ok {
		// TODO: update addr if necessary.
		var inp []byte
		idx := _idx.(uint32)
		copy(inp, msg)
		go func() { tdp.HalfSyncQueue.PushBack(ReverseIDMessage{idx, inp}) }()
		return
	}

	/* condition-3: first come in. */
	go func() { tdp.RookieHandler(addr, msg) }()
}

func (tdp *TDPManager) Parser() {
	for tdp.SafeReadSucideParseSign() {
		_msg := tdp.ParserQueue.PopFront()
		switch ams := _msg.(type) {
		case AddrMessage:
			msg, addr := ams.Msg, ams.Addr
			tdp.parserFunctor(msg, addr)
		default:
			continue
		}
	}
}

func (tdp *TDPManager) Comprehensive() {
	var wg sync.WaitGroup
	wg.Add(5)
	wg_done := make(chan struct{})
	go func() {
		/* listening to die signal and turn on sucide sign from outside function. */
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
	go func() {
		tdp.ReadFlow()
		wg.Done()
	}()

	go func() {
		wg.Wait()
		wg_done <- struct{}{}
	}()
	select {
	case <-wg_done:
		return
	// TODO I think control signal is more Mighty and convincing but the states seems not to be seperable...
	case <-time.After(time.Hour * 24):
		log.Println(`wg-timeout.`)
		return
	}
}

func (tdp *TDPConn) Write(b []byte) (cnt int, err error) {
	// TODO
	return
}

func (tdp *TDPConn) Read() (cnt int, err error) {
	// TODO
	return
}

func (tdp *TDPConn) Close() error {
	// TODO
	return nil
}

func (tdp *TDPConn) SetWriteDeadline(t time.Time) error { /* TODO */ return nil }

func (tdp *TDPConn) SetReadDeadline(t time.Time) error { /* TODO */ return nil }

func (tdp *TDPConn) SetDeadline(t time.Time) error { /* TODO */ return nil }

func (tdp *TDPConn) LocalAddr() net.Addr {
	return tdp.Local.LocalAddr() // local addr
}

func (tdp *TDPConn) RemoteAddr() net.Addr {
	return tdp.Addr // remote addr
}
