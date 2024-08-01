// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
// ACKNOWLEDGE: https://www.rfc-editor.org/rfc/pdfrfc/rfc6013.txt.pdf
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
	                              udp + trusted transmission

Designed in an overt scheme.

TODO:
	write a concrete and specific unit test and validate on real machine and see whether this protocol is able to bypass ISP QoS
	prevent memory leak from the go routine leak

The windows size or group size is intensionally fixed to 128 for simplifying
the process of adjusting windows size, congestion control and fast retransmission firstly defined in TCP.

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
                 4 bytes        |   0 1
                 n    n         |    b b b b b b b b
                 _u    u     uint64  i i i i i i i i
                 _ m    m    8 bytes t t t t t t t t
      4 bytes 2B _  b    b   ?                        2bytes seeds   4bytes2 byte
    +--------+---+----+----+--------+-+-+-+-+-+-+-+-+ -+-+-+-+-+-+-+-+----+-----+
    |assigned|L  |S   |A   |current |t|a|r|r|s|f|v|a| -|-|-|-|-|-|-|-|4   |crc  |
    |        | E |  E |  C | group  |y|c|c|s|y|i|r|v| -|-|-|-|-|-|-|-|sign|check|
    |uniqueID|  N|   Q|   K|recv-num|p|k|k|t|n|n|f|d| -|-|-|-|-|-|-|-|    |sum  |
    +--------+---+----+----+--------+-+-+-+-+-+-+-+-+ -+-+-+-+-+-+-+-+----+-----+
	 the length of payload.

This preamble can ought to be compressed after a successfully handshake.

inflow may be invalid or valid.
For the valid parts, the critera are defined by basic semanteme and methods to prevent or mitigate:
	(syn|fin)-DDos attack, MITM, eg. eavesdrop/faisfy/masquerade communication parties.

	- 0x0000 + SEQ + 0x0000 + 0x0000_0000 + typ | syn | pms + promisedTimeVal + Seed1:
		represent the willing of establishing a connection with current host.
		seed is used for protecting the subsequent messages.

	- ID + SEQ + ACK + 0x0000_0000 + typ | syn | pms | ack + promisedTimeVa + Seed2:
		positive response of request for establishing a connection.
		Before sending, any sender should validate the legitimacy of timeval from source.
		At most record the generated id, initial seq, ack, refPing and seed after passing the last stage.

	- 0x0000 + 0x0000 + 0x0000 + 0x0000_0000 + typ | rst ==> certain udp addr of instigator:
		abort the connection without any explanation
		any sender uses this before removing abstract and malicious items from queues.

		the counterfeiting behaviour needs preventing.

	- ID + SEQ + ACK + 0x0000_0000 + typ | ack:
		connection has been set up.

	- ID + SEQ + ACK + curr_ack_cond + _ack + payload:
		sender needs resending the packet according to curr_ack_cond and wait for SEQ + x.
		x is the last tag identified from curr_ack_cond.
		receiver should check whether this packet is late or not.
	- ID + SEQ + ACK + curr_ack_cond + _rck + payload:
		a retransmitted packet after timeout.
		receiver should check whether this packet has been received.

Architecture:

- read end:
	    read-flows < ReadFromUDP >
	        |
		flows-parser
	         |      \
	      halfsync accepted
	       hashPool     conn
	         |      /
	    EventHandler -------- drop
	         |
	thread-safe-write-back

一个可信连接 <=> 对主机分配的 ID。
短时间内同一（地址:端口）并发传来的重复/迟到同步请求包，只应受理首个，其余丢弃。
只为其保留 cookie 和 seed。超时两次后清除二者。
假如说两台计算机之间并不能通过可靠的 ping 确定通信用时，为了让服务器从没有收到应答的情形脱离，至少要求
	客户 ack cookie 并通过验证后即可直接接入 accepted 集合。此后每次都需要连同传回的 seed 保护控制域。

	typ | syn ------>
	<--------- typ | syn | ack
	[typ | syn | ack | avd] ---->

如果主机 ip 改变但所用的应用还在使用 ID，则变更 ip 需要通过 challenge & response 后才能切换。


- write end(yet to implement):
	    dialUDP => UDPAddr   read data
	                |       /
	            action manager
	             /      |     \
	        handshake alive  write data
	                  keeper
*/

type (
	__tdp_bits__       byte
	__tdp_handler_id__ byte
	__sync_state__     byte

	TDPPacket struct {
		ChNotify chan struct{}
		Msg      []byte
	}

	TDPTimeoutID struct {
		/*
			the state of different timeout.
			- `t` for syncx timeout
			- `p` for packet timeout
		*/
		State uint32
		QID   uint32 // which set should current tdp Connection be in
		CID   uint32 // remote-connection-ID
		PID   uint32 // packet seq
	}
	TDPMapKey struct {
		choice, idx uint32
	}
	// one TDPCB for one port.
	TDPControlBlock struct {
		/*
			read packet from infinite loop as a listener.
			write packet to remote host.
		*/
		Listener           *net.UDPConn
		WLock              sync.Mutex // protect the write side. WriteTo(msg, addr)
		InnerSets          sync.Map   // map{_sync_state, cnt} => *tdpConn
		IDreverser         sync.Map   // map{which queue, connID} => cnt in InnerSet
		ChShouldDie        chan struct{}
		InnerSetsCnt       [2]atomic.Uint32
		SucideReadSign     atomic.Bool
		SucideParseSign    atomic.Bool
		SucideHalfSyncSign atomic.Bool
		SucideAcceptedSign atomic.Bool
		SucideEventSign    atomic.Bool
		EventHandler       *TDPQueue // *EventNotify. enqueue item: timerEvent/msgEvent
		ParserQueue        *TDPQueue // *AddrMessage. enqueue item: (addr, read-flow)
		HalfSyncQueue      *TDPQueue // *ReverseIDMessage
		AcceptedQueue      *TDPQueue // *ReverseIDMessage
	}
)

const (
	HID_FRESH __tdp_handler_id__ = iota
	HID_HALFSYNC
	HID_ACCEPTED

	SYNC1_1 __sync_state__ = iota - 2
	SYNC1_2
	SYNC2 // connected.
	FISH1
	FISH2 // end of connection.

	/* the meaning for control bits. */
	TYP __tdp_bits__ = 0b10000000 // distinguish the type of packet (controlType or merely dataType)
	SYN __tdp_bits__ = 0b01000000 // synchronize for connection
	ACK __tdp_bits__ = 0b00100000 // acknowledge for packet
	RCK __tdp_bits__ = 0b00010000 // re-acknowledge for packet
	RST __tdp_bits__ = 0b00001000 // reset current connection
	FIN __tdp_bits__ = 0b00000100 // finish current connection
	PMS __tdp_bits__ = 0b00000010 // promise time for next packet
	ARV __tdp_bits__ = 0b00000001 // flag to notify that the final packet of one message has arrived.

	// TODO: we also wants to maintain alive connections by certain mechanisms.

	PromoteConnTimeout uint32 = 1953853300 // string "tout" in the representation of Little Endian
	PromotePackTimeout uint32 = 1953853296 // string "pout" in the representation of Little Endian

	MAXNUM_OF_CONN  = 1024
	MAXNUM_OF_EVENT = 8192

	// the postion of each domain defined in one packet.
	TDP_SYNTAX_ID       uint32 = 0  // 0 ... 3 ID for identifying remote connection.
	TDP_SYNTAX_DATALEN  uint32 = 4  // 4 ... 6 DATALEN for indicating the length of payload instead of total packet.
	TDP_SYNTAX_SEQ      uint32 = 6  // 6 ... 9 SEQ.
	TDP_SYNTAX_ACK      uint32 = 10 // 10 ... 13 ACK
	TDP_SYNTAX_ADVANCK  uint32 = 14 // 14 ... 22 PREACK: the mask of receiving advanced packets.
	TDP_SYNTAX_BITS     uint32 = 22 // 22 ... 23 BITS: control flag.
	TDP_SYNTAX_PMSVAL   uint32 = 23 // 23 ... 27 PMSVAL: promised next arriving time.
	TDP_SYNTAX_BASICLIM uint32 = 23 // BASICLIM: basic limitation of the length of a packet.
	TDP_SYNTAX_SEED     uint32 = 27 // 27 ... 30
	TDP_SYNTAX_BOUNDARY uint32 = 30 // The boundary of header.
)

func (tdp *TDPControlBlock) initQueues() {
	tdp.ParserQueue.Init(MAXNUM_OF_CONN)
	tdp.EventHandler.Init(MAXNUM_OF_EVENT)
	tdp.HalfSyncQueue.Init(MAXNUM_OF_CONN)
	tdp.AcceptedQueue.Init(MAXNUM_OF_CONN)
}

/*
 *	BEGIN: Define for alias.
 */

// ! for read-flow

// read the sucide sign of udp listener
func (tdp *TDPControlBlock) SafeReadSucideReadSign() bool {
	return tdp.SucideReadSign.Load()
}

// flip the sucide sign of udp listener
func (tdp *TDPControlBlock) SafeFlipSucideReadSign() {
	tdp.SucideReadSign.Store(!tdp.SafeReadSucideReadSign())
}

// init the sucide sign of udp listener
func (tdp *TDPControlBlock) InitSucideReadSign() {
	tdp.SucideReadSign.Store(true)
}

// ! for parser

// read the sucide sign of parser
func (tdp *TDPControlBlock) SafeReadSucideParseSign() bool {
	return tdp.SucideParseSign.Load()
}

// flip the sucide sign of parser
func (tdp *TDPControlBlock) SafeFlipSucideParseSign() {
	tdp.SucideParseSign.Store(!tdp.SafeReadSucideParseSign())
}

// init the sucide sign of parser
func (tdp *TDPControlBlock) InitSucideParseSign() {
	tdp.SucideParseSign.Store(true)
}

// ! for halfsync-queue

// read the sucide sign of half-sync-queue
func (tdp *TDPControlBlock) SafeReadSucideHalfSyncSign() bool {
	return tdp.SucideHalfSyncSign.Load()
}

// flip the sucide sign of half-sync-queue
func (tdp *TDPControlBlock) SafeFlipSucideHalfSyncSign() {
	tdp.SucideHalfSyncSign.Store(!tdp.SafeReadSucideHalfSyncSign())
}

// init the sucide sign of half-sync-queue
func (tdp *TDPControlBlock) InitSucideHalfSyncSign() {
	tdp.SucideHalfSyncSign.Store(true)
}

// ! for accepted-queue
// read the sucide sign of accepted-queue
func (tdp *TDPControlBlock) SafeReadSucideAcceptedSign() bool {
	return tdp.SucideAcceptedSign.Load()
}

// flip the sucide sign of accepted-queue
func (tdp *TDPControlBlock) SafeFlipSucideAcceptedSign() {
	tdp.SucideAcceptedSign.Store(!tdp.SafeReadSucideAcceptedSign())
}

// init the sucide sign of accepted-queue
func (tdp *TDPControlBlock) InitSucideAcceptedSign() {
	tdp.SucideAcceptedSign.Store(true)
}

/*
 *	END: Define for alias.
 */

// initialize the udpListener.
func (tdp *TDPControlBlock) InitLocalListener(udptype string, port uint16) (err error) {
	tdp.Listener, err = net.ListenUDP(udptype,
		&net.UDPAddr{IP: net.IPv6loopback, Port: int(port)})
	return
}

// read udp-flow and pass the content to parser to identify what the packet wants to convey.
func (tdp *TDPControlBlock) spinningReadFlows() {
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

// function for sequential writing.
func (tdp *TDPControlBlock) SafeWriteAny(msg []byte, addr *net.UDPAddr) (uint32, error) {
	tdp.WLock.Lock()
	cnt, err := tdp.Listener.WriteTo(msg, addr)
	tdp.WLock.Unlock()
	return uint32(cnt), err
}

func ReverseIDMessagefunctor(inp TDPItem) ReverseIDMessage {
	switch x := inp.(type) {
	case ReverseIDMessage:
		return x
	default:
		// use (0, nil) as invalid representation.
		return ReverseIDMessage{Idx: 0, Msg: nil}
	}
}

// return flag of (existed, convert well) and cnt
func (tdp *TDPControlBlock) testifyIDReverser(inp TDPMapKey) (isExisted, convertWell bool, cnt uint32) {
	_cnt, isExisted := tdp.IDreverser.Load(inp)
	cnt, convertWell = _cnt.(uint32)
	return
}

func (tdp *TDPControlBlock) addOneConnetionToHalfSync(
	curr_conn_id uint32, /* a newbie connection needs this. */
	record *TDPConn,
) {
	tdp.InnerSetsCnt[0].Add(1)
	cnt := tdp.InnerSetsCnt[0].Load()
	tdp.IDreverser.Store(TDPMapKey{choice: 0, idx: curr_conn_id}, cnt)
	tdp.InnerSets.Store(TDPMapKey{choice: 0, idx: cnt}, record)
}

// there must be such a record.
func (tdp *TDPControlBlock) removeOneConnectionFromHalfSync(record *TDPConn, cnt_in_set uint32) {
	tmp := TDPMapKey{choice: 0, idx: record.ID}
	tdp.InnerSets.Delete(TDPMapKey{choice: 0, idx: cnt_in_set})
	tdp.IDreverser.Delete(tmp)
}

// there must be such a record.
func (tdp *TDPControlBlock) removeOneConnectionFromAccepted(record *TDPConn, cnt_in_set uint32) {
	tmp := TDPMapKey{choice: 1, idx: record.ID}
	tdp.InnerSets.Delete(TDPMapKey{choice: 1, idx: cnt_in_set})
	tdp.IDreverser.Delete(tmp)
}

func (tdp *TDPControlBlock) addOneConnectionToAccepted(record *TDPConn) {
	tdp.InnerSetsCnt[1].Add(1)
	cnt := tdp.InnerSetsCnt[1].Load()
	tdp.IDreverser.Store(TDPMapKey{choice: 1, idx: record.ID}, cnt)
	tdp.InnerSets.Store(TDPMapKey{choice: 1, idx: cnt}, record)
}

// ! handshake cluster

func (tdp *TDPControlBlock) syn()       {}
func (tdp *TDPControlBlock) synAckPms() {}
func (tdp *TDPControlBlock) synAck()    {}
func (tdp *TDPControlBlock) synAckAvd() {}

// ! handwave cluster

func (tdp *TDPControlBlock) fin()       {}
func (tdp *TDPControlBlock) finAckPms() {}
func (tdp *TDPControlBlock) finAck()    {}
func (tdp *TDPControlBlock) finAckAvd() {}

/*
TODO: adjust pingRefTime by Cybernetics algorithm when necessary.

once timeout, remove item from corresponding queue via eventhandler.

	sender                                               receiver
	                         ping
	+-------------------------------------------------------->
	move receiver to halfsyncQueue; (typ,syn,pms),pmsval,seed1;
	+-------------------------------------------------------->
	                        if receiver has received, ping too
	<--------------------------------------------------------+
	send (typ,syn,ack,pms),pmsval,seed2; set sender to halfsync
	<--------------------------------------------------------+
	move receiver to acceptedQueue once received; (typ,syn,ack);seed3
	+-------------------------------------------------------->
	(typ,syn,ack,avd);seed4;if received,set sender to acceptedQueue
	<--------------------------------------------------------+

	one response during the stage of handshake.
	seal domain with 4 seed after handshake.

	+-------------------------------------------------------->
	+-------------------------------------------------------->
	                SEQ,ACK;stuck when send windows is full
	+-------------------------------------------------------->
			ack in advanced;(ack)(when timeout,use rck)
			( for sender, timeout resend packet 2 times
			 otherwise disconnect from receiver. )
	<--------------------------------------------------------+
	+-------------------------------------------------------->
					... next turn ...
	+-------------------------------------------------------->
	+-------------------------------------------------------->
	+-------------------------------------------------------->
		(rvd); message from upper application has completed
	+-------------------------------------------------------->
					ack in advanced;(ack,rvd)
	<--------------------------------------------------------+


					(typ,fin)
	+-------------------------------------------------------->
					(typ,ack,pms)
	<--------------------------------------------------------+
					(typ,fin,ack)
	<--------------------------------------------------------+
					(typ,fin,ack,avd)
	+-------------------------------------------------------->

For late, TODO: ignore by checking current state.

	To diminish the complexity, this function still needs narrowing to several new functions.
	We have gone too far...
*/
func (tdp *TDPControlBlock) bitsIdentifier(
	invoked_from __tdp_handler_id__,
	tdpConn *TDPConn,
	fresh_addr *net.UDPAddr,
	msg []byte,
) (shouldSkip bool) {
	shouldSkip = false
	_8bits_ := __tdp_bits__(msg[TDP_SYNTAX_BITS])

	/* functors */

	/* return true if invalid otherwise false. */
	seqack_faultChecker_SetBackWhenRight := func(msg []byte) bool {
		seq := utils.LittleEndianBytesToUint32([4]byte(msg[TDP_SYNTAX_SEQ:TDP_SYNTAX_ACK]))
		ack := utils.LittleEndianBytesToUint32([4]byte(msg[TDP_SYNTAX_ACK:TDP_SYNTAX_ADVANCK]))
		if tdpConn.Ack+1 != ack && tdpConn.Seq+1 != seq {
			return true
		}
		tdpConn.Seq, tdpConn.Ack = seq, ack
		return false
	}
	pmsBytes2int64_functor := func(pms_val [4]byte) int64 {
		sec := int64(pms_val[0]) | (int64(pms_val[1]&0x3) << 8)
		mil := int64(pms_val[1]>>2) | (int64(pms_val[2]&0xF) << 8)
		mic := int64(pms_val[2]>>4) | int64(pms_val[3]&0x3F)
		us := mic + mil*1000 + sec*1000000
		return us
	}
	digit2us_functor := func(RefTime uint32) time.Duration {
		return time.Duration(RefTime) * time.Microsecond
	}

	/* packet filter */
	switch _8bits_ {
	case TYP | RST:
		if invoked_from == HID_FRESH {
			shouldSkip = true
			return
		}
		// TODO: Validate ID before reset when possible.
		// check and remove.
		// TODO: prevent malicious attack from unknown sources.
		clear(tdpConn.SBuf)
		clear(tdpConn.RBuf)
		shouldSkip = true
		return

	case TYP | SYN | PMS:
		// TODO: duplicated packets sent from the same host while the first one does not complete.

		/* no tdpConn when dealing with current situation. */
		if invoked_from != HID_FRESH {
			shouldSkip = true
			return
		}
		// 电脑上都有防火墙，如果借助 ping 来探查，先前定的握手协议
		ping_ref, valid := PingWithoutPrint(fresh_addr.String(), 2, 8, 8, 5)
		if !valid {
			/* the validation of accessibility. */
			shouldSkip = true
			return
		}

		us := pmsBytes2int64_functor([4]byte(msg[TDP_SYNTAX_PMSVAL:TDP_SYNTAX_SEED]))
		if utils.ThresholdExceedCheckerViaRatio(ping_ref, us, 2, 3) {
			/* semanteme validation failed. */
			shouldSkip = true
			return
		}

		_seq := msg[TDP_SYNTAX_SEQ:TDP_SYNTAX_ACK]
		assigned_id := make([]byte, 4)
	regain:
		rand.Read(assigned_id)
		curr_conn_id := utils.LittleEndianBytesToUint32([4]byte(assigned_id))
		ok, _, _ := tdp.testifyIDReverser(TDPMapKey{choice: 0, idx: curr_conn_id})
		if ok {
			/* Guarantee the property of injective mapping. */
			goto regain
		}
		ok, _, _ = tdp.testifyIDReverser(TDPMapKey{choice: 1, idx: curr_conn_id})
		if ok {
			goto regain
		}
		mean_time := uint32((ping_ref + us)) >> 1

		seq := utils.LittleEndianBytesToUint32([4]byte(_seq))
		// TODO: set the seq by md5.Sum(seq||addr.string()||refTime)[4:] as seq.
		ack := utils.LittleEndianBytesToUint32([4]byte(_seq))

		record := &TDPConn{}
		record.SetAddr(fresh_addr).SetID(curr_conn_id).
			SetLocal(tdp.Listener).SetRefTime(mean_time).
			SetSeq(seq).SetAck(ack).SetCurrentState(uint32(SYNC1_1))

		var tmp [3]byte = [3]byte{}
		rand.Read(tmp[:]) // Generate seed for the sender.
		copy(record.Seed[3:6], tmp[:])
		copy(record.Seed[:3], msg[TDP_SYNTAX_SEED:TDP_SYNTAX_BOUNDARY])
		tdp.addOneConnetionToHalfSync(curr_conn_id, record)

		go func() {
			tdp.EventHandler.PushBack(
				record.SyncTimeout(0, 0, digit2us_functor(record.RefTime)))
		}()

		tdp.SafeWriteAny(FillHeader(
			curr_conn_id, seq, ack,
			0, 0, TYP|SYN|ACK|PMS,
			true, mean_time, tmp), tdpConn.Addr)
		return

	case TYP | SYN | ACK | PMS:
		state := tdpConn.CurrentState.Load()
		if invoked_from != HID_HALFSYNC &&
			/* todo: Should we add lock for each tdpConn? */
			state != uint32(SYNC1_2) {
			shouldSkip = true
			return
		}

		us := pmsBytes2int64_functor([4]byte(msg[TDP_SYNTAX_PMSVAL:TDP_SYNTAX_SEED]))

		if utils.ThresholdExceedCheckerViaRatio(int64(tdpConn.RefTime), us, 2, 3) ||
			seqack_faultChecker_SetBackWhenRight(msg) {
			/* semanteme validation failed. */
			shouldSkip = true
			return
		}

		tmp := TDPMapKey{choice: 0, idx: tdpConn.ID}
		ok, ok1, cnt := tdp.testifyIDReverser(tmp)
		if !ok || !ok1 {
			shouldSkip = true
			return
		}

		mean_time := (int64(tdpConn.RefTime) + us) / 2
		tdp.removeOneConnectionFromHalfSync(tdpConn, cnt)
		tdp.addOneConnectionToAccepted(tdpConn)
		copy(tdpConn.Seed[3:6], msg[TDP_SYNTAX_SEED:TDP_SYNTAX_BOUNDARY])
		tdpConn.CurrentState.Store(uint32(SYNC1_2))
		var tmp_seed [3]byte = [3]byte{}
		rand.Read(tmp_seed[:])
		copy(tdpConn.Seed[6:9], tmp_seed[:])

		go func() {
			tdpConn.AdmitChan[0] <- struct{}{} // feed the timeout channel.
			tdp.EventHandler.PushBack(
				tdpConn.SyncTimeout(0, 1, digit2us_functor(uint32(mean_time))))
		}()
		tdp.SafeWriteAny(FillHeader(
			tdpConn.ID, tdpConn.Seq, tdpConn.Ack,
			0, 0,
			TYP|SYN|ACK,
			true,
			0, tmp_seed), tdpConn.Addr)
		return

	case TYP | SYN | ACK:
		state := tdpConn.CurrentState.Load()
		if invoked_from != HID_ACCEPTED && state != uint32(SYNC1_2) && seqack_faultChecker_SetBackWhenRight(msg) {
			shouldSkip = true
			return
		}
		tmp := TDPMapKey{choice: 1, idx: tdpConn.ID}
		ok, ok1, _ := tdp.testifyIDReverser(tmp)
		if !ok || !ok1 {
			shouldSkip = true
			return
		}
		tdpConn.CurrentState.Store(uint32(SYNC2))
		tdpConn.AdmitChan[1] <- struct{}{}

		go func() {
			tdp.SafeWriteAny(FillHeader(
				tdpConn.ID, tdpConn.Seq, tdpConn.Ack,
				0, 0,
				TYP|SYN|ACK|ARV,
				true,
				0, [3]byte(tdpConn.Seed[3:6])), tdpConn.Addr)
		}()
		return

	case TYP | SYN | ACK | ARV:
		if invoked_from != HID_HALFSYNC && seqack_faultChecker_SetBackWhenRight(msg) {
			shouldSkip = true
			return
		}

		return
	case ACK | ARV:
		// notify the end of the current message.
		return
	case ACK:
		// both communication entities should change their seq, ack after handshake.

		return

	case RCK:
		// todo: feed data-timeout-channel
		return
	case TYP | FIN | RCK:
		return
	case TYP | FIN:
		return
	case TYP | FIN | ACK:
		return

	default:
		return true
	}
}

func (tdp *TDPControlBlock) homomorphyHandler(invoker __tdp_handler_id__) {
	var (
		selective_queue  *TDPQueue
		selective_choice uint32
		judger           func() bool
	)
	switch invoker {
	case HID_HALFSYNC:
		selective_queue = tdp.HalfSyncQueue
		selective_choice = 0
		judger = tdp.SafeReadSucideHalfSyncSign

	case HID_ACCEPTED:
		selective_queue = tdp.AcceptedQueue
		selective_choice = 1
		judger = tdp.SafeReadSucideAcceptedSign

	default:
		return
	}

	for judger() {
		// what if there is no producer any more and the executing flow stucks at here?
		raw_msg := selective_queue.PopFront()
		_msg := ReverseIDMessagefunctor(raw_msg)
		if _msg.Idx == 0 && _msg.Msg == nil {
			return
		}
		obj, ok1 := tdp.InnerSets.Load(TDPMapKey{choice: selective_choice, idx: _msg.Idx})
		if !ok1 {
			continue
		}
		tdpConn, ok2 := obj.(*TDPConn)
		// TODO: unseal flow for accepted connections.
		if !ok2 || tdp.bitsIdentifier(invoker, tdpConn, nil, _msg.Msg) {
			continue
		}
	}
}

func (tdp *TDPControlBlock) FreshHandler(addr *net.UDPAddr, msg []byte) {
	if uint32(len(msg)) != TDP_SYNTAX_BOUNDARY {
		return // drop this.
	}
	// drop duplicated (addr, port) before generating sessionID.
	if tdp.bitsIdentifier(HID_FRESH, nil, addr, msg) {
		return
	}
}

func (tdp *TDPControlBlock) timeoutClassifier(inp TDPTimeoutID) {
	tmp := TDPMapKey{choice: inp.QID, idx: inp.CID}
	ok1, ok2, cnt := tdp.testifyIDReverser(tmp)
	if !ok1 || !ok2 {
		return
	}
	switch inp.State {
	case PromoteConnTimeout:
		tdp.IDreverser.Delete(tmp)
		tdp.InnerSets.Delete(TDPMapKey{choice: inp.QID, idx: cnt})
	case PromotePackTimeout:
		_conn_handler, ok := tdp.InnerSets.Load(TDPMapKey{choice: tmp.choice, idx: cnt})
		if !ok {
			return
		}
		conn_handler, ok := _conn_handler.(*TDPConn)
		if !ok {
			return
		}
		if conn_handler.TimeoutCnt > 3 {
			tdp.removeOneConnectionFromAccepted(conn_handler, cnt)
			return
		}
		msg := conn_handler.SBuf[cnt].Msg
		// TODO: alternate msg.
		// resend packet and set rck bit.
		tdp.SafeWriteAny(append(
			FillHeader(
				conn_handler.ID,
				conn_handler.Seq+cnt, // TODO: keep Seq as the same after setting up connection and shift by cnt.
				conn_handler.Ack,     // TODO: how to maintain ACK?
				uint16(len(msg)), 0, ACK,
				false, 0, [3]byte{}), msg...),
			conn_handler.Addr)
	}
}

func (tdp *TDPControlBlock) EventAnalyzer() {
	for tdp.SucideEventSign.Load() {
		_item := tdp.EventHandler.PopFront()
		switch item := _item.(type) {
		default:
		case TDPTimeoutID:
			tdp.timeoutClassifier(item)
		}
	}
}

func (tdp *TDPControlBlock) parserFunctor(msg []byte, addr *net.UDPAddr) {
	if msg == nil || uint32(len(msg)) <= TDP_SYNTAX_BASICLIM {
		return
	}
	id := utils.LittleEndianBytesToUint32([4]byte(msg[:TDP_SYNTAX_DATALEN]))
	/*
		TODO: if there are any risks generated from tons of concurrency
				caused by malicious or undeliberate operation ?
	*/

	/* condition-1: accepted or late for certain transmission */
	_idx, ok := tdp.IDreverser.Load(TDPMapKey{choice: 1, idx: id})
	if ok {
		var inp []byte
		idx := _idx.(uint32)
		copy(inp, msg)
		go func() { tdp.AcceptedQueue.PushBack(ReverseIDMessage{idx, inp}) }()
		return
	}

	/* condition-2: half-connected or late during handshake */
	_idx, ok = tdp.IDreverser.Load(TDPMapKey{choice: 0, idx: id})
	if ok {
		// TODO: update addr when necessary.
		var inp []byte
		idx := _idx.(uint32)
		copy(inp, msg)
		go func() { tdp.HalfSyncQueue.PushBack(ReverseIDMessage{idx, inp}) }()
		return
	}

	/* condition-3: first come in or late?  */
	go func() { tdp.FreshHandler(addr, msg) }()
}

func (tdp *TDPControlBlock) singleFlowParser() {
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

func (tdp *TDPControlBlock) emptyChecker() bool {
	return tdp.EventHandler == nil || tdp.ParserQueue == nil ||
		tdp.HalfSyncQueue == nil || tdp.AcceptedQueue == nil
}

func (tdp *TDPControlBlock) Comprehensive(inner_monitor_fn func( /* remain to be designed */ )) {
	if tdp.emptyChecker() {
		tdp.initQueues()
	}
	var wg sync.WaitGroup
	wg.Add(5)
	wg_done := make(chan struct{})

	go func() { inner_monitor_fn(); wg.Done() }()
	go func() { tdp.singleFlowParser(); /* parser-loop */ wg.Done() }()
	go func() { tdp.homomorphyHandler(HID_HALFSYNC); /* halfsync-loop */ wg.Done() }()
	go func() { tdp.homomorphyHandler(HID_ACCEPTED); /* accepted-loop */ wg.Done() }()
	go func() { tdp.spinningReadFlows(); /* read-flows */ wg.Done() }()
	go func() { wg.Wait(); /* wait for terminated routines. */ wg_done <- struct{}{}; close(wg_done) }()

	select {
	/*
		case <-time.After(time.Hour * 24):
			log.Println(`wg-timeout.`)
			return
	*/
	case <-wg_done:
		return
	case <-tdp.ChShouldDie:
		log.Println(`received die signal`)
		return
	}
}

// brains melt...
