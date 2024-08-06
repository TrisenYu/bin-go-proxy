package service

import (
	"net"
	"sync/atomic"
	"time"
)

type (
	UntrustedConn struct {
		Addr   *net.UDPAddr
		State  atomic.Uint32
		Cookie []byte
	}
	TDPConn struct {
		Addr         *net.UDPAddr
		Local        *net.UDPConn
		ID, RefTime  uint32
		Seq, Ack     uint32
		CurrentState atomic.Uint32
		XorKey       [3]byte
		TimeoutCnt   byte // Strikeouts
		Seed         [12]byte
		/*
			for sendbuf and receive buffer, both of them need to set deadline for each packet.
		*/
		SBuf, RBuf []TDPPacket
		AdmitChan  [2]chan struct{}
		ShouldDie  chan struct{} // feature: proactively abort connection.
	}
)

func (tdp *TDPConn) SyncTimeout(qid __sync_state__, which_end uint32, expired time.Duration) interface{} {
	timer := time.NewTimer(expired)
	select {
	case <-timer.C:
		return TDPTimeoutID{CID: tdp.ID, QID: uint32(qid), State: PromoteConnTimeout}
	case res := <-tdp.AdmitChan[which_end]:
		timer.Stop()
		return res
	}
}

func (tdp *TDPConn) PacketTimeout(
	qid __sync_state__,
	isInSendBuf bool,
	packetID uint32,
	expired time.Duration,
) interface{} {
	timer := time.NewTimer(expired)
	var target_ch *chan struct{}
	if isInSendBuf {
		target_ch = &tdp.SBuf[packetID].ChNotify
	} else {
		target_ch = &tdp.RBuf[packetID].ChNotify
	}
	select {
	case <-timer.C:
		tdp.TimeoutCnt += 1
		return TDPTimeoutID{QID: uint32(qid), CID: tdp.ID, PID: packetID, State: PromoteConnTimeout}
	case res := <-*target_ch:
		timer.Stop()
		close(*target_ch) // once receive, we shall close.
		return res
	}
}

func (tdp *TDPConn) SetAddr(addr *net.UDPAddr) *TDPConn {
	tdp.Addr = addr
	return tdp
}

func (tdp *TDPConn) SetLocal(conn *net.UDPConn) *TDPConn {
	tdp.Local = conn
	return tdp
}

func (tdp *TDPConn) SetID(id uint32) *TDPConn {
	tdp.ID = id
	return tdp
}

func (tdp *TDPConn) SetRefTime(ref uint32) *TDPConn {
	tdp.RefTime = ref
	return tdp
}

func (tdp *TDPConn) SetSeq(seq uint32) *TDPConn {
	tdp.Seq = seq
	return tdp
}

func (tdp *TDPConn) SetAck(ack uint32) *TDPConn {
	tdp.Ack = ack
	return tdp
}

func (tdp *TDPConn) SetXorKey(xorkey [3]byte) *TDPConn {
	tdp.XorKey = xorkey
	return tdp
}

func (tdp *TDPConn) SetCurrentState(state uint32) *TDPConn {
	tdp.CurrentState.Store(state)
	return tdp
}

func (tdp *TDPConn) SetSeed(seed [12]byte) *TDPConn {
	tdp.Seed = seed
	return tdp
}

/* For single tdp connection */

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
