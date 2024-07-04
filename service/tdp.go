// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"crypto/rand"
	"errors"
	"net"
	"time"

	"selfproxy/utils"
)

/*
udp + trusted transmission

Conn is a generic stream-oriented network connection.
Multiple goroutines may invoke methods on a Conn simultaneously.

TODO: bypass ISP QoS
*/
type (
	TDP struct {
		seq_st    uint32
		seq_ofs   uint32
		ack_st    uint32
		ack_ofs   uint32
		shakehand uint32

		ref_time      uint32
		ref_time_unit uint8

		udp_conn net.UDPConn

		RecvBuf *[]byte
		SendBuf *[]byte
	}
)

/*
The windows size or group size is intensionally fixed to 64 for simplifying
the process of adjusting windows size, congestion control and fast retransmission.
And the tcp preamble will be tailored and reduced for maintaining trusted transmission.

For synchronizing flood:

	Ping-pong operation is required for measuring approximately RTT to form a promised Time windows.
	If any communication parties violates against the time windows they promised or the time windows is irrational,
	the receiver can immediately abort connection or add ip to blacklist.

For finishing scanning:

	Firewall can handle this well by ignoring. Or all the ports send rst packet.

For TCP-Land attack:

	Firewall can detect this malicious network-flow.
	      4 bytes
	4 bytes              000 n
	n     n    b b b b b 001 u
	_u     u   i i i i i 010 m uint64 uint32
	_ m     m  t t t t t 011 s 8 bytes
	_  b     b           1 min
	+----+----+-+-+-+-+-+----+--------+----+------+
	|S   |A   |a|r|s|p|f|time|current |Prom|pad   |
	|  E |  C |c|s|y|m|i|    | group  |ise-|  3   |
	|   Q|   K|k|t|n|s|n|unit|recv-num|time| bytes|
	+----+----+-+-+-+-+-+----+--------+----+------+

This preamble can be compressed after successfully handshake.

		4 bytes
	4 bytes
	n     n
	_u     u           unsigned
	_ m     m  B Y T E  8 bytes
	_  b     b
	+----+----+-+-+-+-+--------+------+
	|S   |A   |a|r|s|f|current |pad   |
	|  E |  C |c|s|y|i| group  |  3   |
	|   Q|   K|k|t|n|n|recv-num| bytes|
	+----+----+-+-+-+-+--------+------+
*/
type (
	header_bit_domain byte
	TDPpreamble       struct {
		SEQ, ACK      uint32
		BitsDomain    byte
		PromiseTime   uint32
		RecvCondition uint64
	}
)

func (tdph *TDPpreamble) Bytes(IsShakingHandNow bool) []byte {
	res1 := utils.Uint32ToBytesInLittleEndian(tdph.SEQ)
	res2 := utils.Uint32ToBytesInLittleEndian(tdph.ACK)
	res3 := utils.Uint64ToBytesInLittleEndian(tdph.RecvCondition)
	res1 = append(res1, res2...)
	res1 = append(res1, tdph.BitsDomain)
	if IsShakingHandNow {
		res4 := utils.Uint32ToBytesInLittleEndian(tdph.PromiseTime)
		res1 = append(res1, res4...)
	}
	res1 = append(res1, res3...)
	res1 = append(res1, "\x00\x00\x00"...)
	return res1
}

const (
	_ack              header_bit_domain = 128
	_rst              header_bit_domain = 64
	_syn              header_bit_domain = 32
	_pms              header_bit_domain = 16
	_fin              header_bit_domain = 8
	_shield_time_mask                   = uint8(0xF0)
	_ns               header_bit_domain = 0
	_us               header_bit_domain = 1
	_ms               header_bit_domain = 2
	_sec              header_bit_domain = 3
	_min              header_bit_domain = 4

	GroupSize int    = 64
	RECV_ALL  uint64 = ^uint64(0)
)

func (tdp *TDP) pingRequest() bool {
	ref_time, flag := PingWithoutPrint(tdp.RemoteAddr().String(), 3, 10, 5)
	if !flag {
		return false
	}
	tdp.ref_time = uint32(ref_time)
	tdp.ref_time_unit = byte('m') // standard form.
	return true
}

func (tdp *TDP) wrapHeader(domain_bit header_bit_domain) ([]byte, error) {
	var header TDPpreamble
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

	return header.Bytes(tdp.shakehand == 0), nil
}

func (tdp *TDP) parseHeader(msg []byte) (func(inp []byte), error) {
	if len(msg) != 20 && len(msg) != 24 {
		return nil, errors.New(`invalid preamble`)
	}
	if tdp.shakehand == 0 { // yet to set up connection.
		seq, ack := utils.BytesToUint32([4]byte(msg[:4])), utils.BytesToUint32([4]byte(msg[4:8]))
		// compare with current seq and ack
		bits_domain := msg[8]

		// todo: when to change seq_ofs and ack_ofs?
		if ack != tdp.seq_st+tdp.seq_ofs {
			return nil, errors.New(`invalid ack`)
		}

		if seq != tdp.ack_st+tdp.ack_ofs {
			return nil, errors.New(`invalid seq`)
		}

		switch bits_domain & _shield_time_mask {
		case byte(_rst):
			// abort connection
		case byte(_syn | _pms):
			// request for set up connection
		case byte(_syn | _ack):
			// the second ack of client
		case byte(_fin):
			// request for four-way handshake
		case byte(_fin | _ack):
			// the thrid stage of four-way handshake
		case byte(_ack):
			/*
				a complicated classification
				i) normal user data;
				ii) the thrid stage during handshake;
				iii) the second stage during four-way handshake;
				iv) the thrid stage during four-way handshake.
			*/
		default:
			return nil, errors.New(`invalid protocol state`)
		}
	}
	return nil, nil
}

func (tdp *TDP) resendPacket(msg []byte) {
	tdp.udp_conn.Write(msg)
	// I am not sure if this will work.
}

func (tdp *TDP) checkACK() {
}

func (tdp *TDP) readACK() {
	// the ack should indicated the last group state and the current loss condition
}

func (tdp *TDP) sendACK() {
}

func (tdp *TDP) setupConn() {
	if !tdp.pingRequest() {
		tdp.udp_conn.Close()
		return
	}
	init_payload, err := tdp.wrapHeader(_syn) // shakehand does not need to carry basic data.
	if err != nil {
		tdp.udp_conn.Close()
		return
	}
	// TODO: timeout setting
	_, err = tdp.udp_conn.Write(init_payload)
	if err != nil {
		tdp.udp_conn.Close()
		return
	}
	tdp.shakehand = 1
	// syn, seq, promisedTime
}

func (tdp *TDP) finishConn() {}

func (tdp *TDP) connectionFilter() {
}

// trusted read
func (tdp *TDP) Read(b []byte) (n int, err error) {
	return 0, nil
}

// trusted write
func (tdp *TDP) Write(b []byte) (n int, err error) {
	if tdp.shakehand == 0 {
		tdp.setupConn()
	}
	return 0, nil
}

func (tdp *TDP) Close() error {
	return nil
}

func (tdp *TDP) LocalAddr() net.Addr {
	return tdp.udp_conn.LocalAddr()
}

func (tdp *TDP) RemoteAddr() net.Addr {
	return tdp.udp_conn.RemoteAddr()
}

func (tdp *TDP) SetWriteDeadline(t time.Time) error {
	return nil
}

func (tdp *TDP) SetDeadline(t time.Time) error {
	return nil
}

func (tdp *TDP) SetReadDeadline(t time.Time) error {
	return nil
}
