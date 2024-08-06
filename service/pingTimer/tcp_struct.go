package service

import (
	"bytes"
	"encoding/binary"
	"time"

	utils "bingoproxy/utils"
)

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

type TCPHeader struct {
	SPort      uint16
	DPort      uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8 // 4 bits
	Reserved   uint8 // 3 bits
	ECN        uint8 // 3 bits
	Ctrl       uint8 // 6 bits
	Window     uint16
	Checksum   uint16 // Kernel will set this if it's 0
	Urgent     uint16
	Options    []TCPOption
}

/*
BigEndian:
	1d ff							# Sport
	01 bb							# Dport
	5f 52 24 22						# SEQ
	00 00 00 00						# ACK
	a0 02							# headerLen/flag
	fa f0							# winSize
	67 df							# checkSum
	00 00							# urgentPointer
	# Options
	02 04 05 b4						# MSS 1460B
	01								# Nop
	03 03 08						# windowsScale
	04 02							# sack permitted
	08 0a 01 15 20 01 00 00 00 00	# timestampVal, time echo reply


Transmission Control Protocol, Src Port: 7679, Dst Port: 443, Seq: 0, Len: 0
    Source Port: 7679
    Destination Port: 443
    [Stream index: 5]
    [Conversation completeness: Incomplete, SYN_SENT (1)]
    [TCP Segment Len: 0]
    Sequence Number: 0    (relative sequence number)
    Sequence Number (raw): 1599218722
    [Next Sequence Number: 1    (relative sequence number)]
    Acknowledgment Number: 0
    Acknowledgment number (raw): 0
    1010 .... = Header Length: 40 bytes (10)
    Flags: 0x002 (SYN)
        000. .... .... = Reserved: Not set
        ...0 .... .... = Accurate ECN: Not set
        .... 0... .... = Congestion Window Reduced: Not set
        .... .0.. .... = ECN-Echo: Not set
        .... ..0. .... = Urgent: Not set
        .... ...0 .... = Acknowledgment: Not set
        .... .... 0... = Push: Not set
        .... .... .0.. = Reset: Not set
        .... .... ..1. = Syn: Set
        .... .... ...0 = Fin: Not set
        [TCP Flags: ··········S·]
    Window: 64240
    [Calculated window size: 64240]
    Checksum: 0x67df [correct] (matches partial checksum, not 0x2119, likely caused by "TCP checksum offload")
    [Checksum Status: Good]
    Urgent Pointer: 0
    Options: (20 bytes), Maximum segment size, No-Operation (NOP), Window scale, SACK permitted, Timestamps
    [Timestamps]
*/

const (
	TCP_FIN = 0b00_0001
	TCP_SYN = 0b00_0010
	TCP_RST = 0b00_0100
	TCP_PSH = 0b00_1000
	TCP_ACK = 0b01_0000
	TCP_URG = 0b10_0000
)

/*
	ethical hackers. Do not implement syn.
	TODO: migrate the corresponding logic from the method of measuring time or tcpping.
*/

func sendFin(remoteAddr, localAddr string) (time.Time, error) {
	return time.Time{}, nil
}

func sendNull(addr, localAddr string) (time.Time, error) {
	return time.Time{}, nil
}

var PingMethod = []func(addr, localAddr string) (time.Time, error){
	sendNull,
	sendFin,
}

//

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.SPort)
	binary.Read(r, binary.BigEndian, &tcp.DPort)
	binary.Read(r, binary.BigEndian, &tcp.Seq)
	binary.Read(r, binary.BigEndian, &tcp.Ack)

	var mixup uint16
	binary.Read(r, binary.BigEndian, &mixup)
	tcp.DataOffset = byte(mixup >> 12)  // top 4 bits
	tcp.Reserved = byte(mixup >> 9 & 7) // 3 bits
	tcp.ECN = byte(mixup >> 6 & 7)      // 3 bits
	tcp.Ctrl = byte(mixup & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

/*
Checksum for TCPIP protocol family.

	ipv6 supported.

*/
// Reference: https://www.rfc-editor.org/rfc/rfc1071
func TCPIPChecksum(data []byte, tag byte /* 0x11 udp, 0x06 tcp*/, srcIP, dstIP []byte) uint16 {
	pseudoHeader := []byte(srcIP)
	pseudoHeader = append(pseudoHeader, dstIP...)
	pseudoHeader = append(pseudoHeader, []byte{
		0x00, tag,
		byte(len(data) >> 8), byte(len(data)), /* TCP length (16 bits). not include pseudo header */
	}...)

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)

	lenSumThis := len(sumThis)
	var (
		nextWord uint16
		sum      uint32
	)
	for i := 0; lenSumThis > 0; {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
		i += 2
		lenSumThis -= 2
	}
	if lenSumThis&1 != 0 {
		sum += uint32(sumThis[len(sumThis)-1])
	}
	for (sum>>16)&0xFFFF != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(^sum)
}

func (tcp *TCPHeader) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.SPort)
	binary.Write(buf, binary.BigEndian, tcp.DPort)
	binary.Write(buf, binary.BigEndian, tcp.Seq)
	binary.Write(buf, binary.BigEndian, tcp.Ack)

	var mix uint16 = uint16(tcp.DataOffset)<<12 /* top 4 bits */ | uint16(tcp.Reserved)<<9 /* 3 bits */ |
		uint16(tcp.ECN)<<6 /* 3 bits */ | uint16(tcp.Ctrl) /* bottom 6 bits */

	binary.Write(buf, binary.BigEndian, mix)
	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

/*
do not set srcIP and dstIP to any kind of "192.168.1.1" or "::1", instead of
[]byte{0xC0, 0XA8, 0x01, 0x01}.
*/
func SetTcpHeader(srcIP, dstIP []byte, sportNum, dportNum uint16, ctrl uint8) []byte {
	// seq set by crypto-random.
	tmp := make([]byte, 4)
	utils.SetRandByte(&tmp)
	probePacket := TCPHeader{
		SPort:      sportNum,
		DPort:      dportNum,
		Seq:        utils.LittleEndianBytesToUint32([4]byte(tmp)),
		Ack:        0x0000_0000,
		DataOffset: 5, // 4 bits
		Reserved:   0, // 3 bits
		ECN:        0, // 3 bits
		Ctrl:       ctrl,
		Window:     0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:   0,      // Kernel will set this if it's 0
		Urgent:     0,
		Options:    []TCPOption{},
	}
	data := probePacket.Marshal()
	probePacket.Checksum = TCPIPChecksum(data, 0x06, srcIP /* big endian */, dstIP)
	data = probePacket.Marshal()
	return data
}
