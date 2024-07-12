// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
// ACKNOWLEDGEMENT: oyto.github.io/2023/10/31/Go/项目实战/Go实现Ping操作/
package service

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	utils "bingoproxy/utils"
)

type icmpPacket struct {
	Type     uint8  //  8 \ ping
	Code     uint8  //  0 / request
	CheckSum uint16 // ICMPChecksum
	ID       uint16 // ID
	Seq      uint16 // Seq
}

func ICMPcheckSum(data []byte) uint16 {
	var sum uint32
	lena := len(data)
	for i := 0; i+1 < lena; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if lena&1 == 1 {
		sum += uint32(data[lena-1])
	}

	high := sum >> 16
	for high != 0 {
		sum = high + uint32(uint16(sum))
		high = sum >> 16
	}
	return uint16(^sum)
}

func cmpAndSetString[T uint | int64](backup T, curr T) string {
	if backup == curr {
		return `Unreachable`
	}
	return fmt.Sprintf("%v ms", curr)
}

func CheckConnectionByPing(dst_ip string, cnt uint16) (int64, bool) {
	conn, err := net.DialTimeout(`ip:icmp`, dst_ip, time.Duration(10)*time.Second)
	if err != nil {
		log.Println(`[ping.go-46]`, err)
		return -1, false
	}
	defer conn.Close()

	var (
		i           uint16
		buff        bytes.Buffer
		sok         int   = 0
		rok         int   = 0
		minnTime    uint  = ^uint(0)
		maxnTime    int64 = -1
		lstMinn     uint  = minnTime
		lstMaxn     int64 = maxnTime
		maxn_choice string
		minn_choice string
	)

	for i = 0; i < cnt; i++ {
		icmp := &icmpPacket{Type: 8, Code: 0, CheckSum: 0, ID: i, Seq: i}
		binary.Write(&buff, binary.BigEndian, icmp)
		payload := []byte(utils.GenerateEnterableRandomString(16))
		buff.Write(payload)
		payload = buff.Bytes()
		buff.Reset()
		checker := ICMPcheckSum(payload)
		payload[2], payload[3] = byte(checker>>8), byte(checker) // pad checksum

		st := time.Now()
		conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))

		_, err := conn.Write(payload)
		if err != nil {
			log.Println(`[ping.go-76]`, err)
			continue
		}
		sok += 1

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println(`[ping.go-84]`, err)
			continue
		}
		rok += 1
		t := time.Since(st).Milliseconds()

		log.Println(`From`, conn.RemoteAddr().String(),
			`len:`, n, `byte(s)`,
			`Time:`, t, `ms`,
			`TTL:`, buf[8])
		minnTime = utils.MinInt(minnTime, uint(t))
		maxnTime = utils.MaxInt(t, maxnTime)
		time.Sleep(time.Second)
	}
	maxn_choice = cmpAndSetString(lstMaxn, maxnTime)
	minn_choice = cmpAndSetString(lstMinn, minnTime)
	log.Println(`Recv/Total:`, rok, `/`, cnt,
		`Sent/Total:`, sok, `/`, cnt,
		`MaxTime:`, maxn_choice,
		`MinTime:`, minn_choice)
	if sok == 0 {
		return -1, false
	}
	return utils.MaxInt(lstMaxn, maxnTime), true
}

// return: average RTT(unit us) and the reachability result(true for accessable)
func PingWithoutPrint(
	dst_ip string,
	cnt uint16,
	conn_timeout_sec, pong_timeout_sec uint,
) (int64, bool) {
	switch dst_ip {
	// TODO: bad implementation!
	case `[::1]`:
		fallthrough
	case `127.0.0.1`:
		return 15500, true
	default:
	}
	conn, err := net.DialTimeout(`ip:icmp`, dst_ip, time.Duration(conn_timeout_sec)*time.Second)
	if err != nil {
		return -1, false
	}
	defer conn.Close()

	var (
		i        uint16
		buff     bytes.Buffer
		sok, rok       = 0, 0
		res_time int64 = 0
	)
	for i = 0; i < cnt; i++ {
		icmp := &icmpPacket{Type: 8, Code: 0, CheckSum: 0, ID: i, Seq: i}
		binary.Write(&buff, binary.BigEndian, icmp)
		payload := []byte(utils.GenerateEnterableRandomString(16))
		buff.Write(payload)
		payload = buff.Bytes()
		buff.Reset()
		checker := ICMPcheckSum(payload)
		payload[2], payload[3] = byte(checker>>8), byte(checker) // pad checksum

		st := time.Now()
		conn.SetDeadline(time.Now().Add(time.Duration(pong_timeout_sec) * 2 * time.Second))

		_, err := conn.Write(payload)
		if err != nil {
			continue
		}
		sok += 1

		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			continue
		}
		rok += 1
		res_time += time.Since(st).Microseconds()
	}
	if rok == 0 {
		return -1, false
	}
	return res_time / int64(cnt), true
}
