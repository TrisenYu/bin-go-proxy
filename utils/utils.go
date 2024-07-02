// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"encoding/hex"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

const letters string = "qewr4560tyuiopadsfgh123jklzxcvbnmQWERTY789UIOPASDFGHJKLZCXVBNM"

/*
比较两字节串是否一致。相同返回真，否则鉴定为假。

	风险：时间的侧信道攻击。规避侧信道攻击 => 性能下降。
*/
func CompareByteArrEQ(a []byte, b []byte) (bool, string) {
	if len(a) != len(b) {
		return false, `Len: uneq`
	}
	for idx, val := range a {
		if val != b[idx] {
			return false, `Val: uneq`
		}
	}
	return true, `ok`
}

/*
生成指定范围内的伪随机数。

	如 1024~65535 范围内的端口包括注册端口（1024 - 49151）和动态或私有端口（49152 - 65535）。
*/
func generateRandomNumber(min int, max int) int {
	rand.New(rand.NewSource(time.Now().Unix()))
	return rand.Intn(max-min+1) + min
}

/*
Deprecated

参数 `tester` 必须是 `[ipv6]:port` 或 `ipv4:port` 或 `domain:port` 的形式.

	return: conn-dst:port, recommend-protocol err
*/
func CheckAddrType(tester string) (string, string, error) {
	if len(tester) == 0 {
		return ``, "unsupported", errors.New("bad param: " + tester)
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", tester)
	if err != nil {
		udpAddr, err := net.ResolveUDPAddr("udp", tester)
		if err != nil {
			return ``, "unsupported", err
		}
		return udpAddr.IP.String(), "udp", nil
	}
	return tcpAddr.IP.String(), "tcp", nil
}

// 生成伪随机字符串
func GenerateEnterableRandomString(lena int64) string {
	rand.New(rand.NewSource(lena))
	res := make([]byte, lena)
	for i := range res {
		res[i] = letters[(rand.Int63n(lena))%int64(len(letters))]
	}
	return string(res)
}

func Uint64ToBytesInLittleEndian(inp uint64) []byte {
	var res []byte
	for i := 0; i < 8; i++ {
		res = append(res, byte((inp>>(i<<3))&0xFF))
	}
	return res
}

func Uint32ToBytesInLittleEndian(inp uint32) []byte {
	var res []byte
	for i := 0; i < 4; i++ {
		res = append(res, byte((inp>>(i<<3))&0xFF))
	}
	return res
}

func Uint16ToBytesInLittleEndian(inp uint16) []byte {
	var res []byte
	for i := 0; i < 2; i++ {
		res = append(res, byte((inp>>(i<<3))&0xFF))
	}
	return res
}

func BytesToUint16(inp [2]byte) (res uint16) {
	var functor func(byte, int) uint16 = func(b byte, i int) uint16 { return uint16(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8)
	return
}

func BytesToUint32(inp [4]byte) (res uint32) {
	var functor func(byte, int) uint32 = func(b byte, i int) uint32 { return uint32(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8) | functor(inp[2], 16) | functor(inp[3], 24)
	return
}

func BytesToUint64(inp [8]byte) (res uint64) {
	var functor func(byte, int) uint64 = func(b byte, i int) uint64 { return uint64(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8) | functor(inp[2], 16) | functor(inp[3], 24)
	res |= functor(inp[4], 32) | functor(inp[5], 40) | functor(inp[6], 48) | functor(inp[7], 56)
	return
}

/* 0.5 到 0.6 的概率划分字节串为两段。用于联锁握手。 */
func BytesSpliterInHalfChanceField(a []byte) ([]byte, []byte) {
	lena := len(a)
	if lena < 1 {
		return []byte(``), []byte(``)
	}
	portion := generateRandomNumber(50, 60)
	return a[:portion*lena/100], a[portion*lena/100:]
}

func MaxInt[T ~uint | ~int | ~int32 | ~uint32 | ~int64 | ~uint64 | ~uint16 | ~int16](a T, b T) T {
	flag := a > b
	if flag {
		return a
	}
	return b
}

func MinInt[T ~uint | ~int | ~int32 | ~uint32 | ~int64 | ~uint64 | ~uint16 | ~int16](a T, b T) T {
	flag := a < b
	if flag {
		return a
	}
	return b
}

// 获取程序执行的绝对路径
func GetRunPath() (string, error) {
	path, err := filepath.Abs(filepath.Dir(os.Args[0]))
	return path, err
}

func GetFilePath(inp string) (string, error) {
	return filepath.Abs(filepath.Dir(inp))
}

// 调试函数。输出字节串的十六进制。
func BytesHexForm(inp []byte) {
	if len(inp) == 0 {
		log.Println(0)
		return
	}
	log.Println(hex.EncodeToString(inp))
}
