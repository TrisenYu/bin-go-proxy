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
compare whether two byte slices are the same.
return true, `ok` if true, otherwise return false and the reason.
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
generate pseudo-random number between assigned parameter `min` and assigned parameter `max`.
*/
func generateRandomNumber(min int, max int) int {
	rand.New(rand.NewSource(time.Now().Unix()))
	return rand.Intn(max-min+1) + min
}

/*
Deprecated

	 `tester` must be in the shape like `[ipv6]:port` or `ipv4:port` or `domain:port`.

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

// generate pseudo-random string
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

/*
Interlocking

	The function accepts a byte slice as its sole input and
	divides it into two-byte slices with a probability between 0.5 and 0.6 .
*/
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

// get absolute path of current file
func GetRunPath() (string, error) {
	path, err := filepath.Abs(filepath.Dir(os.Args[0]))
	return path, err
}

func GetFilePath(inp string) (string, error) {
	return filepath.Abs(filepath.Dir(inp))
}

// debug function used for dumping hex representation of a byte slice.
func BytesHexForm(inp []byte) {
	if len(inp) == 0 {
		log.Println(0)
		return
	}
	log.Println(hex.EncodeToString(inp))
}
