// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
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

	return true, `ok` if two bytesSlices are equal, otherwise return false with the reason.
*/
func CompareByteSliceEqualOrNot(a []byte, b []byte) (bool, string) {
	lena, lenb := len(a), len(b)
	if lena != lenb {
		return false, fmt.Sprintf(`unequal: differentLen found:(%d,%d)`, lena, lenb)
	}
	for idx, val := range a {
		if val != b[idx] {
			return false, fmt.Sprintf(`unequal: differentVal found at:%d`, idx)
		}
	}
	return true, `ok`
}

/*
generate pseudo-random number between assigned parameter `min` and assigned parameter `max`.
*/
func generateRandomIntNumber(min int, max int) int {
	rand.New(rand.NewSource(time.Now().Unix()))
	return rand.Intn(max-min+1) + min
}

/*
Deprecated.

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

func Uint64ToLittleEndianBytes(inp uint64) []byte {
	var res []byte
	for i := 0; i < 8; i++ {
		res = append(res, byte((inp>>(i<<3))&0xFF))
	}
	return res
}

func Uint32ToLittleEndianBytes(inp uint32) []byte {
	return []byte{byte(inp), byte(inp >> 8), byte(inp >> 16), byte(inp >> 24)}
}

func Uint16ToLittleEndianBytes(inp uint16) []byte {
	return []byte{byte(inp), byte(inp >> 8)}
}

func LittleEndianBytesToUint16(inp [2]byte) (res uint16) {
	var functor func(byte, int) uint16 = func(b byte, i int) uint16 { return uint16(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8)
	return
}

func LittleEndianBytesToUint32(inp [4]byte) (res uint32) {
	var functor func(byte, int) uint32 = func(b byte, i int) uint32 { return uint32(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8) | functor(inp[2], 16) | functor(inp[3], 24)
	return
}

func LittleEndianBytesToUint64(inp [8]byte) (res uint64) {
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
		return []byte{}, []byte{}
	}
	portion := generateRandomIntNumber(50, 60)
	return a[:portion*lena/100], a[portion*lena/100:]
}

type _Intx interface {
	~uint | ~int | ~int32 | ~uint32 | ~int64 | ~uint64 | ~uint16 | ~int16
}

// get the distance from two (u)int(x) numbers.
func AbsMinusInt[T _Intx](a T, b T) T {
	return max(a, b) - min(a, b)
}

// get absolute path of current `utils.go`
func GetRunPath() (string, error) {
	path, err := filepath.Abs(filepath.Dir(os.Args[0]))
	return path, err
}

func GetFilePath(inp string) (string, error) {
	return filepath.Abs(filepath.Dir(inp))
}

// Debug function used for dumping hex representation of a byte slice.
// Timestamp attached ahead.
func BytesHexForm(inp []byte) {
	if len(inp) == 0 {
		log.Println(0)
		return
	}
	log.Println(hex.EncodeToString(inp))
}

func ThresholdExceedCheckerViaRatio[T _Intx](
	ref, gain, numer, denom T,
) bool {
	return AbsMinusInt(ref, gain)*numer >= denom*ref
}
