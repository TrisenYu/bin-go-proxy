// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"errors"
	"net"
	"os"
	"path/filepath"
)

// get absolute path of current `utils.go`
func GetRunPath() (string, error) {
	path, err := filepath.Abs(filepath.Dir(os.Args[0]))
	return path, err
}

func GetFilePath(inp string) (string, error) {
	return filepath.Abs(filepath.Dir(inp))
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

/*
Interlocking

	The function accepts a byte slice as its sole input and
	divides it into two-byte slices with a probability between 0.5 and 0.6 .
*/
func BytesSplitInHalfChanceField(a []byte) ([]byte, []byte) {
	lena := len(a)
	if lena < 1 {
		return []byte{}, []byte{}
	}
	portion := generateRandomIntNumber(50, 60)
	return a[:portion*lena/100], a[portion*lena/100:]
}

func ThresholdExceedCheckerViaRatio[T _Intx](
	ref, gain, numer, denom T,
) bool {
	return AbsMinusInt(ref, gain)*numer >= denom*ref
}
