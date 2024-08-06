// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"errors"
	"fmt"
	"net"

	"bingoproxy/defErr"
)

type IPType int

const (
	InvalidIPType IPType = iota - 1
	_
	_
	_
	_
	IPv4Addr
	_
	IPv6Addr
)

// IPType is int actually.
func CheckIpType(addr string) (IPType, error) {
	_ip := net.ParseIP(addr)
	if _ip == nil {
		return InvalidIPType, errors.New(`invalid address`)
	}
	if _ip.To4() != nil {
		return IPv4Addr, nil
	} else if _ip.To16() != nil {
		return IPv6Addr, nil
	}
	return InvalidIPType, errors.New(`unknown error while testifying address`)
}

// convert address string to address byte slices. if failed, attach an error after nil slice.
func AddrStrToSlice(addr string) ([]byte, error) {
	_ip := net.ParseIP(addr)
	if _ip == nil {
		return nil, errors.New(`invalid addr was provided`)
	}
	// we shall convert the "xxx.xxx.xxx.xxx" to xxx, xxx, xxx, xxx. in bytes sequence.

	ip, err := net.ResolveIPAddr("ip:tcp", addr)

	return ip.IP[:], err
}

// Find the position splite network Address and Port.
func FindPosCutNetworkAddrPort(addr string) int {
	var res int
	lena := len(addr)
	for i := lena - 1; i > 0; i-- {
		if addr[i] == ':' {
			res = i
			return res
		}
	}
	// bad addr:port.
	return -1
}

func SplitAddrPort(addr string) (string, string, int) {
	pos := FindPosCutNetworkAddrPort(addr)
	if pos == -1 {
		return ``, ``, pos
	}
	return addr[:pos], addr[pos+1:], pos
}

// Address passing to current function should be in the shape of `ip:port`.
// extra return val: position that splits the
func SplitAddrSlicePortUint16(addr string) ([]byte, uint16, int, error) {
	_addr, _port, pos := SplitAddrPort(addr)
	if len(_addr) == 0 && len(_port) == 0 {
		return nil, 0, -1, errors.New(`invalid addr`)
	}
	var port uint16
	_, err := fmt.Sscanf(_port, "%d", &port)
	if err != nil {
		return nil, 0, -1, defErr.StrConcat(`invalid Port due to:`, err)
	}
	addrSlice, err := AddrStrToSlice(_addr)
	if err != nil {
		return nil, 0, -1, err
	}
	return addrSlice, port, pos, nil
}
