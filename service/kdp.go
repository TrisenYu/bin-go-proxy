// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"net"
	"time"
)

/*
udp + 可靠传输。传数据包又要用到 Socket.Sock

Conn is a generic stream-oriented network connection.

Multiple goroutines may invoke methods on a Conn simultaneously.
*/
type (
	KCP struct{}
)

// 可靠读
func (kcp *KCP) Read(b []byte) (n int, err error) {
	return 0, nil
}

// 可靠写
func (kcp *KCP) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (kcp *KCP) Close() error {
	return nil
}

func (kcp *KCP) LocalAddr() net.Addr {
	return nil
}

func (kcp *KCP) RemoteAddr() net.Addr {
	return nil
}

func (kcp *KCP) SetWriteDeadline(t time.Time) error {
	return nil
}

func (kcp *KCP) SetDeadline(t time.Time) error {
	return nil
}

func (kcp *KCP) SetReadDeadline(t time.Time) error {
	return nil
}
