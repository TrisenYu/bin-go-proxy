//go:build windows || linux
// +build windows linux

// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package client

import (
	"net"
	"sync"

	cryptoprotect "selfproxy/cryptoProtect"
	defErr "selfproxy/defErr"
	"selfproxy/protocol"
	socket "selfproxy/socket"
)

type ExitFlag struct {
	ExitFlag bool          // new feature
	RWLock   *sync.RWMutex // concurrency control
}

type Client struct {
	MiProxy socket.Socket

	ProxyAsymmCipher cryptoprotect.AsymmCipher
	AsymmCipher      cryptoprotect.AsymmCipher
	StreamCipher     cryptoprotect.StreamCipher
	HashCipher       cryptoprotect.HashCipher

	wNeedBytes      chan []byte
	rDoneSignal     chan bool
	wNotifiedSignal chan bool

	rn          *protocol.ShakeHandMsg
	ackTimCheck [8][]byte
	ackRec      int
}

func (ef *ExitFlag) SafeReadState() bool {
	var res bool
	ef.RWLock.RLock()
	res = ef.ExitFlag
	ef.RWLock.RUnlock()
	return res
}

func (ef *ExitFlag) SafeFilpState() {
	ef.RWLock.Lock()
	if ef.ExitFlag {
		ef.ExitFlag = false
	} else {
		ef.ExitFlag = true
	}
	ef.RWLock.Unlock()
}

var (
	LocalInterceptor net.Listener // message source
	LocalClient      Client       // might be used as local flow-proxy entity in the future
	JudExitFlag      ExitFlag     = ExitFlag{ExitFlag: false, RWLock: new(sync.RWMutex)}
)

func (c *Client) InitChannel() {
	c.rDoneSignal = make(chan bool)
	c.wNotifiedSignal = make(chan bool)
	c.wNeedBytes = make(chan []byte)
}

func (c *Client) DeleteChannel() {
	close(c.rDoneSignal)
	close(c.wNotifiedSignal)
	close(c.wNeedBytes)
}

func (c *Client) EncWrite(plaintext []byte) (uint, error) {
	enc := c.StreamCipher.FlipFlow(plaintext)
	cnt, err := c.MiProxy.Write(enc)
	return cnt, err
}

func (c *Client) DecRead() ([]byte, uint, error) {
	enc, cnt, err := c.MiProxy.Read()
	if cnt == 0 || err != nil {
		return []byte(``), 0, defErr.Concat(err, `or read empty enc-bytes`)
	}
	dec := c.StreamCipher.FlipFlow(enc)
	return dec, cnt, nil
}

func (c *Client) sendPub() error {
	key_len := c.AsymmCipher.GetPubLen()
	key := make([]byte, key_len)
	c.AsymmCipher.GetPub(&key)
	cnt, err := c.MiProxy.Write(key)
	if uint64(cnt) != key_len {
		err = defErr.DescribeThenConcat(`client sending failure`, err)
	}
	return err
}
