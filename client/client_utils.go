//go:build windows || linux
// +build windows linux

// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package client

import (
	"net"
	"sync"

	cryptoprotect "bingoproxy/cryptoProtect"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
	socket "bingoproxy/socket"
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
	CompOption       cryptoprotect.CompOption

	wNeedBytes      chan []byte
	rDoneSignal     chan bool
	wNotifiedSignal chan bool

	rn          *protocol.HandShakeMsg
	ackTimCheck *[8][]byte
	pingRef     int64
	ackRec      int

	KeyLen, IvLen uint64
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
	enc, err := c.StreamCipher.EncryptFlow(plaintext)
	if err != nil {
		return 0, err
	}
	cnt, err := c.MiProxy.Write(enc)
	return cnt, err
}

func (c *Client) DecRead() ([]byte, uint, error) {
	enc, cnt, err := c.MiProxy.Read()
	if cnt <= 0 || err != nil {
		return []byte{}, 0, defErr.ConcatStr(err, `or read empty enc-bytes`)
	}
	dec, err := c.StreamCipher.DecryptFlow(enc)
	return dec, cnt, err
}

func (c *Client) sendPub() error {
	key_len := c.AsymmCipher.GetPubLen()
	key := make([]byte, key_len)
	c.AsymmCipher.GetPub(&key)
	var res_err error
	k, err := c.CompOption.CompressMsg(key)
	if err != nil {
		res_err = defErr.StrConcat(`compression failed`, err)
	}
	cnt, err := c.MiProxy.Write(k)
	if uint64(cnt) != key_len {
		res_err = defErr.StrConcat(`client sending failure`+err.Error()+`--`, res_err)
	}
	return res_err
}
