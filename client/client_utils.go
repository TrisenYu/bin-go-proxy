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
	LocalInterceptor net.Listener // 全局信源
	LocalClient      Client       // 凭此寻找代理
	JudExitFlag      ExitFlag     = ExitFlag{ExitFlag: false, RWLock: new(sync.RWMutex)}
)

func (c *Client) InitChannel() {
	c.rDoneSignal = make(chan bool)
	c.wNotifiedSignal = make(chan bool)
	c.wNeedBytes = make(chan []byte)
}

// panic 或者处理完其它确定整套程序不用而正常退出时再用。
func (c *Client) DeleteChannel() {
	close(c.rDoneSignal)
	close(c.wNotifiedSignal)
	close(c.wNeedBytes)
}

// 会话使用 ZUC 流密码加密。加密本地的信息传给代理解密。
func (c *Client) EncWrite(plaintext []byte) (uint, error) {
	enc := c.StreamCipher.FlipFlow(plaintext)
	// enc := cryptoprotect.ZUCFlipFlow(plaintext, c.Key[:], c.Iv[:])
	cnt, err := c.MiProxy.Write(enc)
	return cnt, err
}

// 会话使用流密码加密。解密代理传回的加密内容
func (c *Client) DecRead() ([]byte, uint, error) {
	enc, cnt, err := c.MiProxy.Read()
	if cnt == 0 || err != nil {
		return []byte(``), 0, defErr.Concat(err, `or read empty enc-bytes`)
	}
	dec := c.StreamCipher.FlipFlow(enc)
	return dec, cnt, nil
}

func (c *Client) sendPub() error {
	key := make([]byte, 65)
	c.AsymmCipher.GetPub(&key)
	cnt, err := c.MiProxy.Write(key)
	if cnt != 65 {
		err = defErr.DescribeThenConcat(`client sending failure`, err)
	}
	return err
}
