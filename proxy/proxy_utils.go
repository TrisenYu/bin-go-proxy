// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package proxy

import (
	"errors"
	"io"

	cryptoprotect "bingoproxy/cryptoProtect"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
	socket "bingoproxy/socket"
)

type EncFlowProxy struct {
	ClientAsymmCipher cryptoprotect.AsymmCipher
	AsymmCipher       cryptoprotect.AsymmCipher
	StreamCipher      cryptoprotect.StreamCipher
	HashCipher        cryptoprotect.HashCipher
	CompOption        cryptoprotect.CompOption

	Client socket.Socket
	Remote socket.Socket

	remote_info *ClientControlMsg

	// concurrency control
	wNeedBytes chan []byte
	rpk        *protocol.HandShakeMsg
	rSignal    chan bool

	// check for timestamp
	ackTimCheck   *[8][]byte
	pingRef       int64
	ackRec        int
	KeyLen, IvLen uint64
}

func (p *EncFlowProxy) InitChannel() {
	p.rSignal = make(chan bool)
	p.wNeedBytes = make(chan []byte)
}

func (p *EncFlowProxy) DeleteChannel() {
	close(p.rSignal)
	close(p.wNeedBytes)
}

func (p *EncFlowProxy) SendPub() error {
	key_len := p.AsymmCipher.GetPubLen()
	key := make([]byte, key_len)
	p.AsymmCipher.GetPub(&key)
	var res_err error
	k, err := p.CompOption.CompressMsg(key)
	if err != nil {
		res_err = defErr.StrConcat(`compression failed`, err)
	}
	cnt, err := p.Client.Write(k)
	if cnt != uint(len(k)) || err != nil {
		res_err = defErr.StrConcat(`sending interrupts `+err.Error()+`--`, err)
	}
	return res_err
}

func (ep *EncFlowProxy) EncWrite2Client(plaintext []byte) (uint, error) {
	enc, err := ep.StreamCipher.EncryptFlow(plaintext)
	if err != nil {
		return 0, err
	}
	cnt, err := ep.Client.Write(enc)
	return cnt, err
}

func (ep *EncFlowProxy) DecReadViaClient() ([]byte, uint, error) {
	enc, cnt, err := ep.Client.Read()
	if cnt <= 0 || err != nil {
		return []byte{}, 0, errors.Join(err, errors.New(`got empty enc-string from client`))
	}
	dec, err := ep.StreamCipher.DecryptFlow(enc)
	return dec, cnt, err
}

func (p *EncFlowProxy) SendRemote(msg []byte) (uint, error) {
	cnt, err := p.Remote.Write(msg)
	return cnt, err
}

func (p *EncFlowProxy) ReadRemote() ([]byte, uint, error) {
	buf, cnt, err := p.Remote.Read()
	return buf, cnt, err
}

/* todo: Test all */
func (p *EncFlowProxy) RR2CS() (uint, error) {
	var final_msg []byte
	for {
		msg, _, err := p.ReadRemote()
		final_msg = append(final_msg, msg...)
		if err == io.EOF {
			break
		}
	}
	res := WrapWithHeader(final_msg, 'D')
	cnt, err := p.EncWrite2Client(res)
	return cnt, err
}

/* todo: Test all */
func (p *EncFlowProxy) CS2RR() error {
	pack, _, err := p.DecReadViaClient()
	if err != nil {
		return err
	}
	_, err = p.SendRemote(pack)
	return err
}
