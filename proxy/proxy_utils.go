// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package proxy

import (
	"errors"
	"io"

	cryptoprotect "selfproxy/cryptoProtect"
	defErr "selfproxy/defErr"
	protocol "selfproxy/protocol"
	socket "selfproxy/socket"
)

/*
代理端抽象成多个代理流。

代理过程：
  - 与接入的客户端握手形成会话密钥；
  - 转发流量告知报文类型（上层应用的对应相应，以及代理的通信反馈。）以让客户端正确处理。
  - 注意释放内存。
*/
type EncFlowProxy struct {
	// 以下分别使用非对称密码、流密码、散列哈希的接口来操控不同选择下的加解密。
	ClientAsymmCipher cryptoprotect.AsymmCipher
	AsymmCipher       cryptoprotect.AsymmCipher
	StreamCipher      cryptoprotect.StreamCipher
	HashCipher        cryptoprotect.HashCipher

	Client socket.Socket
	Remote socket.Socket

	remote_info *ClientControlMsg

	// 握手中的并发控制
	wNeedBytes chan []byte
	rpk        *protocol.ShakeHandMsg
	rSignal    chan bool

	// 用于握手时间戳校验
	ackTimCheck [8][]byte
	ackRec      int
}

func (p *EncFlowProxy) InitChannel() {
	p.rSignal = make(chan bool)
	p.wNeedBytes = make(chan []byte)
}

// panic 或者处理完其它确定整套程序不用而正常退出时再用。
func (p *EncFlowProxy) DeleteChannel() {
	close(p.rSignal)
	close(p.wNeedBytes)
}

/* 代理发送公钥至客户端专用。必须保证已经生成了公钥 */
func (p *EncFlowProxy) SendPub() error {
	key := make([]byte, 65)
	p.AsymmCipher.GetPub(&key)
	cnt, err := p.Client.Write(key)
	if cnt != 65 /* len(pubHexVal) */ || err != nil {
		err = defErr.DescribeThenConcat(`sending interrupts`, err)
	}
	return err
}

// 调用前必须保证已经通过`ep.FlowCipher.SetKey, ep.FlowCipher.SetIv` 显式协商了会话密钥。
func (ep *EncFlowProxy) EncWrite2Client(plaintext []byte) (uint, error) {
	enc := ep.StreamCipher.FlipFlow(plaintext)
	cnt, err := ep.Client.Write(enc)
	return cnt, err
}

// 调用前必须保证已经通过`ep.FlowCipher.SetKey, ep.FlowCipher.SetIv` 显式协商了会话密钥。
func (ep *EncFlowProxy) DecReadViaClient() ([]byte, uint, error) {
	enc, cnt, err := ep.Client.Read()
	if cnt == 0 || err != nil {
		return []byte(``), 0, errors.Join(err, errors.New(`got empty enc-string from client`))
	}
	dec := ep.StreamCipher.FlipFlow(enc)
	return dec, cnt, nil
}

func (p *EncFlowProxy) SendRemote(msg []byte) (uint, error) {
	cnt, err := p.Remote.Write(msg)
	return cnt, err
}

func (p *EncFlowProxy) ReadRemote() ([]byte, uint, error) {
	buf, cnt, err := p.Remote.Read()
	return buf, cnt, err
}

/* todo: 函数需经充分测试。*/
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

/* todo: 函数需经充分测试。*/
func (p *EncFlowProxy) CS2RR() error {
	pack, _, err := p.DecReadViaClient()
	if err != nil {
		return err
	}
	_, err = p.SendRemote(pack)
	return err
}
