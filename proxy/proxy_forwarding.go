// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package proxy

import (
	"errors"
	"log"
	"net"
	"time"

	cryptoprotect "selfproxy/cryptoProtect"
	defErr "selfproxy/defErr"
	protocol "selfproxy/protocol"
	utils "selfproxy/utils"
)

type ClientControlMsg struct {
	Rport  [2]byte
	Remote []byte
}

/*
	TODO：握手后全程都需要时间戳校验通信延迟吗？
		  需不需要像 FTP 一样建立两条连接？一条数据连接，一条控制连接。

转发中途为了能让代理客户端识别传输的报文是数据还是通信反馈，在此定义转发报文格式

	客户端解密后第一个字节限定为 0xAB 或 0xCD。

		为 0xAB 时标识这是一个提供给上层应用的数据包。
		为 0xCD 时则为通信反馈。

	第二字节限定为 0xCA
	之后接报文或者通信反馈信息。

参数：

	payload: remote server 的数据或者通信反馈
	attr: 用于控制 header 格式的单个字符。`F` 代表这个包是通信反馈，`D` 则代表这个包是数据包。用于给客户端拦截处理传回。
*/
func WrapWithHeader(payload []byte, attr rune) []byte {
	var header []byte
	switch attr {
	case 'F': // 反馈报文(proxyFeedback)
		header = append(header, 0xAB)
	case 'D': // 数据包(Data)
		header = append(header, 0xCD)
	}
	header = append(header, 0xCA)
	return append(header, payload...)
}

/*
控制报文解析

	报文：24字节命令与其余 payload
	返回 错误。形式 xxxx error:
		其中 fatal error 需要中断连接。
*/
func (ep *EncFlowProxy) controlTypeSelector(payload []byte) error {
	/* 有的控制报文不需要后续的操作。 */
	switch string(payload[:protocol.CMD_PAYLOAD_LEN]) {
	/* 更换 sessionkey。失败则终止连接。*/
	case protocol.CMD_refresh_sessionkey:
		if len(payload[protocol.CMD_PAYLOAD_LEN:]) != cryptoprotect.KeySize+cryptoprotect.IVSize {
			return errors.New(`fatal error: malicious payload for altering key-iv`)
		}
		key_ed := protocol.CMD_PAYLOAD_LEN + uint(cryptoprotect.KeySize)
		iv_ed := key_ed + uint(cryptoprotect.IVSize)
		ep.StreamCipher.SetKey(payload[protocol.CMD_PAYLOAD_LEN:key_ed])
		ep.StreamCipher.SetIv(payload[key_ed:iv_ed])
		_, err := ep.EncWrite2Client([]byte(protocol.HANDHLT))
		if err != nil {
			return defErr.DescribeThenConcat(`fatal error:`, err)
		}
		return errors.New(`info: jump out`)

	case protocol.CMD_disconnect_with_ep:
		ep.Client.CloseAll()
		if ep.Remote.Conn != nil {
			ep.Remote.CloseAll()
		}
		return errors.New(`unique error: client proactive disconnect`)

	case protocol.CMD_alter_aloof_server:
		if len(payload[protocol.CMD_PAYLOAD_LEN:]) <= 4 {
			return errors.New(`warning: invalid remote setting`)
		}
		var res ClientControlMsg
		res.Rport = [2]byte(payload[protocol.CMD_PAYLOAD_LEN:protocol.CMD_RPORT_ED])
		addrlen_int := utils.BytesToUint16([2]byte(payload[protocol.CMD_RPORT_ED:protocol.CMD_ADDR_ED]))
		recheck_len := protocol.CMD_ADDR_ED + uint(addrlen_int)
		res.Remote = payload[protocol.CMD_ADDR_ED:]
		if uint(len(res.Remote)) != recheck_len {
			return errors.New(`warning: malicious payload`)
		}
		/*
			TODO: 将传给当前端口的报文丢弃，避免形成自环。
			但是如果以后想做 p2p，如果有报文指向自身，就区分不开是中继还是恶意的构造攻击。
				.-> . -> .
					^	 |
					|	 v
					. <- .
			考虑一下解决策略？
		*/
		_, err := ep.EncWrite2Client([]byte(protocol.RESP_recv_server_addrp)) // 发这个≠代理认可
		if err != nil {
			return defErr.DescribeThenConcat(`fatal error:`, err)
		}
		ep.remote_info = &res
		return errors.New(`need jump out`)

	case protocol.CMD_client_ready4_dual:
		if ep.remote_info == nil {
			ep.EncWrite2Client([]byte(protocol.RESP_abort_the_operate))
			return errors.New(`internal error: 'remote_info' domain is still an empty CientControlMsg ptr`)
		}

		err := ep.TryConnRemote(ep.remote_info)
		if err == nil {
			_, err = ep.EncWrite2Client([]byte(protocol.RESP_server_acknowlege))
			if err != nil {
				return defErr.DescribeThenConcat(`fatal error:`, err)
			}
			return nil
		}
		/* 无法连接到远端服务器 */
		_, err1 := ep.EncWrite2Client([]byte(protocol.RESP_fail2_conn2server))
		if err1 != nil {
			return defErr.DescribeThenConcat(`fatal error:`, err1)
		}
		ep.remote_info = nil // 无效就清空
		return defErr.DescribeThenConcat(`remote connection failed error:`, err)

		/* 下一步发数据报文形成转发。转发过程视抛出错误程度决定恢复到何一状态。 */

	}
	return errors.New(`unsupported control type`)
}

/*
尝试连接到远程服务器

	返回 错误
*/
func (ep *EncFlowProxy) TryConnRemote(msg *ClientControlMsg) error {
	server_addr, recommend_protocol, err := utils.CheckAddrType(string(msg.Remote) + `:` + string(msg.Rport[:]))
	if err != nil { // 这个包发过来的服务器地址有错 | 恶意的 client |  通信被劫持篡改
		return errors.New(`can not connect with remote server due to` + err.Error())
	}

	dial, err := net.Dial(recommend_protocol, server_addr)
	if err != nil {
		return errors.New(`remote server is unreachable`)
	}
	ep.Remote.Conn = dial
	ep.Remote.Conn.SetDeadline(time.Now().Add(time.Second * 3))
	ep.Remote.Conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	return nil
}

/*
解析命令。命令形如

	+--+--+----+--------------------------------+...
	|DC|CA|leng| payload
	+--+--+----+--------------------------------+...
	返回 错误。形式 xxxx error:
	其中 `fatal error` 需要中断与客户端的连接。
*/
func (ep *EncFlowProxy) CmdParser() error {
	packet, cnt, err := ep.DecReadViaClient()
	if err != nil || cnt < 30 /* 6+24 */ {
		return defErr.DescribeThenConcat(`unexpected error: failed to dec-read from client or fake packet caused by`, err)
	}
	attr, ver := packet[0], packet[1]
	nxt_len := utils.BytesToUint32([4]byte(packet[2:6]))

	if ver != protocol.PROTOCOL_VERSION {
		return errors.New(`fatal error: fraud version`)
	}
	if attr != 0xDC {
		return errors.New(`unexpected error: unsupported format`) // 异常的包
	}
	if nxt_len < 24 || nxt_len > 65540 /* 2 + 2 + 65536 */ {
		return errors.New(`fatal error: fake cmd-packet detected from invalid nxt-len`)
	}
	return ep.controlTypeSelector(packet[6 : 6+uint(nxt_len)])
}

/*
转发流程如图所示。TODO：错误控制与测试。

	返回读错误和写错误。
	client            proxy             server
		sp+----> rp-----┐  ┌-- rp<------- sp
					 ┌--+--┘
		rp<----+ sp<-┘  └----> sp-------> rp
*/
func (ep *EncFlowProxy) FlowForwarding() (error, error) {
	err_ch := make(chan error)
	defer close(err_ch)
	go func() { err_ch <- ep.CS2RR() }()
	_, err := ep.RR2CS()
	return err, <-err_ch
}

/*
TODO: 函数需经充分测试。
*/
func (ep *EncFlowProxy) Stage2Emulator() {
	defer ep.Remote.CloseAll()
	defer ep.Client.CloseAll()
recontrol:
	if err := ep.CmdParser(); err != nil {
		log.Println(`[proxy_forwarding.go-211]`, err.Error())
		switch err.Error()[0] {
		case 'f':
			fallthrough
		case 'u': /* 这里的错误不好恢复，需要退出。*/
			fallthrough
		default:
			return
			/*
				需要评估下一句的做法
				goto recontrol
			*/
		}
	}

	ep.remote_info = nil
	for {
		r2cerr, c2rerr := ep.FlowForwarding()
		if r2cerr == nil && c2rerr == nil {
			continue
		}
		if c2rerr != nil { // 客户端在转发中途挂了。直接关闭所有连接。
			return
		}
		if r2cerr != nil {
			ep.Remote.CloseAll()
			ep.EncWrite2Client(WrapWithHeader([]byte(`remote server error: `+r2cerr.Error()), 'F'))
			goto recontrol // 需重新通过控制报文建立通信。
		}

	}
}
