// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package proxy

import (
	"errors"
	"log"
	"net"
	"time"

	cryptoprotect "bingoproxy/cryptoProtect"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
	utils "bingoproxy/utils"
)

type ClientControlMsg struct {
	Rport  [2]byte
	Remote []byte
}

// 	TODO：握手后全程都需要时间戳校验通信延迟吗？需不需要像 FTP 一样建立两条连接？一条数据连接，一条控制连接。
/*
	The first byte of control packet is defined as 0xAB or 0xCD.

		0xAB - the packet is for certain application.
		0xCD - the packet is proxy response

	The second byte is set to 0xCA.
	Reminder byte is used for datagram or response payload.

param:

	payload: remote server data or proxy response.
	attr: used for identify the type of header. `F` as response Feedback，`D` as Data.
*/
func WrapWithHeader(payload []byte, attr rune) []byte {
	var header []byte
	switch attr {
	case 'F':
		header = append(header, 0xAB)
	case 'D':
		header = append(header, 0xCD)
	}
	header = append(header, 0xCA)
	return append(header, payload...)
}

/*
resolve command

	packet : (command, payload) ~ (24 bytes, ? )
	return: xxxx error:
		fatal or unexpected error should immediately abort connection.
*/
func (ep *EncFlowProxy) controlTypeSelector(payload []byte) error {
	switch string(payload[:protocol.CMD_PAYLOAD_LEN]) {
	/* change sessionkey. Abort connection once unable to maintain encrypted connection.*/
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
			TODO: avoid self-looping by certain algorithm.
				.-> . -> .
					^    |
					|    v
					. <- .
			What is the final solution ?
		*/
		_, err := ep.EncWrite2Client([]byte(protocol.RESP_recv_server_addrp)) // send ≠ acknowledge
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
		/* unable to connect to remote server */
		_, err1 := ep.EncWrite2Client([]byte(protocol.RESP_fail2_conn2server))
		if err1 != nil {
			return defErr.DescribeThenConcat(`fatal error:`, err1)
		}
		ep.remote_info = nil // clean if invalid
		return defErr.DescribeThenConcat(`remote connection failed error:`, err)

	}
	return errors.New(`unsupported control type`)
}

/*
attempt to set up connection with remote server

	return error
*/
func (ep *EncFlowProxy) TryConnRemote(msg *ClientControlMsg) error {
	server_addr, recommend_protocol, err := utils.CheckAddrType(string(msg.Remote) + `:` + string(msg.Rport[:]))
	if err != nil {
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
command is in the shape of

	+--+--+----+--------------------------------+...
	|DC|CA|leng| payload
	+--+--+----+--------------------------------+...
	return xxxx error if there is indeed an error:
	Abort connection if the error is `fatal error` or `unexpected error`
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
		return errors.New(`unexpected error: unsupported format`)
	}
	if nxt_len < 24 || nxt_len > 65540 /* 2 + 2 + 65536 */ {
		return errors.New(`fatal error: fake cmd-packet detected from invalid nxt-len`)
	}
	return ep.controlTypeSelector(packet[6 : 6+uint(nxt_len)])
}

/*
TODO：Test all of the logic。

set up data path as figure shown.

	return read error and write error
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
TODO: Test all of the logic.
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
		case 'u':
			fallthrough
		default:
			return
			// goto recontrol
		}
	}

	ep.remote_info = nil
	for {
		r2cerr, c2rerr := ep.FlowForwarding()
		if r2cerr == nil && c2rerr == nil {
			continue
		}
		if c2rerr != nil { // client is down, just abort connection.
			return
		}
		if r2cerr != nil {
			ep.Remote.CloseAll()
			ep.EncWrite2Client(WrapWithHeader([]byte(`remote server error: `+r2cerr.Error()), 'F'))
			goto recontrol // reset remote connect.
		}

	}
}
