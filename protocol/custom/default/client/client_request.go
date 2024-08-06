// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	defErr "bingoproxy/defErr"
	custom "bingoproxy/protocol/custom"
	utils "bingoproxy/utils"
)

func CmdHeaderWrapper(payload []byte) []byte {
	header := []byte{0xDC, 0xCA}
	len_buf, lena := new(bytes.Buffer), uint32(len(payload))
	binary.Write(len_buf, binary.LittleEndian, lena)
	header = append(header, len_buf.Bytes()...)
	header = append(header, payload...)
	return header
}

/* TODO: testing and debugging. */
func (c *Client) ChangeRemoteServer(addrp []byte) error {
	_, err := c.EncWrite(CmdHeaderWrapper(append([]byte(custom.CMD_alter_aloof_server), addrp...)))
	switch err { // TODO: error classification
	case nil:
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseConn()
		return defErr.StrConcat(`unexpected error: proxy is down`, err)
	default:
		return err
	}
	correspond_resp, _, rerr := c.DecRead()
	switch rerr {
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseConn()
		return rerr
	}
	status, descript := utils.CmpByte2Slices(correspond_resp, []byte(custom.RESP_recv_server_addrp))
	if !status {
		return defErr.StrConcat(`checked recv-remote-server failed`+descript, rerr)
	}
	return nil
}

/* TODO: testing and debugging. */
func (c *Client) ProactiveAbortConnAsCmd() {
	c.EncWrite(CmdHeaderWrapper([]byte(custom.CMD_disconnect_with_ep)))
	c.MiProxy.CloseConn()
}

/* TODO: testing and debugging. */
func (c *Client) ChangeSessionKey(key, iv []byte) error {
	_, werr := c.EncWrite(CmdHeaderWrapper(
		append([]byte(custom.CMD_refresh_sessionkey), append(key[:], iv[:]...)...)))
	switch werr {
	case nil:
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseConn()
		return defErr.StrConcat(`unexpected error: proxy is down`, werr)
	default:
		return werr
	}
	c.StreamCipher.SetKey(key[:])
	c.StreamCipher.SetIv(iv[:])
	_finish, _, rerr := c.DecRead()
	status, descript := utils.CmpByte2Slices(_finish, []byte(custom.HANDHLT))
	if !status {
		c.MiProxy.CloseConn()
		return defErr.StrConcat(`fatal error: can not recv finish from proxy due to`+descript, rerr)
	}
	return nil
}
