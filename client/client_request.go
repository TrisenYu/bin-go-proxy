// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package client

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	cryptoprotect "bingoproxy/cryptoProtect"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
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
	_, err := c.EncWrite(CmdHeaderWrapper(append([]byte(protocol.CMD_alter_aloof_server), addrp...)))
	switch err { // Todo: error classification
	case nil:
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`unexpected error: proxy is down`, err)
	default:
		return err
	}
	correspond_resp, _, rerr := c.DecRead()
	switch rerr {
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseAll()
		return rerr
	}
	status, descript := utils.CompareByteSliceEqualOrNot(correspond_resp, []byte(protocol.RESP_recv_server_addrp))
	if !status {
		return defErr.DescribeThenConcat(`checked recv-remote-server failed`+descript, rerr)
	}
	return nil
}

/* TODO: testing and debugging. */
func (c *Client) ProactiveAbortConnAsCmd() {
	c.EncWrite(CmdHeaderWrapper([]byte(protocol.CMD_disconnect_with_ep)))
	c.MiProxy.CloseAll()
}

/* TODO: testing and debugging. */
func (c *Client) ChangeSessionKey(
	key [cryptoprotect.KeySize]byte,
	iv [cryptoprotect.IVSize]byte,
) error {
	_, werr := c.EncWrite(CmdHeaderWrapper(
		append([]byte(protocol.CMD_refresh_sessionkey), append(key[:], iv[:]...)...)))
	switch werr {
	case nil:
	case net.ErrClosed:
		fallthrough
	case io.EOF:
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`unexpected error: proxy is down`, werr)
	default:
		return werr
	}
	c.StreamCipher.SetKey(key[:])
	c.StreamCipher.SetIv(iv[:])
	_finish, _, rerr := c.DecRead()
	status, descript := utils.CompareByteSliceEqualOrNot(_finish, []byte(protocol.HANDHLT))
	if !status {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`fatal error: can not recv finish from proxy due to`+descript, rerr)
	}
	return nil
}
