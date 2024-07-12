// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package main

import (
	"log"
	"net"
	"testing"
	"time"

	client "bingoproxy/client"
	cryptoprotect "bingoproxy/cryptoProtect"
	protocol "bingoproxy/protocol"
	proxy "bingoproxy/proxy"
)

func TestForwarding(t *testing.T) {
	log.Println(`[forwarding_test.go-13] Begin forwarding test`)
	var (
		ep proxy.EncFlowProxy
		c  client.Client
	)

	c.InitChannel()
	ep.InitChannel()
	defer ep.DeleteChannel()
	defer c.DeleteChannel()

	ch_listen, ch_conn := make(chan net.Listener, 1), make(chan net.Conn, 1)
	ch_client := make(chan net.Conn, 1)
	ch_err := make(chan [2]error)
	defer close(ch_err)
	defer close(ch_client)
	defer close(ch_listen)
	defer close(ch_conn)

	go func() {
		dial, err := net.Dial("tcp6", "[::1]:9971")
		if err != nil {
			t.Errorf(err.Error())
		}
		ch_client <- dial
	}()

	go func() {
		listener, err := net.Listen("tcp6", ":9971")
		if err != nil {
			t.Errorf(err.Error())
		}
	server_back:
		conn, err := listener.Accept()
		if err != nil {
			goto server_back
		}
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		ch_listen <- listener
		ch_conn <- conn
	}()

	c.MiProxy.Conn = <-ch_client
	ep.Client.Conn = <-ch_conn
	listener := <-ch_listen

	defer ep.Client.CloseAll()
	defer c.MiProxy.CloseAll()
	defer listener.Close()
	go func() {
		werr, rerr := ep.Shakehand()
		ch_err <- [2]error{werr, rerr}
	}()
	time.Sleep(time.Millisecond)
	cwerr, crerr := c.Shakehand()
	if cwerr != nil {
		t.Error(cwerr.Error())
		return
	}
	if crerr != nil {
		t.Error(crerr.Error())
		return
	}

	ep_err := <-ch_err
	pwerr, prerr := ep_err[0], ep_err[1]
	if pwerr != nil {
		t.Error(pwerr.Error())
		return
	}
	if prerr != nil {
		t.Error(prerr.Error())
		return
	}

	log.Println(`[forwarding_test.go-28] End of shakehand.`)

	go func() {
		key, iv, err := cryptoprotect.GeneratePresessionKey()
		if err != nil {
			t.Error(err.Error())
		}
		key = append(key, iv...)
		curr_cmd := client.CmdHeaderWrapper(append([]byte(protocol.CMD_refresh_sessionkey), key...))
		c.EncWrite(curr_cmd)

		// TODO: Add more tests
	}()

	ep.Stage2Emulator() // connection is aborted once return from this function
}
