// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package main

import (
	"log"
	"net"
	"testing"
	"time"

	protocol "bingoproxy/protocol/custom"
	client "bingoproxy/protocol/custom/default/client"
	proxy "bingoproxy/protocol/custom/default/proxy"
)

// TODO: adjust to

func TestForwarding(t *testing.T) {
	log.Println(`Begin forwarding test`)
	var (
		ep proxy.EncFlowProxy
		c  client.Client
	)

	ch_listen, ch_conn := make(chan net.Listener, 1), make(chan net.Conn, 1)
	ch_client := make(chan net.Conn, 1)
	server_done, client_done := make(chan bool, 1), make(chan bool, 1)

	go func() {
		dial, err := net.Dial("tcp6", "[::1]:9971")
		if err != nil {
			t.Errorf(err.Error())
		}
		ch_client <- dial
		close(ch_client)
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
		close(ch_listen)
		close(ch_conn)
	}()

	c.MiProxy.Conn = <-ch_client
	ep.Client.Conn = <-ch_conn
	listener := <-ch_listen

	defer ep.Client.CloseConn()
	defer c.MiProxy.CloseConn()
	defer listener.Close()
	type innerInterface interface {
		Shakehand() (error, error)
	}
	foo := func(op *innerInterface, ch chan<- bool) {
		defer close(ch)
		werr, rerr := (*op).Shakehand()
		if werr != nil {
			ch <- false
			log.Println(werr)
			return
		}
		if rerr != nil {
			ch <- false
			log.Println(werr)
			return
		}
		ch <- true
	}

	go func() {
		var tmp innerInterface = &ep
		foo(&tmp, server_done)
	}()
	go func() {
		time.Sleep(time.Millisecond)
		var tmp innerInterface = &c
		foo(&tmp, client_done)
	}()

	ep_err, c_err := <-server_done, <-client_done
	if !ep_err {
		t.Error(`proxy failed`)
		return
	}
	if !c_err {
		t.Error(`client failed`)
		return
	}

	log.Println(`End of shakehand.`)

	go func() {
		key, iv, err := protocol.GeneratePresessionKey(c.StreamCipher)
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
