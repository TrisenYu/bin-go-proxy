// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package main

import (
	"encoding/hex"
	"log"
	"net"
	"testing"
	"time"

	client "bingoproxy/client"
	defErr "bingoproxy/defErr"
	proxy "bingoproxy/proxy"
)

func TestHandShakeInTCP6(t *testing.T) {
	var (
		c               client.Client
		ep              proxy.EncFlowProxy
		global_listener net.Listener
	)
	c.InitChannel()
	ep.InitChannel()
	defer c.DeleteChannel()
	defer ep.DeleteChannel()
	log.Println(`[handshake_test.go-64] we will begin client-proxy shakehand test.`)

	cp_con, pc_con := make(chan net.Conn, 1), make(chan net.Conn, 1)
	_listener := make(chan net.Listener)

	go func() {
		time.Sleep(time.Second)
		dialer, err := net.Dial("tcp6", "[::1]:9971")
		if err != nil || dialer == nil {
			err = defErr.Concat(err, `dialer may be hazard`)
			t.Error(err.Error())
			return
		}
		dialer.SetReadDeadline(time.Now().Add(time.Second * 5)) // 本地 5 s，线上 10 s
		cp_con <- dialer
	}()

	go func() {
		listener, err := net.Listen("tcp6", ":9971")
		if err != nil {
			t.Error(err.Error())
			return
		}
	server_back:
		conn, err := listener.Accept()
		if err != nil {
			log.Println(`failed to accept new client, we will go back.`)
			goto server_back
		}
		log.Println(`Accept one Client`)
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		pc_con <- conn
		_listener <- listener
	}()

	c.MiProxy.Conn, ep.Client.Conn = <-cp_con, <-pc_con
	global_listener = <-_listener
	log.Println(`Before shakehand`)
	defer c.MiProxy.Conn.Close()
	defer ep.Client.Conn.Close()
	defer global_listener.Close()
	defer close(cp_con)
	defer close(pc_con)
	defer close(_listener)

	server_done, client_done := make(chan bool), make(chan bool)
	defer close(server_done)
	defer close(client_done)
	go func() {
		pwerr, prerr := ep.Shakehand()
		if pwerr != nil {
			server_done <- false
			t.Errorf(pwerr.Error())
			return
		}
		if prerr != nil {
			server_done <- false
			t.Errorf(prerr.Error())
			return
		}
		server_done <- true
	}()
	go func() {
		cwerr, crerr := c.Shakehand()
		if cwerr != nil {
			client_done <- false
			t.Errorf(cwerr.Error())
			return
		}
		if crerr != nil {
			client_done <- false
			t.Errorf(crerr.Error())
			return
		}
		client_done <- true
	}()
	jup, juc := <-server_done, <-client_done
	if jup && juc {
		log.Println(`key:`, hex.EncodeToString(c.StreamCipher.GetKey()))
		log.Println(`epKey:`, hex.EncodeToString(ep.StreamCipher.GetKey()))
	} else {
		t.Error(`Unaccepted`)
		return
	}
	log.Println(`[handshake_test.go] End of HandShake Test`)
}
