// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package main

import (
	"encoding/hex"
	"log"
	"net"
	"reflect"
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

	log.Println(`we will begin client-proxy shakehand test.`)

	cp_con, pc_con := make(chan net.Conn, 1), make(chan net.Conn, 1)
	_listener := make(chan net.Listener)

	go func() {
		time.Sleep(time.Second)
		dialer, err := net.Dial("tcp6", "[::1]:9971")
		if err != nil || dialer == nil {
			err = defErr.ConcatStr(err, `dialer may be hazard`)
			t.Error(err.Error())
			return
		}
		dialer.SetReadDeadline(time.Now().Add(time.Second * 5))
		cp_con <- dialer
		close(cp_con)
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
		close(pc_con)
		close(_listener)
	}()

	c.MiProxy.Conn, ep.Client.Conn = <-cp_con, <-pc_con
	global_listener = <-_listener
	log.Println(`Before shakehand`)
	defer c.MiProxy.Conn.Close()
	defer ep.Client.Conn.Close()
	defer global_listener.Close()

	server_done, client_done := make(chan bool), make(chan bool)

	go func() {
		pwerr, prerr := ep.Shakehand()
		defer close(server_done)
		if pwerr != nil {
			server_done <- false
			ep.DeleteChannel()
			t.Errorf(pwerr.Error())
			return
		}
		if prerr != nil {
			server_done <- false
			ep.DeleteChannel()
			t.Errorf(prerr.Error())
			return
		}
		server_done <- true
		ep.DeleteChannel()
	}()
	go func() {
		cwerr, crerr := c.Shakehand()
		defer close(client_done)
		if cwerr != nil {
			client_done <- false
			c.DeleteChannel()
			t.Errorf(cwerr.Error())
			return
		}
		if crerr != nil {
			client_done <- false
			c.DeleteChannel()
			t.Errorf(crerr.Error())
			return
		}
		client_done <- true
		c.DeleteChannel()
	}()
	jup, juc := <-server_done, <-client_done
	if jup && juc {
		log.Println(`key:`, hex.EncodeToString(c.StreamCipher.GetKey()))
		log.Println(`epKey:`, hex.EncodeToString(ep.StreamCipher.GetKey()))
		log.Println(reflect.TypeOf(c.StreamCipher).Elem().Name())
	} else {
		t.Error(`Unaccepted`)
		return
	}
	log.Println(`End of HandShake Test`)
}
