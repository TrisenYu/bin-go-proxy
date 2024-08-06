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

	defErr "bingoproxy/defErr"
	client "bingoproxy/protocol/custom/default/client"
	proxy "bingoproxy/protocol/custom/default/proxy"
	utils "bingoproxy/utils"
)

func TestHandShakeInTCP6(t *testing.T) {
	var (
		c               client.Client
		ep              proxy.EncFlowProxy
		global_listener net.Listener
	)

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
		var tmp innerInterface = &c
		foo(&tmp, client_done)
	}()
	jup, juc := <-server_done, <-client_done
	if !(jup && juc) {
		t.Error(`Unaccepted`)
		return
	}
	log.Println(`key:`, hex.EncodeToString(c.StreamCipher.GetKey()))
	log.Println(`epKey:`, hex.EncodeToString(ep.StreamCipher.GetKey()))
	log.Println(reflect.TypeOf(c.StreamCipher).Elem().Name())

	helo := []byte(`hello world`)
	rres1, err := c.StreamCipher.EncryptFlow(helo)
	if err != nil {
		t.Error(err)
		return
	}
	rres2, err := ep.StreamCipher.DecryptFlow(rres1)
	f, _ := utils.CmpByte2Slices(rres2, helo)
	if err != nil || !f {
		log.Println(rres2, helo)
		t.Error(defErr.StrConcat(`decryption failed. potential error: `, err))
		return
	}
	rres3, err := c.StreamCipher.EncryptFlow(helo)
	f, _ = utils.CmpByte2Slices(rres3, rres1)
	if err != nil || f {
		t.Error(defErr.StrConcat(`counter or feedback stays the same...`, err))
		return
	}
	log.Println(`End of HandShake Test`)
}
