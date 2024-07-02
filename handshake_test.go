// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package main

import (
	"encoding/hex"
	"log"
	"net"
	"testing"
	"time"

	client "selfproxy/client"
	defErr "selfproxy/defErr"
	proxy "selfproxy/proxy"
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
		log.Println(`key:`, hex.EncodeToString(c.StreamCipher.GetKey()),
			`iv: `, hex.EncodeToString(c.StreamCipher.GetIv()))
		log.Println(`epKey:`, hex.EncodeToString(ep.StreamCipher.GetKey()),
			`epIv: `, hex.EncodeToString(ep.StreamCipher.GetIv()))
	} else {
		t.Error(`Unaccepted`)
		return
	}
	log.Println(`[handshake_test.go] End of HandShake Test`)
}

/*
func TestHandShakeInUDP6(t *testing.T) {
	// 看测试，目前还是只支持 tcp……
	var (
		c  client.Client
		ep proxy.EncFlowProxy
	)
	client.GlobalClientPem, client.GlobalClientPub = cryptoprotect.GenerateSM2KeyPair()
	proxy.GlobalProxyPem, proxy.GlobalProxyPub = cryptoprotect.GenerateSM2KeyPair()
	log.Println(`PPUB:`, proxy.GlobalProxyPub)
	log.Println(`CPUB:`, client.GlobalClientPub)
	c.InitChannel()
	ep.InitChannel()
	defer c.DeleteChannel()
	defer ep.DeleteChannel()
	log.Println(`[handshake_test.go-64] we will begin client-proxy shakehand test.`)

	cp_con, pc_con := make(chan net.Conn, 1), make(chan net.Conn, 1)

	go func() {
		time.Sleep(time.Second)
		dialer, err := net.Dial("udp6", "[::1]:9972")
		if err != nil || dialer == nil {
			err = defErr.Concat(err, `dialer may be hazard`)
			t.Error(err.Error())
			return
		}
		dialer.SetReadDeadline(time.Now().Add(time.Second * 5))
		cp_con <- dialer
	}()

	go func() {
		udp_proxy := &net.UDPAddr{IP: net.ParseIP("[::1]:9972"), Port: 9972}
		conn, err := net.ListenUDP("udp6", udp_proxy)
		if err != nil {
			t.Error(err.Error())
			return
		}
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		pc_con <- conn
	}()

	c.MiProxy.Conn, ep.Client.Conn = <-cp_con, <-pc_con
	log.Println(`Before shakehand`)
	defer c.MiProxy.Conn.Close()
	defer ep.Client.Conn.Close()
	defer close(cp_con)
	defer close(pc_con)

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
		log.Println(`key:`, hex.EncodeToString(c.Key[:]),
			`iv: `, hex.EncodeToString(c.Iv[:]),
			`PpubX`, c.PPub.X)
		log.Println(`epKey:`, hex.EncodeToString(ep.Key[:]),
			`epIv: `, hex.EncodeToString(ep.Iv[:]),
			`CpubX`, ep.CPub.X)
	} else {
		t.Error(`Unaccepted`)
	}
	log.Println(`[handshake_test.go] End of HandShake Test`)
}
*/
