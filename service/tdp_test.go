package service

import (
	"log"
	"net"
	"testing"
	"time"
)

// TODO
func TestUDP(t *testing.T) {
	cnt := 0
	for i := 0; i < 2; i++ {
		go func() {
			time.Sleep(time.Second * 2)
			dial_conn, err := net.Dial("udp6", "[::1]:3314")
			if err != nil {
				log.Println(err)
				return
			}
			defer dial_conn.Close()
			dial_conn.Write([]byte(`hello`))
		}()
	}
	server, err := net.ListenUDP(
		"udp", &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: 3314,
		})
	if err != nil {
		t.Error(err)
		return
	}
	defer server.Close()
	now := make([]byte, 1024)
	for {
		cnt += 1
		_, addr, _ := server.ReadFromUDP(now)
		log.Println(addr.String(), string(now))
		if cnt == 2 {
			break
		}
	}
}
