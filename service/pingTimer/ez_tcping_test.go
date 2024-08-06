package service

import (
	"log"
	"testing"
)

func TestTcpping(t *testing.T) {
	TCPPing("youku.com", "")
	TCPPing("tudou.com", "")
	TCPPing("thbwiki.com", "")
	TCPPing("bing.com", "")
	TCPPing("135.181.29.38", "")
	TCPPing("2408:8720:806:300:70::77", "")
	TCPPing("135.181.29.38:80", "localhost:7791")
	val, err := TCPPing("135.181.29.38:443", "127.0.0.1:7792")
	log.Println(val, err)
}

func TestForImplementation(t *testing.T) {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
}
