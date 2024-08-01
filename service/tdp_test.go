package service

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	utils "bingoproxy/utils"
)

// TO Write in a tidy and clean way.
func TestUDP(t *testing.T) {
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
	for i := 1; i <= 2; i++ {
		_, addr, _ := server.ReadFromUDP(now)
		log.Println(addr.String(), string(now))
	}
}

func TestQueue(t *testing.T) {
	var helo *TDPQueue
	var wg sync.WaitGroup
	var ptr_ch *chan struct{}
	wg.Add(3)
	helo = &TDPQueue{}
	helo.Init(16)
	log.Println(utils.LittleEndianBytesToUint32([4]byte([]byte("tout"))),
		utils.LittleEndianBytesToUint32([4]byte([]byte(`pout`))),
	)

	encapsulator := func(iM int) {
		defer wg.Done()
		log.Println(iM, `: before getting item from queue...`)
		time.Sleep(time.Second * time.Duration(rand.Intn(2)))
		_res := helo.PopFront()
		switch now := _res.(type) {
		case ReverseIDMessage:
			log.Println(iM, `: we get ReverseIDMessage:`, now.Idx)
		case AddrMessage:
			log.Println(iM, `: we get AddrMessage:`, now.Addr, string(now.Msg))
		default:
			log.Println(`bad item fetched from queue.`)
		}
	}
	for i := 0; i < 3; i++ {
		go encapsulator(i)
	}

	time.Sleep(5 * time.Second)
	helo.PushBack(ReverseIDMessage{Idx: 1, Msg: nil})
	log.Println(`we send (1, nil) to reader...`)
	time.Sleep(3 * time.Second)
	helo.PushBack(AddrMessage{Msg: []byte(`hello world`)})
	helo.PushBack(AddrMessage{Msg: []byte(`hello world2`)})

	done_ch := make(chan struct{})
	defer close(done_ch)
	ptr_ch = &done_ch
	go func() {
		wg.Wait()
		*ptr_ch <- struct{}{}
	}()
	select {
	case <-*ptr_ch:
		log.Println(`all routine working with queue went well.`)
		return
	case <-time.After(10 * time.Second):
		log.Println(`timeout...`)
	}

	// TODO: should we add clean function of queue?
}

func TestSyncS(t *testing.T) {
}

func TestSyncR(t *testing.T) {
}

func TestFinS(t *testing.T) {}

func TestFinR(t *testing.T) {}

func TestConcurrentAction(t *testing.T) {}
