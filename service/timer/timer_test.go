package timer

import (
	"log"
	"testing"
	"time"
)

func unk_selector_test(ch chan struct{}) interface{} {
	tim := time.NewTimer(time.Second)
	select {
	case <-tim.C:
		log.Println(`timeout`)
		return struct {
			a uint32
			b byte
		}{a: 11, b: 23}
	case a := <-ch:
		log.Println(`ack`)
		return a
	}
}

func TestPrivateDemand(t *testing.T) {
	monika := make(chan struct{})
	go func() { unk_selector_test(monika) }()
	log.Println(`no stuck!`)
	time.Sleep(20 * time.Millisecond)
	monika <- struct{}{}
	log.Println(`end of private demand testing.`)
	close(monika)
}
