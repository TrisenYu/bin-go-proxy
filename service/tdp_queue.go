// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"container/list"
	"net"
	"sync"
	"sync/atomic"
)

type (
	TDPItem interface {
		ReverseIDMessage | AddrMessage | struct{} | interface{}
	}
	TDPQueue struct {
		q                list.List
		empty, full      *sync.Cond
		mutex            sync.Mutex
		length, boundary int32
	}
	ReverseIDMessage struct {
		Idx uint32
		Msg []byte
	}
	AddrMessage struct {
		Addr *net.UDPAddr
		Msg  []byte
	}
)

const default_size int32 = 256

func (q *TDPQueue) Init(max_queue_size int32) {
	q.empty = sync.NewCond(&sync.Mutex{})
	q.full = sync.NewCond(&sync.Mutex{})
	if max_queue_size <= 0 {
		q.boundary = default_size
	} else {
		q.boundary = max_queue_size
	}
}

// push one item into queue.
func (q *TDPQueue) PushBack(msg TDPItem) {
	switch msg.(type) {
	case struct{}:
		return
	case nil:
		return
	default:
	}
	q.full.L.Lock()
	for q.Len() == q.boundary {
		q.full.Wait() /// Wait for state of not full
	}
	q.full.L.Unlock()

	q.mutex.Lock()
	q.q.PushBack(msg)
	q.length += 1
	q.mutex.Unlock()

	q.empty.Signal() /// not empty any more.
}

// return nil if queue is empty. pop one item from the head of queue.
func (q *TDPQueue) PopFront() TDPItem {
	q.empty.L.Lock()
	for q.Len() == 0 {
		q.empty.Wait()
	}
	q.empty.L.Unlock()

	q.mutex.Lock()
	_res := q.q.Front()
	if _res == nil {
		q.mutex.Unlock()
		return nil
	}
	res := _res.Value
	q.q.Remove(_res)
	q.length -= 1
	q.mutex.Unlock()

	q.full.Signal()
	return res
}

// return the length of current queue.
func (q *TDPQueue) Len() int32 {
	res := atomic.LoadInt32(&q.length)
	return res
}
