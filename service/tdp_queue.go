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
		length, boundary int32
		IsDead           atomic.Bool
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
	q.IsDead.Store(false)
	if max_queue_size <= 0 {
		q.boundary = default_size
	} else {
		q.boundary = max_queue_size
	}
}

// push one item into queue.
// if item is `struct{}` or `nil`, do nothing and return.
func (q *TDPQueue) PushBack(msg TDPItem) {
	switch msg.(type) {
	case struct{}:
		return
	case nil:
		return
	default:
	}
	if q.IsDead.Load() {
		return
	}
	q.full.L.Lock()
	for q.Len() == q.boundary {
		q.full.Wait() /// Wait for state of not full
	}
	if q.IsDead.Load() {
		q.empty.Broadcast() /// immediately kill all
		q.full.L.Unlock()
		return
	}
	q.q.PushBack(msg)
	q.length += 1

	q.empty.Signal() /// not empty any more.
	q.full.L.Unlock()
}

// return nil if queue is empty. pop one item from the head of queue.
func (q *TDPQueue) PopFront() TDPItem {
	if q.IsDead.Load() {
		return nil
	}
	q.empty.L.Lock()
	for q.Len() == 0 {
		q.empty.Wait()
	}
	if q.IsDead.Load() {
		q.full.Broadcast() /// immediately kill all
		q.empty.L.Unlock() // TODO: it seems like a bad implementation.
		return nil
	}
	_res := q.q.Front()
	if _res == nil {
		q.empty.L.Unlock()
		return nil
	}
	res := _res.Value
	q.q.Remove(_res)
	q.length -= 1
	q.full.Signal()
	q.empty.L.Unlock()
	return res
}

// return the length of current queue.
func (q *TDPQueue) Len() int32 {
	res := atomic.LoadInt32(&q.length)
	return res
}

// notify to reset.
func (q *TDPQueue) DeadReset() {
	q.IsDead.Store(true)
}

// recover the queue.
func (q *TDPQueue) DeadRecover() {
	// TODO Check if the list is empty. If not, pop all.
	q.IsDead.Store(false)
}
