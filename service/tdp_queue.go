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
	Queue interface {
		PushBack() interface{} // pop item from queueHead.
		PopFront(interface{})  // push item to queue
		Len() int64            // length of current queue.
	}

	ReverseIDMessageQueue struct {
		q      list.List
		empty  *sync.Cond
		length int32
	}
	AddrMessageQueue struct {
		q      list.List
		length int32
		empty  *sync.Cond
	}
	EventNotifyQueue struct {
		q      list.List
		length int32
		empty  *sync.Cond
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

// I am not sure if this work.
func (m *ReverseIDMessageQueue) Init() {
	m.empty = &sync.Cond{}
}

func (a *AddrMessageQueue) Init() {
	a.empty = &sync.Cond{}
}

// push message into queue.
func (m *ReverseIDMessageQueue) PushBack(msg ReverseIDMessage) {
	m.empty.L.Lock()
	defer m.empty.L.Unlock()
	m.q.PushBack(msg)
	atomic.AddInt32(&m.length, 1)
	m.empty.Broadcast()
}

// return nil if queue is empty.
func (m *ReverseIDMessageQueue) PopFront() ReverseIDMessage {
	m.empty.L.Lock()
	defer m.empty.L.Unlock()
	for m.Len() == 0 {
		m.empty.Wait()
	}

	_res := m.q.Front()
	if _res == nil {
		return ReverseIDMessage{}
	}
	res := _res.Value.(ReverseIDMessage)
	m.q.Remove(_res)
	atomic.AddInt32(&m.length, -1)
	return res
}

// return the length of queue.
func (m *ReverseIDMessageQueue) Len() int32 {
	res := atomic.LoadInt32(&m.length)
	return res
}

// push AddrMessage into queue. there is no limitation on pushing one item to the queue.
func (a *AddrMessageQueue) PushBack(msg AddrMessage) {
	a.empty.L.Lock()
	a.q.PushBack(msg)
	atomic.AddInt32(&a.length, 1)
	a.empty.L.Unlock()
	a.empty.Broadcast()
}

// block if no item in queue. when being notified, this function will fetch one item from queue.
// if nothing is inside the queue, return nil.
// otherwise remove and reture the item.
func (a *AddrMessageQueue) PopFront() AddrMessage {
	a.empty.L.Lock()
	defer a.empty.L.Unlock()
	for a.Len() == 0 {
		a.empty.Wait()
	}

	_res := a.q.Front()
	if _res == nil {
		return AddrMessage{}
	}
	res := _res.Value.(AddrMessage)
	a.q.Remove(_res)
	atomic.AddInt32(&a.length, -1)
	return res
}

// return the length of queue.
func (a *AddrMessageQueue) Len() int32 {
	res := atomic.LoadInt32(&a.length)
	return res
}

// push message into queue.
func (e *EventNotifyQueue) PushBack(msg interface{}) {
	// if the msg is struct{}, then there is no need for enqueueing.
	switch msg.(type) {
	case struct{}:
		return
	case nil:
		return
	default:
	}
	e.empty.L.Lock()
	defer e.empty.L.Unlock()
	e.q.PushBack(msg)
	atomic.AddInt32(&e.length, 1)
	e.empty.Broadcast()
}

// return nil if queue is empty.
func (e EventNotifyQueue) PopFront() interface{} {
	e.empty.L.Lock()
	defer e.empty.L.Unlock()
	for e.Len() == 0 {
		e.empty.Wait()
	}

	_res := e.q.Front()
	if _res == nil {
		return nil
	}
	res := _res.Value
	e.q.Remove(_res)
	atomic.AddInt32(&e.length, -1)
	return res
}

// return the length of queue.
func (e EventNotifyQueue) Len() int32 {
	res := atomic.LoadInt32(&e.length)
	return res
}
