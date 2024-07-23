// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package socket

import (
	"errors"
	"net"
)

type Socket struct {
	Conn net.Conn
}

func (s *Socket) Read() ([]byte, uint, error) {
	if s.Conn == nil {
		return []byte{}, 0, errors.New(`tried to write on an empty connection`)
	}
	res := make([]byte, 2048)
	cnt, err := s.Conn.Read(res)
	choice := min(cnt, 2048)
	if choice != cnt {
		err = errors.New(`incoming flow exccedd the maximum capicity(2048) of recv-buf, need continous recv`)
	}
	return res[:choice], uint(choice), err
}

func (s *Socket) Write(msg []byte) (uint, error) {
	if s.Conn == nil {
		return 0, errors.New(`tried to write on an empty connection`)
	}
	cnt, err := s.Conn.Write(msg)
	return uint(cnt), err
}

func (s *Socket) CloseAll() {
	if s.Conn == nil {
		return
	}
	s.Conn.Close()
}
