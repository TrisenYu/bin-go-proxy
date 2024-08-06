//go:build windows
// +build windows

package service

import (
	"log"
	"syscall"
)

func TCPPing(saddr, daddr string) (int, error) {
	var (
		fd     syscall.Handle
		choice int
	)
	log.Println(fd, choice)
	return -1, nil
}
