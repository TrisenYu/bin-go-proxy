//go:build linux
// +build linux

// SPDX-LICENSE-IDENTIFIER: GPL-2.0
// (C) 2024 Author: <kisfg@hotmail.com>
package interceptor

import "os/exec"

func InitGlobalHijack() {
	// TODO
	return
}

func ExitGlobalHijack() {
	// TODO
	return
}

func InitTunOnLinux() {
	/*
		ip tuntap add mode tun dev tun0 	# create
		ip addr add 198.18.0.1/15 dev tun0	# allocate networke segment
		ip link set dev tun0 up				# setup
		ip tuntap del mode tun dev tun0 	# delete
	*/

	cmd := exec.Command("ip", "tuntap", "add", "dev", "proxyTun", "mod", "tun")
	cmd.Run()
	cmd = exec.Command("ip", "addr", "add", "172.16.0.1/16", "dev", "proxyTun")
	cmd.Run()
	cmd = exec.Command("ip", "addr", "add", "fd00::1/8", "dev", "proxyTun")
	cmd.Run()
	cmd = exec.Command("ip", "link", "set", "proxyTun", "up")
	cmd.Run()
}

func TunOffAndClean() {
	cmd := exec.Command("ip", "tuntap", "del", "dev", "proxyTun", "mod", "tun")
	cmd.Run()
}
