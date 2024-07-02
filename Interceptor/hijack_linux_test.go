//go:build linux
// +build linux

package interceptor

import (
	"testing"

	service "selfproxy/service"
)

func TestTunDev(t *testing.T) {
	InitTunOnLinux()
	_, checker := service.CheckConnectionByPing("172.16.0.1", 1)
	if !checker {
		t.Errorf("unable to ping.")
	}
	_, checker = service.CheckConnectionByPing("fd00::1", 1)
	if !checker {
		t.Errorf("unable to ping.")
	}
	TunOffAndClean()
}
