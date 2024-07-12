package service

import "testing"

func TestNtp(t *testing.T) {
	if _, err := AccessCurrTime(7); err != nil {
		t.Errorf(err.Error())
	}
}
