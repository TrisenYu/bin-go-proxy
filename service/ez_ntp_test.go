package service

import "testing"

func TestNtp(t *testing.T) {
	if err := AccessCurrTime(8); err != nil {
		t.Errorf(err.Error())
	}
}
