// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import "testing"

func TestNtp(t *testing.T) {
	if _, err := AccessCurrTime(7); err != nil {
		t.Errorf(err.Error())
	}
}
