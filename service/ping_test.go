// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package service

import (
	"log"
	"testing"
)

func TestPing(t *testing.T) {
	// t.me => unreachable in the Chinese Mainland due to GFW.
	max_ttl, flag := CheckConnectionByPing("baidu.com", 3)
	if !flag {
		t.Error(`bad ping`)
	}
	log.Println(max_ttl, `ms`)
}
