// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/rand"
	"log"
	"testing"

	utils "selfproxy/utils"
)

func TestFieldTransformation(t *testing.T) {
	functor := func(s *uint32, data int) {
		if data != 0 {
			if data == 0xFF {
				data = 0x119
			}
			*s = uint32(data)
		} else {
			*s = 293
		}
	}
	var cnt [256]int = [256]int{}
	for i := 0; i < 256; i++ {
		var (
			tmpi uint32
			tmpj uint32
		)
		functor(&tmpi, i)
		for j := 0; j < 0x100; j++ {
			functor(&tmpj, j)
			now := tmpi * tmpj
			ll := now & 0xFF
			lh := (now >> 8) & 0xFF
			hl := (now >> 16) & 0xFF
			tmp := uint8(ll^lh^hl) ^ uint8((tmpi&0xFF)^((tmpi>>8)&0xFF))
			cnt[tmp]++
		}
	}
	for i := 0; i < 0x100; i++ {
		log.Printf("%X %v\n", i, cnt[i])
	}
}

func TestSalsa20(t *testing.T) {
	var (
		key [32]byte
		iv  [16]byte
	)
	rand.Read(key[:])
	rand.Read(iv[:])
	enc := Salsa20FlipCrypt([]byte(`hello world`), key, iv)
	utils.BytesHexForm(enc)
	recovery := Salsa20FlipCrypt(enc, key, iv)
	if string(recovery) != `hello world` {
		t.Error(`invalid chacha enc-dec-op.`)
	}
}

func TestSha256(t *testing.T) {
	hello := CalculateFlowSha256Hash([]byte(`hello world`))
	utils.BytesHexForm(hello[:])
}

func TestLatticeCipher(t *testing.T) {
	log.Println(`-----------------`)
	// TODO.
}
