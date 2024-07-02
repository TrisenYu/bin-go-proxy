// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"log"
	"testing"
)

func TestSplitByteArr(t *testing.T) {
	pwna := []byte{}
	pwnb := []byte{0x1}
	pwnc := []byte{0x10, 0x20, 0x30}
	pwnd := []byte{0x20, 0x30, 0xFF, 0x33, 0xAb}
	_l, _h := BytesSpliterInHalfChanceField(pwna)
	log.Println(_l, _h)
	_l, _h = BytesSpliterInHalfChanceField(pwnb)
	log.Println(_l, _h)
	_l, _h = BytesSpliterInHalfChanceField(pwnc)
	log.Println(_l, _h)
	_l, _h = BytesSpliterInHalfChanceField(pwnd)
	log.Println(_l, _h)
	pwne := []byte(GenerateEnterableRandomString(2048))
	_l, _h = BytesSpliterInHalfChanceField(pwne)
	log.Println(len(_l), len(_h))
	pwnf := []byte(GenerateEnterableRandomString(4097))
	_l, _h = BytesSpliterInHalfChanceField(pwnf)
	log.Println(len(_l), len(_h))
}
