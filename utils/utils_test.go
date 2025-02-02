// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"log"
	"testing"
)

func TestSplitByteArr(t *testing.T) {
	{
		_l, _h := BytesSplitInHalfChanceField([]byte{})
		log.Println(_l, _h)
	}
	{
		_l, _h := BytesSplitInHalfChanceField([]byte{0x1})
		log.Println(_l, _h)
	}
	{
		_l, _h := BytesSplitInHalfChanceField([]byte{0x10, 0x20, 0x30})
		log.Println(_l, _h)
	}
	{
		_l, _h := BytesSplitInHalfChanceField([]byte{0x20, 0x30, 0xFF, 0x33, 0xAb})
		log.Println(_l, _h)
	}
	{
		pwne := []byte(GenerateEnterableRandomString(2048))
		_l, _h := BytesSplitInHalfChanceField(pwne)
		log.Println(len(_l), len(_h))
	}
	{
		pwnf := []byte(GenerateEnterableRandomString(4097))
		_l, _h := BytesSplitInHalfChanceField(pwnf)
		log.Println(len(_l), len(_h))
	}
}
