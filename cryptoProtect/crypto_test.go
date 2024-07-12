// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"log"
	"testing"

	utils "bingoproxy/utils"
)

func TestCiphers(t *testing.T) {
	var test_cipher StreamCipher = &SM4_GCM{}
	key, iv, err := GeneratePresessionKey()
	if err != nil {
		t.Error(err)
	}
	test_cipher.SetKey(key)
	test_cipher.SetIv(iv)

	helo := "hello words!!!!!!I am the storm that is approaching"
	res := test_cipher.EncryptFlow([]byte(helo))
	res1 := test_cipher.EncryptFlow([]byte(helo))
	log.Println(`res: `)
	utils.BytesHexForm(res)
	log.Println(`res1: `)
	utils.BytesHexForm(res1)
	dec := test_cipher.DecryptFlow(res)
	dec1 := test_cipher.DecryptFlow(res1)

	log.Println(`decrypt from res: `)
	utils.BytesHexForm(dec)
	log.Println(`decrypt from res1: `)
	utils.BytesHexForm(dec1)
	log.Println(`real msg: `)
	utils.BytesHexForm([]byte(helo))
}

func TestSalsa20(t *testing.T) {
	var test_cipher StreamCipher = &Salsa20{}
	key, iv, err := GeneratePresessionKey()
	if err != nil {
		t.Error(err)
	}
	test_cipher.SetKey(key)
	test_cipher.SetIv(iv)

	helo := "hello words!!!!!!I am the storm that is approaching"
	res := test_cipher.EncryptFlow([]byte(helo))
	res1 := test_cipher.EncryptFlow([]byte(helo))
	log.Println(`res: `)
	utils.BytesHexForm(res)
	log.Println(`res1: `)
	utils.BytesHexForm(res1)
	dec := test_cipher.DecryptFlow(res)
	dec1 := test_cipher.DecryptFlow(res1)

	log.Println(`decrypt from res: `)
	utils.BytesHexForm(dec)
	log.Println(`decrypt from res1: `)
	utils.BytesHexForm(dec1)
	log.Println(`real msg: `)
	utils.BytesHexForm([]byte(helo))
}

func TestSha256(t *testing.T) {
	hello := CalculateFlowSha256Hash([]byte(`hello world`))
	log.Println(`Sha256 of "hello world": `)
	utils.BytesHexForm(hello[:])
}

func TestLatticeCipher(t *testing.T) {
	log.Println(`-----------------`)
	// TODO.
}
