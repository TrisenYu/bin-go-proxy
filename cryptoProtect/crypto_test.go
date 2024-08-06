// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	crand "crypto/rand"
	"log"
	"reflect"
	"testing"

	asymmetricciphers "bingoproxy/cryptoProtect/asymmetricCiphers"
	hashciphers "bingoproxy/cryptoProtect/hashCiphers"
	streamciphers "bingoproxy/cryptoProtect/streamCiphers"
	utils "bingoproxy/utils"

	"golang.org/x/crypto/blake2b"
)

var ez_payload = []byte(`0ne can be arbitrarily defined as ni1.`)

func TestCipher(t *testing.T) {
	/* asymmetricCipher */
	{
		commutator := []AsymmCipher{&asymmetricciphers.SM2{}}
		val := commutator[0]
		lena := val.GetPubLen()
		val.GenerateKeyPair()
		key := make([]byte, lena)
		val.GetPub(&key)
		utils.AddTag2HexHeader(key, `pub-key is`)
		enc, err := val.PubEncrypt(ez_payload)
		if err != nil {
			t.Error(err)
			return
		}
		dec, err := val.PemDecrypt(enc)
		if err != nil {
			t.Error(err)
			return
		}
		f, _ := utils.CmpByte2Slices(dec, ez_payload)
		if !f {
			t.Error(`invalid decryption for wrong output`)
			return
		}
		clear(commutator)
	}
	/* hashcipher */
	{
		Commutator := []HashCipher{
			&hashciphers.SM3{},
			&hashciphers.Sha256{},
			&hashciphers.Sha384{},
			&hashciphers.Sha512{},
			&hashciphers.Sha3_256{},
			&hashciphers.Sha3_384{},
			&hashciphers.Sha3_512{},
			&hashciphers.Blake2b256{},
			&hashciphers.Blake2s256{},
			&hashciphers.Blake2b384{},
			&hashciphers.Blake2b512{},
		}
		log.Println(`payload: `, string(ez_payload))
		for idx, val := range Commutator {
			lena := val.GetHashLen()
			hmac := val.CalculateHashOnce(ez_payload)
			utils.AddTag2HexHeader(hmac, idx, lena, reflect.TypeOf(val).Elem().Name())
		}
		clear(Commutator)
	}
	/* streamcipher */
	{
		Commutator := []StreamCipher{
			&streamciphers.AES_CTR_256{},
			&streamciphers.AES_OFB_256{},
			&streamciphers.AES_GCM_256{},
			&streamciphers.SM4_CTR{},
			&streamciphers.SM4_OFB{},
			&streamciphers.SM4_GCM{},
			&streamciphers.Chacha20poly1305{},
			&streamciphers.ZUC{},
			&streamciphers.Salsa20{},
		}

		for idx, val := range Commutator {
			keyLen, ivLen := val.GetKeyLen(), val.GetIvLen()
			key, iv := make([]byte, keyLen), make([]byte, ivLen)
			crand.Read(key)
			crand.Read(iv)
			val.SetKey(key)
			val.SetIv(iv)

			enc, err := val.EncryptFlow(ez_payload)
			if err != nil {
				t.Error(idx, reflect.TypeOf(val).Elem().Name(), `encryption failure: `, err)
				return
			}
			dec, err := val.DecryptFlow(enc)
			if err != nil {
				t.Error(idx, reflect.TypeOf(val).Elem().Name(), `decryption failure: `, err)
				return
			}
			f, _ := utils.CmpByte2Slices(dec, ez_payload)
			if !f {
				t.Error(idx, reflect.TypeOf(val).Elem().Name(), `decryption failure: wrong output`)
				return
			}
		}
		clear(Commutator)
	}
	// single testcase for shilly-shally problem in hand.
	{
		hasher, err := blake2b.New512(nil)
		if err != nil {
			t.Error(err)
			return
		}
		log.Println(hasher.Size(), hasher.BlockSize())
		hasher.Write(ez_payload)
		tmp := hasher.Sum(nil)
		utils.BytesHexForm(tmp)
		hasher.Write(ez_payload)
		utils.BytesHexForm(hasher.Sum(nil))
		hasher.Reset()
		tmp = hasher.Sum(nil)
		utils.BytesHexForm(tmp)
	}
}
