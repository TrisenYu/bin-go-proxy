// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

type SM4_OFB struct {
	Key [KeySize]byte
	Iv  [IVSize]byte
}

type SM4_CTR struct {
	Key [KeySize]byte
	Iv  [IVSize]byte
}

func (s *SM4_OFB) FlipFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	block, err := sm4.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, s.Iv[:])
	xor_res := make([]byte, len(msg))
	stream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_CTR) FlipFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	block, err := sm4.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, s.Iv[:])
	xor_res := make([]byte, len(msg))
	stream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_CTR) SetKey(key []byte) {
	s.Key = [KeySize]byte(key)
}

func (s *SM4_CTR) SetIv(iv []byte) {
	s.Iv = [IVSize]byte(iv)
}

func (s *SM4_CTR) GetKey() []byte {
	return s.Key[:]
}

func (s *SM4_CTR) GetIv() []byte {
	return s.Iv[:]
}

func (s *SM4_OFB) SetKey(key []byte) {
	s.Key = [KeySize]byte(key)
}

func (s *SM4_OFB) SetIv(iv []byte) {
	s.Iv = [IVSize]byte(iv)
}

func (s *SM4_OFB) GetKey() []byte {
	return s.Key[:]
}

func (s *SM4_OFB) GetIv() []byte {
	return s.Iv[:]
}
