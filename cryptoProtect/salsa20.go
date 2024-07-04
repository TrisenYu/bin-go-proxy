// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import "golang.org/x/crypto/salsa20"

// Deprecated
func Salsa20FlipCrypt(inp []byte, key [32]byte, iv [16]byte) []byte {
	oup := make([]byte, len(inp))
	var extend_iv [24]byte
	copy(extend_iv[:16], iv[:])
	for i := 16; i < 24; i++ {
		extend_iv[i] = iv[i-16] ^ iv[i-8]
	}
	salsa20.XORKeyStream(oup, inp, extend_iv[:], &key)
	return oup
}

const Salsa20NonceLen int = 24

type Salsa20 struct {
	Key [KeySize]byte
	Iv  [IVSize]byte
}

func (_salsa20 *Salsa20) FlipFlow(msg []byte) []byte {
	oup := make([]byte, len(msg))
	var extend_iv [Salsa20NonceLen]byte
	copy(extend_iv[:IVSize], _salsa20.Iv[:])
	for i := IVSize; i < Salsa20NonceLen; i++ {
		extend_iv[i] = _salsa20.Iv[i-IVSize] ^ _salsa20.Iv[i-IVSize/2]
	}
	salsa20.XORKeyStream(oup, msg, extend_iv[:], &_salsa20.Key)
	return oup
}

func (_salsa20 *Salsa20) SetKey(key []byte) {
	_salsa20.Key = [KeySize]byte(key)
}

func (_salsa20 *Salsa20) SetIv(iv []byte) {
	copy(_salsa20.Iv[:], iv[:IVSize])
}

func (_salsa20 *Salsa20) GetKey() []byte {
	return _salsa20.Key[:]
}

func (_salsa20 *Salsa20) GetIv() []byte {
	return _salsa20.Iv[:]
}
