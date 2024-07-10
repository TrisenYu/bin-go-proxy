// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/zuc"
)

func ZUCFlipFlow(obj []byte, key []byte, iv []byte) []byte {
	/*
		The IV needs to be unique, but not secure. Therefore it's common to
		include it at the beginning of the ciphertext.
	*/
	xor_res := make([]byte, len(obj))
	stream, err := zuc.NewCipher(key, iv)
	if err != nil {
		panic(err)
	}
	stream.XORKeyStream(xor_res, obj)
	return xor_res
}

type ZUC struct {
	Key       [KeySize]byte
	Iv        [IVSize]byte
	iv        [zuc.IVSize256 - IVSize]byte // alien. latent overflow risk
	encstream cipher.Stream
	decstream cipher.Stream
}

func (_zuc *ZUC) EncryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))
	extend_iv := [zuc.IVSize256]byte{}
	copy(extend_iv[:IVSize], _zuc.Iv[:])
	copy(extend_iv[IVSize:], _zuc.iv[:])
	if _zuc.encstream == nil {
		stream, err := zuc.NewCipher(_zuc.Key[:], extend_iv[:])
		if err != nil {
			panic(err)
		}
		_zuc.encstream = stream
	}
	_zuc.encstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (_zuc *ZUC) DecryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))
	extend_iv := [zuc.IVSize256]byte{}
	copy(extend_iv[:IVSize], _zuc.Iv[:])
	copy(extend_iv[IVSize:], _zuc.iv[:])
	if _zuc.decstream == nil {
		stream, err := zuc.NewCipher(_zuc.Key[:], extend_iv[:])
		if err != nil {
			panic(err)
		}
		_zuc.decstream = stream
	}
	_zuc.decstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (_zuc *ZUC) SetKey(key []byte) {
	_zuc.Key = [KeySize]byte(key)
}

func (_zuc *ZUC) SetIv(iv []byte) {
	_zuc.Iv = [IVSize]byte(iv)
	tmp := [zuc.IVSize256 - IVSize]byte{}
	for i := 0; i < zuc.IVSize256-IVSize; i++ {
		tmp[i] = (_zuc.Iv[i] + _zuc.Iv[IVSize-1-i]) & 0xFF
	}
	copy(_zuc.iv[:], tmp[:])
}

func (_zuc *ZUC) GetKey() []byte {
	return _zuc.Key[:]
}

func (_zuc *ZUC) GetIv() []byte {
	return _zuc.Iv[:]
}
