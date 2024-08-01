// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/zuc"
)

const (
	zucKeySize = 32
	zucIvSize  = 23
)

type ZUC struct {
	Key       [zucKeySize]byte
	Iv        [zucIvSize]byte
	encstream cipher.Stream
	decstream cipher.Stream
}

func (_zuc *ZUC) EncryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))
	if _zuc.encstream == nil {
		stream, err := zuc.NewCipher(_zuc.Key[:], _zuc.Iv[:])
		if err != nil {
			return nil, err
		}
		_zuc.encstream = stream
	}
	_zuc.encstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (_zuc *ZUC) DecryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))

	if _zuc.decstream == nil {
		stream, err := zuc.NewCipher(_zuc.Key[:], _zuc.Iv[:])
		if err != nil {
			return nil, err
		}
		_zuc.decstream = stream
	}
	_zuc.decstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (_zuc *ZUC) GetKeyLen() uint64      { return zucKeySize }
func (_zuc *ZUC) GetIvLen() uint64       { return zucIvSize }
func (_zuc *ZUC) GetKeyIvLen() uint64    { return zucKeySize + zucIvSize }
func (_zuc *ZUC) SetKey(key []byte)      { _zuc.Key = [zucKeySize]byte(key) }
func (_zuc *ZUC) SetIv(iv []byte)        { _zuc.Iv = [zucIvSize]byte(iv) }
func (_zuc *ZUC) GetKey() []byte         { return _zuc.Key[:] }
func (_zuc *ZUC) GetIv() []byte          { return _zuc.Iv[:] }
func (_zuc *ZUC) WithIvAttached() uint64 { return 0 }
