// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	AES_CTR struct {
		Key       [KeySize]byte
		Iv        [IVSize]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}
	AES_OFB struct {
		Key       [KeySize]byte
		Iv        [IVSize]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}

	/*
	   a loop like label_1 can perform well as long as no man in the middle.

	   label_1:

	   	c       ep
	   	e------>d
	   	d<------e

	   label_2: however, scenario label_1 can not work on this:

	   	c
	   	e->+
	   	   |
	   	d<-+

	   label_3: if there are even going to be multiple entities forming a p2p encrypted network,
	   these methods are extremely terrible. Proper and plausible SMPC is a must but it is too complicated.
	*/
	AES_GCM struct {
		Key      [KeySize]byte
		Iv       [IVSize]byte
		shadowIv [IVSize]byte
		stream   cipher.AEAD
	}
)

// CTR
func (a *AES_CTR) EncryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))
	if a.encstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}
		a.encstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (a *AES_CTR) DecryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))
	if a.decstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}
		a.decstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (a *AES_CTR) SetKey(key []byte) {
	a.Key = [KeySize]byte(key)
}

func (a *AES_CTR) SetIv(iv []byte) {
	a.Iv = [IVSize]byte(iv)
}

func (a *AES_CTR) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_CTR) GetIv() []byte {
	return a.Iv[:]
}

// OFB
func (a *AES_OFB) EncryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))

	if a.encstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}

		a.encstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (a *AES_OFB) DecryptFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))

	if a.decstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}

		a.decstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (a *AES_OFB) SetKey(key []byte) {
	a.Key = [32]byte(key)
}

func (a *AES_OFB) SetIv(iv []byte) {
	a.Iv = [16]byte(iv)
}

func (a *AES_OFB) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_OFB) GetIv() []byte {
	return a.Iv[:]
}

// GCM
func (a *AES_GCM) EncryptFlow(msg []byte) []byte {
	if a.stream == nil {
		cc, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}
		stream, err := cipher.NewGCM(cc)
		if err != nil {
			panic(err)
		}
		a.stream = stream
	}
	res := a.stream.Seal(nil, a.Iv[:], msg, a.Iv[:])
	for i := 0; i < IVSize; i++ {
		a.Iv[i] = byte(uint16((a.Iv[i] + (a.Iv[(i-1+IVSize)%IVSize] << 1))))
	}
	return res
}

func (a *AES_GCM) DecryptFlow(msg []byte) []byte {
	if a.stream == nil {
		cc, err := aes.NewCipher(a.Key[:])
		if err != nil {
			panic(err)
		}
		stream, err := cipher.NewGCM(cc)
		if err != nil {
			panic(err)
		}
		a.stream = stream
	}
	res, err := a.stream.Open(nil, a.shadowIv[:], msg, a.shadowIv[:])
	if err != nil {
		panic(err)
	}
	for i := 0; i < IVSize; i++ {
		a.shadowIv[i] = byte(uint16((a.shadowIv[i] + (a.shadowIv[(i-1+IVSize)%IVSize] << 1))))
	}
	return res
}

func (a *AES_GCM) SetKey(key []byte) {
	a.Key = [32]byte(key)
	a.stream = nil
}

func (a *AES_GCM) SetIv(iv []byte) {
	a.Iv = [16]byte(iv)
	a.shadowIv = [16]byte(iv)
}

func (a *AES_GCM) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_GCM) GetIv() []byte {
	return a.Iv[:]
}
