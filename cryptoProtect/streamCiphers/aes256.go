// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/aes"
	"crypto/cipher"
)

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

type (
	AES_CTR_256 struct {
		Key       [32]byte
		Iv        [16]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}
	AES_OFB_256 struct {
		Key       [32]byte
		Iv        [16]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}
	AES_GCM_256 struct {
		Key       [32]byte
		Iv        [12]byte
		encstream cipher.AEAD
		decstream cipher.AEAD
	}
)

// CTR
func (a *AES_CTR_256) EncryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))
	if a.encstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}
		a.encstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_CTR_256) DecryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))
	if a.decstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}
		a.decstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_CTR_256) SetKey(key []byte) {
	a.Key = [32]byte(key)
}

func (a *AES_CTR_256) SetIv(iv []byte) {
	a.Iv = [16]byte(iv)
}

func (a *AES_CTR_256) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_CTR_256) GetIv() []byte {
	return a.Iv[:]
}

// return the length of key.
func (a *AES_CTR_256) GetKeyLen() uint64 {
	return 32
}

// return the length of iv.
func (a *AES_CTR_256) GetIvLen() uint64 {
	return 16
}

// return the length of key and iv.
func (a *AES_CTR_256) GetKeyIvLen() uint64 {
	return 48
}

// return 0 if IV does not need attaching to the preamble of one datagram.
func (a *AES_CTR_256) WithIvAttached() uint64 {
	return 0
}

// OFB
func (a *AES_OFB_256) EncryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))

	if a.encstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}

		a.encstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_OFB_256) DecryptFlow(msg []byte) ([]byte, error) {
	xor_res := make([]byte, len(msg))

	if a.decstream == nil {
		block, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}

		a.decstream = cipher.NewCTR(block, a.Iv[:])
	}
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_OFB_256) SetKey(key []byte) {
	a.Key = [32]byte(key)
}

func (a *AES_OFB_256) SetIv(iv []byte) {
	a.Iv = [16]byte(iv)
}

func (a *AES_OFB_256) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_OFB_256) GetIv() []byte {
	return a.Iv[:]
}

// return the length of key.
func (a *AES_OFB_256) GetKeyLen() uint64 {
	return 32
}

// return the length of iv.
func (a *AES_OFB_256) GetIvLen() uint64 {
	return 16
}

// return the length of key and iv.
func (a *AES_OFB_256) GetKeyIvLen() uint64 {
	return 48
}

// return 0 if IV does not need attaching to the preamble of one datagram.
func (a *AES_OFB_256) WithIvAttached() uint64 {
	return 0
}

// GCM
func (a *AES_GCM_256) EncryptFlow(msg []byte) ([]byte, error) {
	if a.encstream == nil {
		cc, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}
		stream, err := cipher.NewGCM(cc)
		if err != nil {
			return nil, err
		}
		a.encstream = stream
	}
	res := a.encstream.Seal(nil, a.Iv[:], msg, nil)
	return res, nil
}

func (a *AES_GCM_256) DecryptFlow(msg []byte) ([]byte, error) {
	if a.decstream == nil {
		cc, err := aes.NewCipher(a.Key[:])
		if err != nil {
			return nil, err
		}
		stream, err := cipher.NewGCM(cc)
		if err != nil {
			return nil, err
		}
		a.decstream = stream
	}
	res, err := a.decstream.Open(nil, a.Iv[:], msg, nil)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *AES_GCM_256) SetKey(key []byte) {
	a.Key = [32]byte(key)
	a.encstream, a.decstream = nil, nil
}

func (a *AES_GCM_256) SetIv(iv []byte) {
	a.Iv = [12]byte(iv)
}

func (a *AES_GCM_256) GetKey() []byte {
	return a.Key[:]
}

func (a *AES_GCM_256) GetIv() []byte {
	return a.Iv[:]
}

// return the length of key.
func (a *AES_GCM_256) GetKeyLen() uint64 {
	return 32
}

// return the length of iv.
func (a *AES_GCM_256) GetIvLen() uint64 {
	return 12
}

// return the length of key and iv.
func (a *AES_GCM_256) GetKeyIvLen() uint64 {
	return 44
}

// return 0 if IV does not need attaching to the preamble of one datagram.
func (a *AES_GCM_256) WithIvAttached() uint64 {
	return 16
}
