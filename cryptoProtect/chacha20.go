// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Chacha20poly1305 struct {
	Key      [KeySize]byte
	Iv       [IVSize]byte
	shadowIv [IVSize]byte
	stream   cipher.AEAD
}

func (c *Chacha20poly1305) EncryptFlow(msg []byte) ([]byte, error) {
	var extend_iv [GoogleCiphersNonceLen]byte
	copy(extend_iv[:IVSize], c.Iv[:])
	for i := IVSize; i < GoogleCiphersNonceLen; i++ {
		extend_iv[i] = byte(c.Iv[i-IVSize] + c.Iv[i-IVSize/2])
	}
	if c.stream == nil {
		cc, err := chacha20poly1305.NewX(c.Key[:])
		if err != nil {
			return nil, err
		}
		c.stream = cc
	}
	res := c.stream.Seal(nil, extend_iv[:], msg, c.Iv[:])

	for i := 0; i < IVSize; i++ {
		c.Iv[i] = byte(uint16((c.Iv[i] + (c.Iv[(i-1+IVSize)%IVSize] << 1))))
	}

	return res, nil
}

func (c *Chacha20poly1305) DecryptFlow(msg []byte) ([]byte, error) {
	var extend_iv [GoogleCiphersNonceLen]byte
	copy(extend_iv[:IVSize], c.shadowIv[:])
	for i := IVSize; i < GoogleCiphersNonceLen; i++ {
		extend_iv[i] = byte(c.shadowIv[i-IVSize] + c.shadowIv[i-IVSize/2])
	}
	if c.stream == nil {
		cc, err := chacha20poly1305.NewX(c.Key[:])
		if err != nil {
			return nil, err
		}
		c.stream = cc
	}
	res, err := c.stream.Open(nil, extend_iv[:], msg, c.shadowIv[:])
	if err != nil {
		return nil, err
	}

	for i := 0; i < IVSize; i++ {
		c.shadowIv[i] = byte(uint16((c.shadowIv[i] + (c.shadowIv[(i-1+IVSize)%IVSize] << 1))))
	}
	return res, nil
}

func (c *Chacha20poly1305) SetKey(key []byte) {
	c.Key = [KeySize]byte(key)
	c.stream = nil
}

func (c *Chacha20poly1305) SetIv(iv []byte) {
	c.Iv = [IVSize]byte(iv)
	c.shadowIv = [IVSize]byte(iv)
}

func (c *Chacha20poly1305) GetKey() []byte {
	return c.Key[:]
}

func (c *Chacha20poly1305) GetIv() []byte {
	return c.Iv[:]
}
