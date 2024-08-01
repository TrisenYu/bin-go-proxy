// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Chacha20poly1305 struct {
	Key                  [32]byte
	Iv                   [24]byte
	encStream, decStream cipher.AEAD
}

func (c *Chacha20poly1305) generateAead(aead *cipher.AEAD) (err error) {
	if *aead != nil {
		return nil
	}
	*aead, err = chacha20poly1305.NewX(c.Key[:])
	return err
}

func (c *Chacha20poly1305) EncryptFlow(msg []byte) ([]byte, error) {
	err := c.generateAead(&c.encStream)
	if err != nil {
		return nil, err
	}
	res := c.encStream.Seal(nil, c.Iv[:], msg, nil)
	return res, nil
}

func (c *Chacha20poly1305) DecryptFlow(msg []byte) ([]byte, error) {
	err := c.generateAead(&c.decStream)
	if err != nil {
		return nil, err
	}
	res, err := c.decStream.Open(nil, c.Iv[:], msg, nil)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Chacha20poly1305) SetKey(key []byte) {
	c.Key = [32]byte(key)
	c.encStream, c.decStream = nil, nil
}

func (c *Chacha20poly1305) SetIv(iv []byte) {
	c.Iv = [24]byte(iv)
}

func (c *Chacha20poly1305) GetKey() []byte {
	return c.Key[:]
}

func (c *Chacha20poly1305) GetIv() []byte {
	return c.Iv[:]
}

// return the length of key.
func (c *Chacha20poly1305) GetKeyLen() uint64 {
	return 32
}

// return the length of iv.
func (c *Chacha20poly1305) GetIvLen() uint64 {
	return 24
}

func (c *Chacha20poly1305) GetKeyIvLen() uint64 {
	return 56
}

// return 0 if IV does not need attaching to the preamble of one datagram.
func (c *Chacha20poly1305) WithIvAttached() uint64 {
	return 16
}
