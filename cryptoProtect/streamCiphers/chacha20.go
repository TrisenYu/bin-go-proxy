// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chacha20polyKeyLen        = 32
	chacha20polyIvLen         = 24
	chacha20polyExtAttachedIv = 16
)

type Chacha20poly1305 struct {
	Key                  [chacha20polyKeyLen]byte
	Iv, iv               [chacha20polyIvLen]byte
	encStream, decStream cipher.AEAD
}

func (c *Chacha20poly1305) generateAead(aead *cipher.AEAD) (err error) {
	if *aead != nil {
		return nil
	}
	*aead, err = chacha20poly1305.NewX(c.Key[:])
	return err
}

func (c *Chacha20poly1305) ivRotate(inp *[chacha20polyIvLen]byte) {
	lena := chacha20polyIvLen
	for i := 0; i < lena; i++ {
		(*inp)[i] = (GaloisBox[(*inp)[(i+lena-1)%lena]] + (*inp)[i]) & 0xFF
	}
}

func (c *Chacha20poly1305) EncryptFlow(msg []byte) ([]byte, error) {
	err := c.generateAead(&c.encStream)
	if err != nil {
		return nil, err
	}
	res := c.encStream.Seal(nil, c.Iv[:], msg, c.Key[:])
	c.ivRotate(&c.Iv)
	return res, nil
}

func (c *Chacha20poly1305) DecryptFlow(msg []byte) ([]byte, error) {
	err := c.generateAead(&c.decStream)
	if err != nil {
		return nil, err
	}
	res, err := c.decStream.Open(nil, c.iv[:], msg, c.Key[:])
	if err != nil {
		return nil, err
	}
	c.ivRotate(&c.iv)
	return res, nil
}

func (c *Chacha20poly1305) SetKey(key []byte) {
	c.Key = [chacha20polyKeyLen]byte(key)
	c.encStream, c.decStream = nil, nil
}

func (c *Chacha20poly1305) SetIv(iv []byte) {
	c.Iv = [chacha20polyIvLen]byte(iv)
	copy(c.iv[:], c.Iv[:])
}
func (c *Chacha20poly1305) GetKey() []byte         { return c.Key[:] }
func (c *Chacha20poly1305) GetKeyLen() uint64      { return chacha20polyKeyLen }
func (c *Chacha20poly1305) GetIvLen() uint64       { return chacha20polyIvLen }
func (c *Chacha20poly1305) GetKeyIvLen() uint64    { return chacha20polyKeyLen + chacha20polyIvLen }
func (c *Chacha20poly1305) WithIvAttached() uint64 { return chacha20polyExtAttachedIv }
