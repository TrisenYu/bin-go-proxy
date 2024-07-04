package cryptoprotect

import (
	"crypto/aes"
	"crypto/cipher"
)

// Only code for ctr, ofb mode.

type AES_CTR struct {
	Key [KeySize]byte
	Iv  [IVSize]byte
}

type AES_OFB struct {
	Key [KeySize]byte
	Iv  [IVSize]byte
}

func (a *AES_CTR) FlipFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))
	block, err := aes.NewCipher(a.Key[:])
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, a.Iv[:])
	stream.XORKeyStream(xor_res, msg)
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

func (a *AES_OFB) FlipFlow(msg []byte) []byte {
	xor_res := make([]byte, len(msg))

	block, err := aes.NewCipher(a.Key[:KeySize])
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, a.Iv[:])
	stream.XORKeyStream(xor_res, msg)
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
