// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/aes"
	"crypto/cipher"
)

/*
	The encryption and decryption in gcm mode resemble a socket utilized in network communication.

	Proper and plausible scheme of SMPC is a must for decentralized secure scenario,
	but it is too complicated at present.
*/

const (
	aes256KeyLen   = 32
	aes256IvLen    = 16
	aesGCM256IvLen = 12
)

type (
	AES_CTR_256 struct {
		Key       [aes256KeyLen]byte
		Iv        [aes256IvLen]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}
	AES_OFB_256 struct {
		Key       [aes256KeyLen]byte
		Iv        [aes256IvLen]byte
		encstream cipher.Stream
		decstream cipher.Stream
	}
	AES_GCM_256 struct {
		Key       [aes256KeyLen]byte
		Iv, iv    [aesGCM256IvLen]byte
		encstream cipher.AEAD
		decstream cipher.AEAD
	}
)

// CTR
func (a *AES_CTR_256) generateStream(stream *cipher.Stream) error {
	if *stream != nil {
		return nil
	}
	block, err := aes.NewCipher(a.Key[:])
	if err != nil {
		return err
	}
	*stream = cipher.NewCTR(block, a.Iv[:])
	return nil
}

func (a *AES_CTR_256) EncryptFlow(msg []byte) ([]byte, error) {
	err := a.generateStream(&a.encstream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_CTR_256) DecryptFlow(msg []byte) ([]byte, error) {
	err := a.generateStream(&a.decstream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_CTR_256) SetKey(key []byte)      { a.Key = [aes256KeyLen]byte(key) }
func (a *AES_CTR_256) SetIv(iv []byte)        { a.Iv = [aes256IvLen]byte(iv) }
func (a *AES_CTR_256) GetKey() []byte         { return a.Key[:] }
func (a *AES_CTR_256) GetKeyLen() uint64      { return aes256KeyLen }
func (a *AES_CTR_256) GetIvLen() uint64       { return aes256IvLen }
func (a *AES_CTR_256) GetKeyIvLen() uint64    { return aes256IvLen + aes256KeyLen }
func (a *AES_CTR_256) WithIvAttached() uint64 { return 0 }

// OFB
func (a *AES_OFB_256) generateStream(stream *cipher.Stream) error {
	if *stream != nil {
		return nil
	}
	block, err := aes.NewCipher(a.Key[:])
	if err != nil {
		return err
	}
	*stream = cipher.NewOFB(block, a.Iv[:])
	return nil
}

func (a *AES_OFB_256) EncryptFlow(msg []byte) ([]byte, error) {
	err := a.generateStream(&a.encstream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	a.encstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_OFB_256) DecryptFlow(msg []byte) ([]byte, error) {
	err := a.generateStream(&a.decstream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	a.decstream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (a *AES_OFB_256) SetKey(key []byte)      { a.Key = [aes256KeyLen]byte(key) }
func (a *AES_OFB_256) SetIv(iv []byte)        { a.Iv = [aes256IvLen]byte(iv) }
func (a *AES_OFB_256) GetKey() []byte         { return a.Key[:] }
func (a *AES_OFB_256) GetKeyLen() uint64      { return aes256KeyLen }
func (a *AES_OFB_256) GetIvLen() uint64       { return aes256IvLen }
func (a *AES_OFB_256) GetKeyIvLen() uint64    { return aes256IvLen + aes256KeyLen }
func (a *AES_OFB_256) WithIvAttached() uint64 { return 0 }

// GCM
func (a *AES_GCM_256) generateAead(aead *cipher.AEAD) error {
	if *aead != nil {
		return nil
	}
	block, err := aes.NewCipher(a.Key[:])
	if err != nil {
		return err
	}
	*aead, err = cipher.NewGCM(block)
	return err
}

func (a *AES_GCM_256) ivRotate(inp *[aesGCM256IvLen]byte) {
	lena := aesGCM256IvLen
	for i := 0; i < lena; i++ {
		(*inp)[i] = (GaloisBox[(*inp)[(i+lena-1)%lena]] + (*inp)[i]) & 0xFF
	}
}

func (a *AES_GCM_256) EncryptFlow(msg []byte) ([]byte, error) {
	err := a.generateAead(&a.encstream)
	if err != nil {
		return nil, err
	}
	res := a.encstream.Seal(nil, a.Iv[:], msg, a.Key[:])
	a.ivRotate(&a.Iv)
	return res, nil
}

func (a *AES_GCM_256) DecryptFlow(msg []byte) ([]byte, error) {
	err := a.generateAead(&a.decstream)
	if err != nil {
		return nil, err
	}
	res, err := a.decstream.Open(nil, a.iv[:], msg, a.Key[:])
	if err != nil {
		return nil, err
	}
	a.ivRotate(&a.iv)
	return res, nil
}

func (a *AES_GCM_256) SetKey(key []byte) {
	a.Key = [aes256KeyLen]byte(key)
	a.encstream, a.decstream = nil, nil
}

func (a *AES_GCM_256) SetIv(iv []byte) {
	a.Iv = [aesGCM256IvLen]byte(iv)
	copy(a.iv[:], a.Iv[:])
}

func (a *AES_GCM_256) GetKey() []byte         { return a.Key[:] }
func (a *AES_GCM_256) GetKeyLen() uint64      { return aes256KeyLen }
func (a *AES_GCM_256) GetIvLen() uint64       { return aesGCM256IvLen }
func (a *AES_GCM_256) GetKeyIvLen() uint64    { return aes256KeyLen + aesGCM256IvLen }
func (a *AES_GCM_256) WithIvAttached() uint64 { return aes256IvLen }
