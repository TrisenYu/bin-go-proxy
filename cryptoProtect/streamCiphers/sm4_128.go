// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

const (
	sm4KeySize   = 16
	sm4IvSize    = sm4KeySize
	sm4GCMIvSize = 12
)

type (
	SM4_OFB struct {
		Key       [sm4KeySize]byte
		Iv        [sm4IvSize]byte
		encStream cipher.Stream
		decStream cipher.Stream
	}
	SM4_CTR struct {
		Key       [sm4KeySize]byte
		Iv        [sm4IvSize]byte
		encStream cipher.Stream
		decStream cipher.Stream
	}
	SM4_GCM struct {
		Key       [sm4KeySize]byte
		Iv        [sm4GCMIvSize]byte
		encStream cipher.AEAD
		decStream cipher.AEAD
	}
)

func (s *SM4_GCM) generateStream(aead *cipher.AEAD) error {
	if *aead != nil {
		return nil
	}
	block, err := sm4.NewCipher(s.Key[:])
	if err != nil {
		return err
	}
	*aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	return nil
}

/* GCM */
func (s *SM4_GCM) EncryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.encStream)
	if err != nil {
		return nil, err
	}
	xor_res := s.encStream.Seal(nil, s.Iv[:], msg, nil)
	return xor_res, nil
}

func (s *SM4_GCM) DecryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.decStream)
	if err != nil {
		return nil, err
	}
	xor_res, err := s.decStream.Open(nil, s.Iv[:], msg, nil)
	if err != nil {
		return nil, err
	}
	return xor_res, nil
}

func (s *SM4_GCM) SetKey(key []byte) {
	s.Key = [sm4KeySize]byte(key)
	s.encStream, s.decStream = nil, nil
}

func (s *SM4_GCM) SetIv(iv []byte)        { s.Iv = [sm4GCMIvSize]byte(iv) }
func (s *SM4_GCM) GetKey() []byte         { return s.Key[:] }
func (s *SM4_GCM) GetIv() []byte          { return s.Iv[:] }
func (s *SM4_GCM) GetKeyLen() uint64      { return sm4KeySize }
func (s *SM4_GCM) GetIvLen() uint64       { return sm4GCMIvSize }
func (s *SM4_GCM) GetKeyIvLen() uint64    { return sm4KeySize + sm4GCMIvSize }
func (s *SM4_GCM) WithIvAttached() uint64 { return sm4IvSize }

/* OFB */
func (s *SM4_OFB) generateStream(steam *cipher.Stream) error {
	if *steam != nil {
		return nil
	}
	block, err := sm4.NewCipher(s.Key[:])
	if err != nil {
		return err
	}
	*steam = cipher.NewCTR(block, s.Iv[:])
	return nil
}

func (s *SM4_OFB) EncryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.encStream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	s.encStream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (s *SM4_OFB) DecryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.decStream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	s.decStream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (s *SM4_OFB) SetKey(key []byte)      { s.Key = [sm4KeySize]byte(key) }
func (s *SM4_OFB) SetIv(iv []byte)        { s.Iv = [sm4IvSize]byte(iv) }
func (s *SM4_OFB) GetKey() []byte         { return s.Key[:] }
func (s *SM4_OFB) GetIv() []byte          { return s.Iv[:] }
func (s *SM4_OFB) GetKeyLen() uint64      { return sm4KeySize }
func (s *SM4_OFB) GetIvLen() uint64       { return sm4IvSize }
func (s *SM4_OFB) GetKeyIvLen() uint64    { return sm4KeySize + sm4IvSize }
func (s *SM4_OFB) WithIvAttached() uint64 { return 0 }

/* CTR */
func (s *SM4_CTR) generateStream(steam *cipher.Stream) error {
	if *steam != nil {
		return nil
	}
	block, err := sm4.NewCipher(s.Key[:])
	if err != nil {
		return err
	}
	*steam = cipher.NewCTR(block, s.Iv[:])
	return nil
}

func (s *SM4_CTR) EncryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.encStream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	s.encStream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (s *SM4_CTR) DecryptFlow(msg []byte) ([]byte, error) {
	err := s.generateStream(&s.decStream)
	if err != nil {
		return nil, err
	}
	xor_res := make([]byte, len(msg))
	s.decStream.XORKeyStream(xor_res, msg)
	return xor_res, nil
}

func (s *SM4_CTR) SetKey(key []byte)      { s.Key = [sm4KeySize]byte(key) }
func (s *SM4_CTR) SetIv(iv []byte)        { s.Iv = [sm4IvSize]byte(iv) }
func (s *SM4_CTR) GetKey() []byte         { return s.Key[:] }
func (s *SM4_CTR) GetIv() []byte          { return s.Iv[:] }
func (s *SM4_CTR) GetKeyLen() uint64      { return sm4KeySize }
func (s *SM4_CTR) GetIvLen() uint64       { return sm4IvSize }
func (s *SM4_CTR) GetKeyIvLen() uint64    { return sm4KeySize + sm4IvSize }
func (s *SM4_CTR) WithIvAttached() uint64 { return 0 }
