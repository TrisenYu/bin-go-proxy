// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

type (
	SM4_OFB struct {
		Key       [KeySize]byte
		Iv        [IVSize]byte
		encStream cipher.Stream
		decStream cipher.Stream
	}
	SM4_CTR struct {
		Key       [KeySize]byte
		Iv        [IVSize]byte
		encStream cipher.Stream
		decStream cipher.Stream
	}
	SM4_GCM struct {
		Key      [KeySize]byte
		Iv       [IVSize]byte
		shadowIv [IVSize]byte
		stream   cipher.AEAD
	}
)

/* GCM */
func (s *SM4_GCM) EncryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	compressIv := [12] /* stream.NonceSize() */ byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]))
		compressIv[i%12] = uint8(s.Iv[i] + (s.Iv[(i-1+IVSize)&0xF] << 2) + compressIv[i%12])
	}
	if s.stream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		stream, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		s.stream = stream
	}
	xor_res := s.stream.Seal(nil, compressIv[:], msg, s.Iv[:])
	for i := 0; i < IVSize; i++ {
		s.Iv[i] = byte(uint16((s.Iv[i] + (s.Iv[(i-1+IVSize)%IVSize] << 1)))) & 0xFF
	}
	return xor_res
}

func (s *SM4_GCM) DecryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	compressIv := [12] /* stream.NonceSize() */ byte{}

	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
		compressIv[i%12] = uint8(s.shadowIv[i] + (s.shadowIv[(i-1+IVSize)&0xF] << 2) + compressIv[i%12])

	}
	if s.stream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		stream, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		s.stream = stream
	}
	xor_res, err := s.stream.Open(nil, compressIv[:], msg, s.shadowIv[:])
	if err != nil {
		panic(err)
	}
	for i := 0; i < IVSize; i++ {
		s.shadowIv[i] = byte(uint16((s.shadowIv[i] + (s.shadowIv[(i-1+IVSize)%IVSize] << 1)))) & 0xFF
	}
	return xor_res
}

func (s *SM4_GCM) SetKey(key []byte) {
	s.Key = [KeySize]byte(key)
	s.stream = nil
}

func (s *SM4_GCM) SetIv(iv []byte) {
	s.Iv = [IVSize]byte(iv)
	s.shadowIv = [IVSize]byte(iv)
}

func (s *SM4_GCM) GetKey() []byte {
	return s.Key[:]
}

func (s *SM4_GCM) GetIv() []byte {
	return s.Iv[:]
}

/* OFB */
func (s *SM4_OFB) EncryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	if s.encStream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		s.encStream = cipher.NewCTR(block, s.Iv[:])
	}
	xor_res := make([]byte, len(msg))
	s.encStream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_OFB) DecryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	if s.decStream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		s.decStream = cipher.NewCTR(block, s.Iv[:])
	}
	xor_res := make([]byte, len(msg))
	s.decStream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_OFB) SetKey(key []byte) {
	s.Key = [KeySize]byte(key)
}

func (s *SM4_OFB) SetIv(iv []byte) {
	s.Iv = [IVSize]byte(iv)
}

func (s *SM4_OFB) GetKey() []byte {
	return s.Key[:]
}

func (s *SM4_OFB) GetIv() []byte {
	return s.Iv[:]
}

/* CTR */
func (s *SM4_CTR) EncryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	if s.encStream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		s.encStream = cipher.NewCTR(block, s.Iv[:])
	}
	xor_res := make([]byte, len(msg))
	s.encStream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_CTR) DecryptFlow(msg []byte) []byte {
	key := [IVSize]byte{}
	for i := 0; i < IVSize; i++ {
		key[i] = uint8((s.Key[i] + s.Key[KeySize-1-i]) & 0xFF)
	}
	if s.decStream == nil {
		block, err := sm4.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		s.decStream = cipher.NewCTR(block, s.Iv[:])
	}
	xor_res := make([]byte, len(msg))
	s.decStream.XORKeyStream(xor_res, msg)
	return xor_res
}

func (s *SM4_CTR) SetKey(key []byte) {
	s.Key = [KeySize]byte(key)
}

func (s *SM4_CTR) SetIv(iv []byte) {
	s.Iv = [IVSize]byte(iv)
}

func (s *SM4_CTR) GetKey() []byte {
	return s.Key[:]
}

func (s *SM4_CTR) GetIv() []byte {
	return s.Iv[:]
}
