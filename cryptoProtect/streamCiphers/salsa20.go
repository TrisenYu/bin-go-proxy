// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package streamciphers

import "golang.org/x/crypto/salsa20"

const (
	salsa20KeyLen   = 32
	salsa20NonceLen = 24
)

type Salsa20 struct {
	Key    [salsa20KeyLen]byte
	Iv, iv [salsa20NonceLen]byte
}

func (s *Salsa20) ivRotate(inp *[salsa20NonceLen]byte) {
	lena := salsa20NonceLen
	for i := 0; i < lena; i++ {
		(*inp)[i] = (GaloisBox[(*inp)[(i+lena-1)%lena]] + (*inp)[i]) & 0xFF
	}
}

func (s *Salsa20) DecryptFlow(msg []byte) ([]byte, error) {
	oup := make([]byte, len(msg))
	salsa20.XORKeyStream(oup, msg, s.iv[:], &s.Key)
	s.ivRotate(&s.iv)
	return oup, nil
}

func (s *Salsa20) EncryptFlow(msg []byte) ([]byte, error) {
	oup := make([]byte, len(msg))
	// we need iv avalanche since salsa20 XorKeyStream always generates
	// the same ciphertext for the same plaintext if we don't change iv at all.
	salsa20.XORKeyStream(oup, msg, s.Iv[:], &s.Key)
	s.ivRotate(&s.Iv)
	return oup, nil
}

func (s *Salsa20) SetIv(iv []byte) {
	s.Iv = [salsa20NonceLen]byte(iv)
	copy(s.iv[:], s.Iv[:])
}
func (s *Salsa20) GetKeyLen() uint64      { return salsa20KeyLen }
func (s *Salsa20) GetKeyIvLen() uint64    { return salsa20KeyLen + salsa20NonceLen }
func (s *Salsa20) GetIvLen() uint64       { return salsa20NonceLen }
func (s *Salsa20) SetKey(key []byte)      { s.Key = [salsa20KeyLen]byte(key) }
func (s *Salsa20) GetKey() []byte         { return s.Key[:] }
func (s *Salsa20) WithIvAttached() uint64 { return 0 }
