// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package hashciphers

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

type (
	Sha256   struct{ hasher hash.Hash }
	Sha3_256 struct{ hasher hash.Hash }
	Sha384   struct{ hasher hash.Hash }
	Sha3_384 struct{ hasher hash.Hash }
	Sha512   struct{ hasher hash.Hash }
	Sha3_512 struct{ hasher hash.Hash }
)

// 256
func (s *Sha3_256) CalculateHashOnce(msg []byte) []byte {
	res := sha3.Sum256(msg)
	return res[:]
}

func (s *Sha3_256) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha3.New256()
}

func (s *Sha256) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha256.New()
}

func (s *Sha256) CalculateHashOnce(msg []byte) []byte {
	tmp := sha256.Sum256(msg)
	return tmp[:]
}

func (s *Sha3_256) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha3_256) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}
func (s *Sha256) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha256) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}
func (s *Sha256) GetHashLen() uint64   { return 32 }
func (s *Sha3_256) GetHashLen() uint64 { return 32 }

// 384
func (s *Sha3_384) CalculateHashOnce(msg []byte) []byte {
	res := sha3.Sum384(msg)
	return res[:]
}

func (s *Sha384) CalculateHashOnce(msg []byte) []byte {
	tmp := sha512.Sum384(msg)
	return tmp[:]
}

func (s *Sha3_384) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha3.New384()
}

func (s *Sha384) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha512.New384()
}

func (s *Sha3_384) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha3_384) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}
func (s *Sha384) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha384) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}
func (s *Sha384) GetHashLen() uint64   { return 48 }
func (s *Sha3_384) GetHashLen() uint64 { return 48 }

// 512
func (s *Sha3_512) CalculateHashOnce(msg []byte) []byte {
	res := sha3.Sum512(msg)
	return res[:]
}

func (s *Sha512) CalculateHashOnce(msg []byte) []byte {
	tmp := sha512.Sum512(msg)
	return tmp[:]
}

func (s *Sha3_512) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha3.New512()
}

func (s *Sha512) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	s.hasher = sha512.New()
}

func (s *Sha3_512) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha3_512) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}
func (s *Sha512) Accumulate(msg []byte) (cnt int, err error) { return s.hasher.Write(msg) }
func (s *Sha512) AggregatedHash() []byte {
	if s.hasher == nil {
		return nil
	}
	return s.hasher.Sum(nil)
}

func (sha *Sha512) GetHashLen() uint64 { return 64 }
func (s *Sha3_512) GetHashLen() uint64 { return 64 }
