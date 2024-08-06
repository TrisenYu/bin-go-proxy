// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package hashciphers

import (
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// TODO: are there demands for turing hasher in blake hash function to verifier for MAC?

type (
	Blake2b256 struct{ hasher hash.Hash }
	Blake2s256 struct{ hasher hash.Hash }
	Blake2b384 struct{ hasher hash.Hash }
	Blake2b512 struct{ hasher hash.Hash }
)

// 256
func (b *Blake2b256) CalculateHashOnce(msg []byte) []byte {
	res := blake2b.Sum256(msg)
	return res[:]
}

func (b *Blake2s256) CalculateHashOnce(msg []byte) []byte {
	res := blake2s.Sum256(msg)
	return res[:]
}

func (b *Blake2b256) NewHasher() {
	if b.hasher != nil {
		b.hasher.Reset()
		return
	}
	hasher, err := blake2b.New256(nil)
	if err != nil {
		b.hasher = nil
		return
	}
	b.hasher = hasher
}

func (b *Blake2s256) NewHasher() {
	if b.hasher != nil {
		b.hasher.Reset()
		return
	}
	hasher, err := blake2s.New256(nil)
	if err != nil {
		b.hasher = nil
		return
	}
	b.hasher = hasher
}

func (b *Blake2b256) Accumulate(msg []byte) (cnt int, err error) { return b.hasher.Write(msg) }
func (b *Blake2b256) AggregatedHash() []byte {
	if b.hasher == nil {
		return nil
	}
	return b.hasher.Sum(nil)
}

func (b *Blake2s256) Accumulate(msg []byte) (cnt int, err error) { return b.hasher.Write(msg) }
func (b *Blake2s256) AggregatedHash() []byte {
	if b.hasher == nil {
		return nil
	}
	return b.hasher.Sum(nil)
}

func (b *Blake2b256) GetHashLen() uint64 { return 32 }
func (b *Blake2s256) GetHashLen() uint64 { return 32 }

// 384
func (b *Blake2b384) CalculateHashOnce(msg []byte) []byte {
	res := blake2b.Sum384(msg)
	return res[:]
}

// TODO: are there demands for turing hasher in blake hash function to verifier for MAC?
func (b *Blake2b384) NewHasher() {
	if b.hasher != nil {
		b.hasher.Reset()
		return
	}
	hasher, err := blake2b.New384(nil)
	if err != nil {
		b.hasher = nil
		return
	}
	b.hasher = hasher
}
func (b *Blake2b384) Accumulate(msg []byte) (cnt int, err error) { return b.hasher.Write(msg) }
func (b *Blake2b384) AggregatedHash() []byte {
	if b.hasher == nil {
		return nil
	}
	return b.hasher.Sum(nil)
}

func (b *Blake2b384) GetHashLen() uint64 { return 48 }

// 512
func (b *Blake2b512) CalculateHashOnce(msg []byte) []byte {
	res := blake2b.Sum512(msg)
	return res[:]
}

func (s *Blake2b512) NewHasher() {
	if s.hasher != nil {
		s.hasher.Reset()
		return
	}
	hasher, err := blake2b.New512(nil)
	if err != nil {
		s.hasher = nil
		return
	}
	s.hasher = hasher
}

func (b *Blake2b512) Accumulate(msg []byte) (cnt int, err error) { return b.hasher.Write(msg) }
func (b *Blake2b512) AggregatedHash() []byte {
	if b.hasher == nil {
		return nil
	}
	return b.hasher.Sum(nil)
}

func (b *Blake2b512) GetHashLen() uint64 { return 64 }
