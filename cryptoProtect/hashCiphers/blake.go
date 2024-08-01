// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package hashciphers

import (
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

type (
	Blake2b256 struct{}
	Blake2s256 struct{}
	Blake2b384 struct{}
	Blake2b512 struct{}
)

func (b *Blake2b256) CalculateHash(msg []byte) []byte {
	res := blake2b.Sum256(msg)
	return res[:]
}

func (b *Blake2s256) CalculateHash(msg []byte) []byte {
	res := blake2s.Sum256(msg)
	return res[:]
}

func (b *Blake2b256) GetHashLen() uint64 { return 32 }
func (b *Blake2s256) GetHashLen() uint64 { return 32 }

func (b *Blake2b384) CalculateHash(msg []byte) []byte {
	res := blake2b.Sum384(msg)
	return res[:]
}

func (b *Blake2b512) CalculateHash(msg []byte) []byte {
	res := blake2b.Sum512(msg)
	return res[:]
}

func (b *Blake2b384) GetHashLen() uint64 { return 48 }
func (b *Blake2b512) GetHashLen() uint64 { return 64 }
