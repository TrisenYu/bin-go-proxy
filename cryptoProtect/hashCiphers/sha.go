// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package hashciphers

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

func CalculateFlowSha256Hash(msg []byte) [32]byte {
	return sha256.Sum256(msg)
}

type (
	Sha256   struct{}
	Sha3_256 struct{}
	Sha384   struct{}
	Sha3_384 struct{}
	Sha512   struct{}
	Sha3_512 struct{}
)

func (s *Sha3_256) CalculateHash(msg []byte) []byte {
	res := sha3.Sum256(msg)
	return res[:]
}

func (sha *Sha256) CalculateHash(msg []byte) []byte {
	tmp := sha256.Sum256(msg)
	return tmp[:]
}

func (sha *Sha256) GetHashLen() uint64 { return 32 }
func (s *Sha3_256) GetHashLen() uint64 { return 32 }

func (s *Sha3_384) CalculateHash(msg []byte) []byte {
	res := sha3.Sum384(msg)
	return res[:]
}

func (sha *Sha384) CalculateHash(msg []byte) []byte {
	tmp := sha512.Sum384(msg)
	return tmp[:]
}

func (sha *Sha384) GetHashLen() uint64 { return 48 }
func (s *Sha3_384) GetHashLen() uint64 { return 48 }

func (s *Sha3_512) CalculateHash(msg []byte) []byte {
	res := sha3.Sum512(msg)
	return res[:]
}

func (sha *Sha512) CalculateHash(msg []byte) []byte {
	tmp := sha512.Sum512(msg)
	return tmp[:]
}

func (sha *Sha512) GetHashLen() uint64 { return 64 }
func (s *Sha3_512) GetHashLen() uint64 { return 64 }
