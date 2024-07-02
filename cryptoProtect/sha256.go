// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

func CalculateFlowSha256Hash(msg []byte) [32]byte {
	return sha256.Sum256(msg)
}

type (
	Sha256   struct{}
	Sha3_256 struct{}
)

func (s *Sha3_256) CalculateHash(msg []byte) []byte {
	res := sha3.Sum256(msg)
	return res[:]
}

func (sha *Sha256) CalculateHash(msg []byte) []byte {
	tmp := sha256.Sum256(msg)
	return tmp[:]
}
