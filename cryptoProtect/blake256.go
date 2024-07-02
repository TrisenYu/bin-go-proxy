package cryptoprotect

import (
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

type (
	Blake2b256 struct{}
	Blake2s256 struct{}
)

func (b *Blake2b256) CalculateHash(msg []byte) []byte {
	res := blake2b.Sum256(msg)
	return res[:]
}

func (b *Blake2s256) CalculateHash(msg []byte) []byte {
	res := blake2s.Sum256(msg)
	return res[:]
}
