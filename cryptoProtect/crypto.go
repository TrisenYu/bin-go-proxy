// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/rand"
)

/*
	Temporarily define crypto-suite-numno as a 4 bytes number.
	The 4 bytes are allocated for asymmetric encryption method, stream cipher, hash function and reserved domain.
	Client application should provide logining proxy for crypto-suite-numno, protocol version and access-token
	And that shake hand. Once the crypto-suite-numno is utilized, there is no operation for altering crypto methods
	Excepct disconnecting from proxy and redoing.
*/

type (
	asymmetric_cipher_choice uint // asymmetric crypto alias
	stream_cipher_choice     uint // stream crypto alias
	hash_cipher_choice       uint // hash crypto alias'
	compressed_choice        uint // alias for certain algorithm compression
)

const (
	IVSize   int                      = 16
	KeySize  int                      = 32
	HashSize int                      = KeySize
	SignSize int                      = 64
	PICK_SM2 asymmetric_cipher_choice = iota + 1
	// TODO: Lattice encryption.
)

const (
	PICK_ZUC                  stream_cipher_choice = iota + 1 // zuc stream cipher
	PICK_SALSA20                                              // salsa20 stream cipher
	PICK_AES_OFB_256                                          // aes-output-feedback-256 cipher
	PICK_AES_CTR_256                                          // aes-couter-mode-256 cipher
	PICK_AES_GCM_256                                          // aes-galois-counter-mode cipher
	PICK_SM4_OFB_256                                          // sm4-output-feedback-256 cipher
	PICK_SM4_CTR_256                                          // sm4-couter-mode-256 cipher
	PICK_SM4_GCM_256                                          // sm4-galois-counter-mode cipher
	PICK_CHACHA20POLY1305_256                                 // chacha20-poly1305 cipher
)

const (
	PICK_SM3        hash_cipher_choice = iota + 1 // sm3 hash
	PICK_SHA256                                   // sha256
	PICK_SHA3_256                                 // sha3-256
	PICK_BLAKE2B256                               // blake2b256
	PICK_BLAKE2S256                               // blake2s56
)

const (
	PICK_NULL_COMP compressed_choice = iota + 1 // no need for compression alogrithm
	PICK_ZLIB_COMP                              // zstd compression
)

type AsymmCipher interface {
	// Generate key pair for certain instance.
	GenerateKeyPair()
	/*
		Recommand Only **ONE** argument for setting pub.
		Argument can be []byte, *[]byte, or different pub instance.
	*/
	SetPub(args ...interface{}) error
	// copy pub instance in memory to []byte
	GetPub(res *[]byte)
	/*
		Encrypt msg by pub and then return the result.
		if encryption failed, recommand directly `panic`.
	*/
	PubEncrypt(msg []byte) ([]byte, error)

	GetPubLen() uint64
	/*
		Decrypt msg by pri and then return the result.
		if decryption failed, recommand directly `panic`.
	*/
	PemDecrypt(msg []byte) ([]byte, error)
	// sign with prikey. error provided for subsequently utilization.
	PemSign(msg []byte) ([]byte, error)
	// verify with pubkey. success and then return true, other wise false.
	PubVerify(msg []byte, signature []byte) bool
}

type StreamCipher interface {
	// SetKey from bytes
	SetKey(key []byte)
	// SetIV from bytes
	SetIv(iv []byte)
	// return the key in the representation of bytes
	GetKey() []byte
	// return the iv in the representation of bytes
	// GetIv() []byte

	// IV stripped.
	EncryptFlow(msg []byte) []byte
	DecryptFlow(msg []byte) []byte
}

type HashCipher interface {
	CalculateHash(msg []byte) []byte // not for file
}

type CompOption interface {
	InitCompresser() error
	InitDecompresser() error
	CompressMsg(msg []byte) ([]byte, error)
	DecompressMsg(msg []byte) ([]byte, error)
}

func GeneratePresessionKey() ([]byte, []byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}
