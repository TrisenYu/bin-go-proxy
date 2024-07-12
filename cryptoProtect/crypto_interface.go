// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import "crypto/rand"

// TODO: error should pass to upper layer rather than simply invoke panic().

type AsymmCipher interface {
	// Generate key pair for certain instance.
	GenerateKeyPair()

	/*
		Recommand Only **ONE** argument for setting pub.
		Argument can be []byte, *[]byte, or different pub instance which should code in a specific way.
	*/
	SetPub(args ...interface{}) error

	// copy pub instance in memory to []byte
	GetPub(res *[]byte)

	/*
		Encrypt msg by pub and then return the result.
		if encryption failed, recommand directly `panic`.
	*/
	PubEncrypt(msg []byte) ([]byte, error)

	// return length of pub-key.
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

	// encrypt message and output without IV.
	EncryptFlow(msg []byte) []byte

	// decrypt message. There is no IV in the payload.
	DecryptFlow(msg []byte) []byte
}

type HashCipher interface {
	CalculateHash(msg []byte) []byte // not for file
}

type CompOption interface {
	// initiation of compresser.
	InitCompresser() error

	// initiation of decompresser.
	InitDecompresser() error

	// compress message.
	CompressMsg(msg []byte) ([]byte, error)

	// decompress message.
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
