// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

type AsymmCipher interface {
	// Generate key pair for certain instance.
	GenerateKeyPair()

	/*
		Recommand Only **ONE** argument for setting pub.
		Argument can be []byte, *[]byte, or different pub instance which should code in a specific way.
	*/
	SetPub(args ...interface{}) error

	// copy pub instance in memory to []byte.
	GetPub(res *[]byte)

	// Encrypt message by pubKey and then return the result and possible error.
	PubEncrypt(msg []byte) ([]byte, error)

	// return the length of pub-key.
	GetPubLen() uint64

	// return the length of signature
	GetSignatureLen() uint64

	// Decrypt message by priKey and then return the result and possible error.
	PemDecrypt(msg []byte) ([]byte, error)

	// sign with prikey. error provided for subsequently utilization.
	PemSign(msg []byte) ([]byte, error)

	// verify with pubkey. success and then return true, other wise false.
	PubVerify(msg []byte, signature []byte) bool
}

type StreamCipher interface {
	// SetKey from bytes.
	SetKey(key []byte)

	// SetIV from bytes.
	SetIv(iv []byte)

	// return the key in the representation of bytes.
	GetKey() []byte

	// return the length of key.
	GetKeyLen() uint64

	// return the length of iv.
	GetIvLen() uint64

	// return the length of key and iv.
	GetKeyIvLen() uint64

	// return 0 if IV does not need attaching to the preamble of one datagram.
	WithIvAttached() uint64

	// encrypt message and output without IV.
	EncryptFlow(msg []byte) ([]byte, error)

	// decrypt message. There is no IV in the payload.
	DecryptFlow(msg []byte) ([]byte, error)
}

type HashCipher interface {
	// return the length of hash.
	GetHashLen() uint64

	// calculate the hash of byteSlices, this method is not for file.
	CalculateHashOnce(msg []byte) []byte

	/*
		New a hasher for calculating the hash of one file.
		if the hasher is not nil, reset the hasher.
	*/
	NewHasher()

	// return the final hash of certain file.
	AggregatedHash() []byte

	// accumulate for byte stream.
	Accumulate(msg []byte) (cnt int, err error)
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
