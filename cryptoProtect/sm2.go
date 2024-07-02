// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	utils "selfproxy/utils"

	"github.com/emmansun/gmsm/sm2"
)

func publicKeyToBytes(publicKey *ecdsa.PublicKey) []byte {
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	byteLen := utils.MaxInt(len(xBytes), len(yBytes))

	xBytes = append(make([]byte, byteLen-len(xBytes)), xBytes...)
	yBytes = append(make([]byte, byteLen-len(yBytes)), yBytes...)

	// uncompression form. add "04" prefix and set total bits to 65.
	publicKeyBytes := append([]byte{0x04}, append(xBytes, yBytes...)...)

	return publicKeyBytes
}

func pubBytesToKey(pubStr []byte) *ecdsa.PublicKey {
	curve := sm2.P256().Params()
	byteLen := (curve.BitSize + 7) / 8
	xBytes := pubStr[1 : byteLen+1]
	yBytes := pubStr[byteLen+1 : 2*byteLen+1]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return publicKey
}

type SM2 struct {
	pri *sm2.PrivateKey
	pub *ecdsa.PublicKey
}

func (_sm2 *SM2) SetPub(args ...interface{}) error {
	if len(args) != 1 {
		return errors.New(`invalid args detected from len(args)`)
	}
	switch args[0].(type) {
	case *ecdsa.PublicKey:
		_sm2.pub = args[0].(*ecdsa.PublicKey)
	case []byte:
		_sm2.pub = pubBytesToKey(args[0].([]byte))
	case *[]byte:
		_sm2.pub = pubBytesToKey(*args[0].(*[]byte))
	default:
		return errors.New(`invalid args detected from type(argv[0])`)
	}
	return nil
}

func (_sm2 *SM2) GetPub(res *[]byte) {
	*res = publicKeyToBytes(_sm2.pub)
}

func (_sm2 *SM2) GenerateKeyPair() {
	pem, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_sm2.pri, _sm2.pub = pem, &pem.PublicKey
}

func (_sm2 *SM2) PubEncrypt(msg []byte) ([]byte, error) {
	enc, err := sm2.Encrypt(rand.Reader, _sm2.pub, msg, sm2.ASN1EncrypterOpts)
	return enc, err
}

func (_sm2 *SM2) PemDecrypt(msg []byte) ([]byte, error) {
	dec, err := sm2.Decrypt(_sm2.pri, msg)
	return dec, err
}

func (_sm2 *SM2) PemSign(msg []byte) ([]byte, error) {
	signed_r, signed_s, err := sm2.SignWithSM2(rand.Reader, &_sm2.pri.PrivateKey, []byte(``), msg)
	rbytes, sbytes := signed_r.Bytes() /* 32 bytes */, signed_s.Bytes() /* 32 bytes */
	signed := append(rbytes, sbytes...)
	return signed, err
}

func (_sm2 *SM2) PubVerify(msg []byte, signature []byte) bool {
	r, s := new(big.Int), new(big.Int)
	if len(signature) != SignSize {
		return false
	}
	r.SetBytes(signature[:SignSize/2])
	s.SetBytes(signature[SignSize/2:])
	return sm2.VerifyWithSM2(_sm2.pub, []byte(``), msg, r, s)
}

func (_sm2 *SM2) GetPubLen() uint64 {
	return 65 // 32 + 32 + 1(04)
}
