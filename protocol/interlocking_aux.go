// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

import (
	"crypto/rand"

	cryptoprotect "bingoproxy/cryptoProtect"
)

const (
	// TODO: collect up the sparse description of errors.
	/* monochrome string */
	CLIENT_PREFIX             string = `client: `
	PROXY_PREFIX              string = `proxy: `
	PROXY_FAKE_HANDSHAKE      string = CLIENT_PREFIX + `fake proxy-handshake-message `
	FAILED_TO_RECV_COMP_PPUB  string = CLIENT_PREFIX + `failed to receive (comp)ppub `
	INVALID_PPUB_LENGTH       string = CLIENT_PREFIX + `invalid length of ppub `
	FAILED_TO_SEND_ACKPPUB    string = CLIENT_PREFIX + `failed to send ack-ppub `
	FAILED_TO_COMPRESS_CFLOW  string = CLIENT_PREFIX + `failed to compress cflow `
	FAILED_TO_PARSE_ACKCFLOW  string = CLIENT_PREFIX + `failed to parse ack-cflow `
	FAILED_TO_SEND_COMP_CFLOW string = CLIENT_PREFIX + `failed to send compressed cflow `

	CLIENT_FAKE_HANDSHAKE     string = `fake client-handshake-message `
	INVALID_CPUB_LENGTH       string = PROXY_PREFIX + `invalid length of cpub `
	FAILED_TO_COMPRESS_PPUB   string = PROXY_PREFIX + `failed to compress ppub `
	FAILED_TO_SEND_COMP_PFLOW string = PROXY_PREFIX + `failed to send ppub`
	FAILED_TO_SEND_ACKCPUB    string = PROXY_PREFIX + `failed to send ack-cpub `
	FAILED_TO_COMPRESS_PFLOW  string = PROXY_PREFIX + `failed to compress pflow `
	FAILED_TO_SEND_PFLOW      string = PROXY_PREFIX + `failed to send pflow `
	FAILED_TO_PARSE_ACKPFLOW  string = PROXY_PREFIX + `failed to parse ack-pflow `
	/* bilatery string */
	FAILED_TO_PING_AND_MEASURE         string = `failed to ping and measured RTT `
	INTERLOCKING_TURN_INVALID_ACKCFLOW string = `interlocking turn: invalid ack-cflow `
	INTERLOCKING_TURN_INVALID_ACKPFLOW string = `interlocking turn: invalid ack-pflow `
	FAILED_TO_VERIFY_SIGNATURE         string = `failed to verify signature `
)

type (
	HandShakeMsg struct {
		Kern      [cryptoprotect.KeySize + cryptoprotect.IVSize]byte // login-proxy: key-iv client <- rn  48 bytes
		Nonce     uint64                                             // random-nonce                       8 bytes
		Hasher    [cryptoprotect.HashSize]byte                       // hash of concat(kern, nonce)       32 bytes
		Signature [cryptoprotect.SignSize]byte                       // signature of hash                 64 bytes
		Timestamp []byte                                             // timestamp
	}
)

/*
the way of mapping:

	1 +----+----+----+----+----+----+----+----+
	  |c   |p   |c   |p   |c   |p   |c   |p   |
	  +----+----+----+----+----+----+----+----+

	2 and then xor pressionkey with sbox => hash as key
*/
func GenerateSessionKey(
	prekey [cryptoprotect.KeySize]byte,
	rn [cryptoprotect.KeySize + cryptoprotect.IVSize]byte,
	cnonce, pnonce uint64,
	hash_obj cryptoprotect.HashCipher,
) [cryptoprotect.KeySize]byte {
	key := make([]byte, cryptoprotect.KeySize)
	keySize := cryptoprotect.KeySize
	for i := 0; i < keySize; i += 4 {
		shift, flag := i/4, i/8
		if flag&1 == 1 {
			key[i] = prekey[i] ^ byte(pnonce>>uint64(shift<<3))
		} else {
			key[i] = prekey[i] ^ byte(cnonce>>uint64(shift<<3))
		}
	}
	for i := 0; i < keySize; i++ {
		key[i] = (key[i] + cryptoprotect.S_Box[key[i]] + cryptoprotect.S_Box[key[(i-1+keySize)%keySize]]) & 0xFF
	}
	return [32]byte(hash_obj.CalculateHash(key))
}

func GenerateRandUint64WithByteRepresentation() (uint64, []byte, error) {
	nonce := make([]byte, 8)
	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return 0, []byte{}, err
	}
	var nonceIn64 uint64 = 0
	for i := 0; i < 8; i++ {
		nonceIn64 |= uint64(nonce[i]) << (i << 3)
	}
	return nonceIn64, nonce, nil
}
