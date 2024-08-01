// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

import (
	"crypto/rand"

	cryptoprotect "bingoproxy/cryptoProtect"
)

/*
terminology:
	RN: random number
*/

const (
	/* monochrome string */
	C_PREFIX             string = `client: ` // utilize in cilent
	PROXY_FAKE_HANDSHAKE string = C_PREFIX + `fake proxy-handshake-message `
	/// descriptions of errors about the actions related to ppub invoking from client.
	FAILED_TO_RECV_COMPRESSED_PPUB  string = C_PREFIX + `failed to receive (comp)ppub `
	INVALID_PPUB_LENGTH             string = C_PREFIX + `invalid length of ppub `
	FAILED_TO_SEND_ACKPPUB          string = C_PREFIX + `failed to send ack-ppub ` /// desciptions of errors about the cpub invoking from client.
	FAILED_TO_COMPRESS_CPUB         string = C_PREFIX + `failed to compress cpub `
	FAILED_TO_VALIDATE_ACKCPUB      string = C_PREFIX + `failed to validate ack-cpub ` /// descriptions of errors about cflow invoking from client
	FAILED_TO_COMPRESS_CFLOW        string = C_PREFIX + `failed to compress cflow `
	FAILED_TO_SEND_COMPRESSED_CFLOW string = C_PREFIX + `failed to send compressed cflow `
	FAILED_TO_PARSE_ACKCFLOW        string = C_PREFIX + `failed to parse ack-cflow `
	FAILED_TO_SEND_ACKPFLOW         string = C_PREFIX + `failed to send ack-pflow `  /// description of errors about pflow invoking from client
	INCONSISTENCY_OF_RN             string = C_PREFIX + `inconsistency of given RN ` /// description of errors about rn invoking from client

	P_PREFIX              string = `proxy: ` // utilize in proxy
	CLIENT_FAKE_HANDSHAKE string = P_PREFIX + `fake client-handshake-message `
	/// descriptions of errors about the actions related to cpub invoking from proxy.
	FAILED_TO_RECV_COMPRESSED_CPUB  string = P_PREFIX + `failed to receive (comp)cpub`
	INVALID_CPUB_LENGTH             string = P_PREFIX + `invalid length of cpub `
	FAILED_TO_SEND_ACKCPUB          string = P_PREFIX + `failed to send ack-cpub `
	FAILED_TO_COMPRESS_PPUB         string = P_PREFIX + `failed to compress ppub ` /// descriptions of errors about ppub invoking from proxy.
	FAILED_TO_VALIDATE_ACKPPUB      string = P_PREFIX + `failed to validate ack-ppub `
	FAILED_TO_COMPRESS_PFLOW        string = P_PREFIX + `failed to compress pflow ` /// descriptions of errors about pflow invoking from proxy.
	FAILED_TO_SEND_COMPRESSED_PFLOW string = P_PREFIX + `failed to send compressed pflow `
	FAILED_TO_PARSE_ACKPFLOW        string = P_PREFIX + `failed to parse ack-pflow ` /// descriptions of errors about cflow invoking from proxy
	FAILED_TO_SEND_ACKCFLOW         string = P_PREFIX + `failed to send ack-cflow `
	AN_INVALID_CFLOW                string = P_PREFIX + `invalid cflow has been checked ` /// descriptions of errors about rn invoking from proxy
	FAILED_TO_EXTRACT_RN            string = P_PREFIX + `failed to extract RN `
	FAILED_TO_VALIDATE_RN           string = P_PREFIX + `failed to validate RN `
	/* bilatery string */
	BILATERY_FAILED_TO_PING        string = `failed to ping and measured RTT `
	BILATERY_INVALID_HELLO         string = `invalid hello `
	BILATERY_INVALID_ACKCFLOW      string = `interlocking turn: invalid ack-cflow `
	BILATERY_INVALID_ACKPFLOW      string = `interlocking turn: invalid ack-pflow `
	BILATERY_INNER_SIGNAL_FAILED   string = `signal of invalid flow`
	BILATERY_SIGNATURE_FAILURE     string = `failed to verify signature `
	BILATERY_HASH_ACK_FAILURE      string = `failed to acknowledge hash `
	BILATERY_FINISHED_FAILURE      string = `failed to send hash `
	BILATERY_ACK_FINISHED_FAILURE  string = `failed to acknowledge finish `
	BILATERY_PEM_DECRYPTION_FAILED string = `failed to decrypt with pem `
)

type HandShakeMsg struct {
	Nonce     uint64 // random-nonce                      8 bytes
	Kern      []byte // login-proxy: key-iv client <- rn  ? bytes
	Hasher    []byte // hash of concat(kern, nonce)       ? bytes
	Signature []byte // signature of hash                 ? bytes
	Timestamp []byte // timestamp
}

/*
the way of mapping:

	1 +----+----+----+----+----+----+----+----+
	  |c   |p   |c   |p   |c   |p   |c   |p   |
	  +----+----+----+----+----+----+----+----+

	2 and then operate pressionkey with sbox => hash as key
*/
func GenerateSessionKey(
	prekey []byte,
	rn []byte,
	cnonce, pnonce uint64,
	stream_obj cryptoprotect.StreamCipher,
	hash_obj cryptoprotect.HashCipher,
) []byte {
	keySize := stream_obj.GetKeyLen()
	key := make([]byte, keySize)

	var i uint64 = 0
	for ; i < keySize; i += 4 {
		shift, flag := i>>2, (i>>3) == 1
		var choice uint64
		switch flag {
		case true:
			choice = pnonce >> uint64(shift<<3)
		default:
			choice = cnonce >> uint64(shift<<3)
		}
		key[i] = prekey[i] ^ byte(choice)
	}
	for i = 0; i < keySize; i++ {
		key[i] = byte(key[i] + cryptoprotect.AESBox[key[i]] + cryptoprotect.AESBox[key[(i-1+keySize)%keySize]])
	}

	return []byte(hash_obj.CalculateHash(key))
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
