// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

import (
	cryptoprotect "bingoproxy/cryptoProtect"
	utils "bingoproxy/utils"
)

/*
terminology:
	RN: random number
*/

const (
	/* monochrome string */

	// utilize in cilent
	C_PREFIX             string = `client: `
	PROXY_FAKE_HANDSHAKE string = C_PREFIX + `fake proxy-handshake-message `
	/// descriptions of errors about the actions related to ppub invoking from client.
	RECV_COMP_PPUB_FAILURE  string = C_PREFIX + `failed to receive (comp)ppub `
	INVALID_PPUB_LENGTH     string = C_PREFIX + `invalid length of ppub `
	SEND_ACKPPUB_FAILURE    string = C_PREFIX + `failed to send ack-ppub ` /// desciptions of errors about the cpub invoking from client.
	COMPRESS_CPUB_FAILURE   string = C_PREFIX + `failed to compress cpub `
	INVALID_ACKCPUB         string = C_PREFIX + `invalid ack-cpub ` /// descriptions of errors about cflow invoking from client
	COMPRESS_CFLOW_FAILURE  string = C_PREFIX + `failed to compress cflow `
	SEND_COMP_CFLOW_FAILURE string = C_PREFIX + `failed to send compressed cflow `
	PARSE_ACKCFLOW_FAILURE  string = C_PREFIX + `failed to parse ack-cflow `
	SEND_ACKPFLOW_FAILURE   string = C_PREFIX + `failed to send ack-pflow `  /// description of errors about pflow invoking from client
	RN_INCONSISTENCY        string = C_PREFIX + `inconsistency of given RN ` /// description of errors about rn invoking from client
	// utilize in proxy
	P_PREFIX              string = `proxy: `
	CLIENT_FAKE_HANDSHAKE string = P_PREFIX + `fake client-handshake-message `
	/// descriptions of errors about the actions related to cpub invoking from proxy.
	RECV_COMP_CPUB_FAILURE  string = P_PREFIX + `failed to receive (comp)cpub`
	INVALID_CPUB_LENGTH     string = P_PREFIX + `invalid length of cpub `
	SEND_ACKCPUB_FAILURE    string = P_PREFIX + `failed to send ack-cpub `
	COMPRESS_PPUB_FAILURE   string = P_PREFIX + `failed to compress ppub ` /// descriptions of errors about ppub invoking from proxy.
	INVALID_ACKPPUB         string = P_PREFIX + `invalid ack-ppub `
	COMPRESS_PFLOW_FAILURE  string = P_PREFIX + `failed to compress pflow ` /// descriptions of errors about pflow invoking from proxy.
	SEND_COMP_PFLOW_FAILURE string = P_PREFIX + `failed to send compressed pflow `
	PARSE_ACKPFLOW_FAILURE  string = P_PREFIX + `failed to parse ack-pflow ` /// descriptions of errors about cflow invoking from proxy
	SEND_ACKCFLOW_FAILURE   string = P_PREFIX + `failed to send ack-cflow `
	INVALID_CFLOW           string = P_PREFIX + `invalid cflow ` /// descriptions of errors about rn invoking from proxy
	EXTRACT_RN_FAILURE      string = P_PREFIX + `failed to extract RN `
	INVALID_RN              string = P_PREFIX + `invalid RN `
	/* bilatery string */

	BI_FAILED_TO_PING      string = `failed to ping and measured RTT `
	BI_INVALID_HELLO       string = `invalid hello `
	BI_INVALID_ACKCFLOW    string = `interlocking turn: invalid ack-cflow `
	BI_INVALID_ACKPFLOW    string = `interlocking turn: invalid ack-pflow `
	BI_INNER_SIGNAL_FAILED string = `signal of invalid flow`
	BI_SIGNATURE_FAILURE   string = `failed to verify signature `
	BI_HASH_ACK_FAILURE    string = `failed to acknowledge hash `
	BI_FINISHED_FAILURE    string = `failed to send hash `
	BI_ACK_FINISHED_FAILED string = `failed to acknowledge finish `
	BI_BAD_PEM_DECRYPTION  string = `failed to decrypt with pem `
)

type HandShakeMsg struct {
	Nonce     uint64 // random-nonce                      8 bytes
	Kern      []byte // login-proxy: key-iv client <- rn  ? bytes
	Hasher    []byte // hash of concat(kern, nonce)       ? bytes
	Signature []byte // signature of hash                 ? bytes
	Timestamp []byte // timestamp                         ? bytes
}

// generate (key, iv) pair.
func GeneratePresessionKey(currCipher cryptoprotect.StreamCipher) ([]byte, []byte, error) {
	key := make([]byte, currCipher.GetKeyLen())
	if _, err := utils.SetRandByte(&key); err != nil {
		return nil, nil, err
	}

	iv := make([]byte, currCipher.GetIvLen())
	if _, err := utils.SetRandByte(&iv); err != nil {
		return nil, nil, err
	}
	return key, iv, nil
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
		key[i] = byte(key[i] + cryptoprotect.AESBoxVariant[key[i]] + cryptoprotect.AESBoxVariant[key[(i-1+keySize)%keySize]])
	}

	return []byte(hash_obj.CalculateHashOnce(key))
}

func GenerateRandUint64WithByteRepresentation() (uint64, []byte, error) {
	nonce := make([]byte, 8)
	_, err := utils.SetRandByte(&nonce)
	if err != nil {
		return 0, []byte{}, err
	}
	var nonceIn64 uint64 = 0
	for i := 0; i < 8; i++ {
		nonceIn64 |= uint64(nonce[i]) << (i << 3)
	}
	return nonceIn64, nonce, nil
}
