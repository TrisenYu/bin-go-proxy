// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>

package proxy

import (
	"errors"
	"time"

	auth "bingoproxy/auth"
	cryptoprotect "bingoproxy/cryptoProtect"
	asymmetricciphers "bingoproxy/cryptoProtect/asymmetricCiphers"
	hashciphers "bingoproxy/cryptoProtect/hashCiphers"
	streamciphers "bingoproxy/cryptoProtect/streamCiphers"
	zipper "bingoproxy/cryptoProtect/zipper"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
	service "bingoproxy/service"
	utils "bingoproxy/utils"
)

/*
 * TODO: speed limitation for preventing DDos.
 *    we need tact for single ip
 *                 for fake ips
 */

/*
 * invoke this after initialize `client_asymmetric_pub`.
 *	serialize the handshake-msg into bytes, then encrypt with client_pub
 */
func (ep *EncFlowProxy) cPubEncrypt(handshake *protocol.HandShakeMsg) ([]byte, error) {
	serialization := make([]byte, 0)
	serialization = append(serialization, utils.Uint64ToLittleEndianBytes(handshake.Nonce)...)
	serialization = append(serialization, handshake.Kern...)
	serialization = append(serialization, handshake.Hasher...)
	serialization = append(serialization, handshake.Signature...)
	serialization = append(serialization, handshake.Timestamp...)
	encrypt_msg, err := ep.ClientAsymmCipher.PubEncrypt(serialization)
	return encrypt_msg, err
}

func (ep *EncFlowProxy) decryptHandShakeMsg(enc []byte) ([]byte, error) {
	dec, err := ep.AsymmCipher.PemDecrypt(enc)
	return dec, err
}

func (ep *EncFlowProxy) extractHandShakeMsg(msg []byte) (*protocol.HandShakeMsg, error) {
	var (
		nonce_ed uint64 = 8
		iv_ed           = nonce_ed + ep.KeyLen + ep.IvLen
		hash_ed         = iv_ed + ep.HashCipher.GetHashLen()
		sign_ed         = hash_ed + ep.AsymmCipher.GetSignatureLen()
	)
	now := protocol.SafeReadTimeLen()
	if uint64(len(msg))-sign_ed != now {
		return &protocol.HandShakeMsg{}, errors.New(protocol.CLIENT_FAKE_HANDSHAKE)
	}

	var handshakemsg protocol.HandShakeMsg = protocol.HandShakeMsg{
		Nonce:     utils.LittleEndianBytesToUint64([8]byte(msg[:nonce_ed])),
		Kern:      msg[nonce_ed:iv_ed],
		Hasher:    msg[iv_ed:hash_ed],
		Signature: msg[hash_ed:sign_ed],
		Timestamp: msg[sign_ed:],
	}
	return &handshakemsg, nil
}

/* Must ensure the pubkey has been generated before invoking this. */
func (ep *EncFlowProxy) GeneratePresessionKey() (*protocol.HandShakeMsg, error) {
	key, iv, err := cryptoprotect.GeneratePresessionKey(ep.StreamCipher)
	if err != nil {
		return nil, err
	}
	nonceIn64, nonce, err := protocol.GenerateRandUint64WithByteRepresentation()
	if err != nil {
		return nil, err
	}
	now := []byte(protocol.SafeResetLen())
	var (
		nonce_ed uint64 = 8
		iv_ed           = ep.KeyLen + ep.IvLen + nonce_ed
	)
	KeyIv := make([]byte, iv_ed-nonce_ed)

	ep.StreamCipher.SetKey(key)
	ep.StreamCipher.SetIv(iv)
	copy(KeyIv[:ep.KeyLen], key)
	copy(KeyIv[ep.KeyLen:], iv)

	kern := []byte(nonce)
	kern = append(kern, KeyIv...)
	kern = append(kern, now...)
	hasher := ep.HashCipher.CalculateHash(kern)
	signature, err := ep.AsymmCipher.PemSign(hasher)
	if err != nil {
		return nil, err
	}
	server_hello := protocol.HandShakeMsg{
		Nonce:     nonceIn64,
		Kern:      KeyIv,
		Hasher:    hasher,
		Signature: signature,
		Timestamp: now,
	}

	return &server_hello, nil
}

func (ep *EncFlowProxy) ProxyReadHello() error {
	client_hello, cnt, err := ep.Client.Read()

	if cnt != 4+auth.TokenLen || err != nil {
		return defErr.StrConcat(`unable to read crypto domain or err:`, err)
	}
	token := client_hello[4:]
	state, descript := auth.AuthValidation(token)
	if !state {
		return errors.New(descript)
	}

	_crypto_suite := [4]byte(client_hello[:4])
	crypto_suite := utils.LittleEndianBytesToUint32(_crypto_suite)
	functor := func(u uint32, i int) byte { return byte((u >> i) & 0xFF) }

	switch functor(crypto_suite, 0) {
	case byte(cryptoprotect.PICK_SM2):
		ep.AsymmCipher = &asymmetricciphers.SM2{}
		ep.ClientAsymmCipher = &asymmetricciphers.SM2{} // use the same asymmetric-crypto-suite
		ep.AsymmCipher.GenerateKeyPair()
	default:
		return errors.New(`unsupported asymmetric cipher`)
	}

	// TODO: We need a more elegant method to load the final cipher object rather than hard-encode.
	switch functor(crypto_suite, 8) {
	case byte(cryptoprotect.PICK_ZUC):
		ep.StreamCipher = &streamciphers.ZUC{}
	case byte(cryptoprotect.PICK_SALSA20):
		ep.StreamCipher = &streamciphers.Salsa20{}
	case byte(cryptoprotect.PICK_AES_OFB_256):
		ep.StreamCipher = &streamciphers.AES_OFB_256{}
	case byte(cryptoprotect.PICK_AES_CTR_256):
		ep.StreamCipher = &streamciphers.AES_CTR_256{}
	case byte(cryptoprotect.PICK_AES_GCM_256):
		ep.StreamCipher = &streamciphers.AES_GCM_256{}
	case byte(cryptoprotect.PICK_SM4_OFB_128):
		ep.StreamCipher = &streamciphers.SM4_OFB{}
	case byte(cryptoprotect.PICK_SM4_CTR_128):
		ep.StreamCipher = &streamciphers.SM4_CTR{}
	case byte(cryptoprotect.PICK_SM4_GCM_128):
		ep.StreamCipher = &streamciphers.SM4_GCM{}
	case byte(cryptoprotect.PICK_CHACHA20POLY1305_256):
		ep.StreamCipher = &streamciphers.Chacha20poly1305{}
	default:
		return errors.New(`unsupported stream cipher`)
	}
	ep.KeyLen, ep.IvLen = ep.StreamCipher.GetKeyLen(), ep.StreamCipher.GetIvLen()

	switch functor(crypto_suite, 16) {
	case byte(cryptoprotect.PICK_SM3):
		ep.HashCipher = &hashciphers.SM3{}
	case byte(cryptoprotect.PICK_SHA256):
		ep.HashCipher = &hashciphers.Sha256{}
	case byte(cryptoprotect.PICK_SHA3_256):
		ep.HashCipher = &hashciphers.Sha3_256{}
	case byte(cryptoprotect.PICK_SHA384):
		ep.HashCipher = &hashciphers.Sha384{}
	case byte(cryptoprotect.PICK_SHA3_384):
		ep.HashCipher = &hashciphers.Sha3_384{}
	case byte(cryptoprotect.PICK_SHA512):
		ep.HashCipher = &hashciphers.Sha512{}
	case byte(cryptoprotect.PICK_SHA3_512):
		ep.HashCipher = &hashciphers.Sha3_256{}
	case byte(cryptoprotect.PICK_BLAKE2B256):
		ep.HashCipher = &hashciphers.Blake2b256{}
	case byte(cryptoprotect.PICK_BLAKE2S256):
		ep.HashCipher = &hashciphers.Blake2s256{}
	case byte(cryptoprotect.PICK_BLAKE2B384):
		ep.HashCipher = &hashciphers.Blake2b384{}
	case byte(cryptoprotect.PICK_BLAKE2B512):
		ep.HashCipher = &hashciphers.Blake2b512{}
	default:
		return errors.New(`unsupported hash cipher`)
	}

	switch functor(crypto_suite, 24) {
	case byte(cryptoprotect.PICK_NULL_COMP):
		ep.CompOption = &zipper.IdCompress{}
	case byte(cryptoprotect.PICK_ZLIB_COMP):
		ep.CompOption = &zipper.Zlib{}
	default:
		return errors.New(`unsupproted compressed algorithm`)
	}
	return nil
}

// step 1 send ppub
func (ep *EncFlowProxy) writeStep1() error {
	err := ep.SendPub()
	if err != nil {
		ep.Client.CloseAll()
		return err
	}
	return nil
}

// step 1 wait ack PPUB
func (ep *EncFlowProxy) readStep1() error {
	ackppub, _, err := ep.Client.Read()
	if !protocol.AckFlowValidation(
		ep.HashCipher,
		ackppub,
		[]byte(protocol.ACKPPUB),
		ep.ackTimCheck,
		&ep.ackRec,
		ep.pingRef,
		false) {
		ep.Client.CloseAll()
		return defErr.StrConcat(protocol.FAILED_TO_VALIDATE_ACKPPUB, err)
	}
	return nil
}

// step 2 recv CPUB
func (ep *EncFlowProxy) readStep2() error {
	should_kill := func() {
		ep.wNeedBytes <- []byte{}
		ep.Client.CloseAll()
	}
	pub, _, err := ep.Client.Read()
	if err != nil {
		should_kill()
		return defErr.StrConcat(protocol.FAILED_TO_RECV_COMPRESSED_CPUB, err)
	}
	p, err := ep.CompOption.DecompressMsg(pub)
	if err != nil {
		should_kill()
		return err
	}
	ep.wNeedBytes <- p
	return nil
}

// step 2 ack CPUB
func (ep *EncFlowProxy) writeStep2() error {
	cpub := <-ep.wNeedBytes
	if uint64(len(cpub)) != ep.AsymmCipher.GetPubLen() {
		ep.Client.CloseAll()
		return errors.New(protocol.INVALID_CPUB_LENGTH)
	}
	now, curr_ack := protocol.AckToTimestampHash(ep.HashCipher, []byte(protocol.ACKCPUB))
	now = append(now, curr_ack...)
	// From the perspective of information theory, the entropy of ciphertext is rather higher than plaintext
	// and therefore ciphertext is more likely in arousing the suspicion.
	// Nevertheless, I think the sliced handshake payload will need compressing.
	cnt, err := ep.Client.Write(now)
	if cnt != uint(len(now)) || err != nil {
		ep.Client.CloseAll()
		return errors.New(protocol.FAILED_TO_SEND_ACKCPUB)
	}
	ep.ClientAsymmCipher.SetPub(cpub)
	return nil
}

// step4 send pflow1 | pflow2 and wait for ack
func (ep *EncFlowProxy) writeStep4(pflow []byte, turn int) error {
	pf, err := ep.CompOption.CompressMsg(pflow)
	if err != nil {
		ep.Client.CloseAll()
		return errors.New(protocol.FAILED_TO_COMPRESS_PFLOW)
	}
	cnt, err := ep.Client.Write(pf)
	if err != nil || cnt != uint(len(pf)) {
		ep.Client.CloseAll()
		return defErr.StrConcat(protocol.FAILED_TO_SEND_COMPRESSED_PFLOW, err)
	}
	// log.Println(`wait pflow`, turn)
	pack := <-ep.wNeedBytes
	var choice []byte
	switch turn {
	case 1:
		choice = []byte(protocol.ACKPPK1)
	case 2:
		choice = []byte(protocol.ACKPPK2)
	default:
		return errors.New(protocol.BILATERY_INVALID_ACKPFLOW)
	}

	if !protocol.AckFlowValidation(
		ep.HashCipher, pack, choice,
		ep.ackTimCheck, &ep.ackRec,
		ep.pingRef, true) {
		ep.Client.CloseAll()
		return errors.New(protocol.FAILED_TO_PARSE_ACKPFLOW)
	}
	return nil
}

// step3 recv ackpflow1 | ackpflow2
func (ep *EncFlowProxy) readStep4() error {
	ackppk, cnt, err := ep.Client.Read()
	if uint64(cnt) != protocol.SafeGainTimestampHashLen() || err != nil {
		ep.wNeedBytes <- []byte{}
		ep.Client.CloseAll()
		return defErr.StrConcat(protocol.FAILED_TO_PARSE_ACKPFLOW, err)
	}
	ep.wNeedBytes <- ackppk
	return nil
}

// step3 ack cflow1 | cflow2
func (ep *EncFlowProxy) writeStep3(turn int) error {
	var choice []byte
	switch turn {
	case 1:
		choice = []byte(protocol.ACKCPK1)
	case 2:
		choice = []byte(protocol.ACKCPK2)
	default:
		return errors.New(protocol.P_PREFIX + protocol.BILATERY_INVALID_ACKCFLOW)
	}
	if !<-ep.rSignal {
		ep.Client.CloseAll()
		return errors.New(protocol.P_PREFIX + protocol.BILATERY_INNER_SIGNAL_FAILED)
	}
	curr, res := protocol.AckToTimestampHash(ep.HashCipher, choice)
	cnt, err := ep.Client.Write(append(curr, res...))

	if uint64(cnt) != protocol.SafeGainTimestampHashLen() || err != nil {
		ep.Client.CloseAll()
		return defErr.StrConcat(protocol.FAILED_TO_SEND_ACKCFLOW, err)
	}
	return nil
}

// step3 recv cflow1 | cflow2
func (ep *EncFlowProxy) readStep3() ([]byte, error) {
	mission_failed := func(err error) ([]byte, error) {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return []byte{}, err
	}
	cf, _, err := ep.Client.Read()
	if err != nil {
		return mission_failed(err)
	}
	cflow, err := ep.CompOption.DecompressMsg(cf)
	if err != nil {
		return mission_failed(err)
	}
	ep.rSignal <- true
	return cflow, nil
}

// step 8 parse rn, combine p.nonce, c.nonce, rn and presession key to generate session key
func (ep *EncFlowProxy) rnAndDecrypt(cpk1, cpk2 []byte) (*protocol.HandShakeMsg, error) {
	cpk := append(cpk1, cpk2...)
	rn_pck, err := ep.decryptHandShakeMsg(cpk)
	if err != nil {
		ep.Client.CloseAll()
		return nil, defErr.StrConcat(protocol.P_PREFIX+protocol.BILATERY_PEM_DECRYPTION_FAILED, err)
	}
	rn, err := ep.extractHandShakeMsg(rn_pck)
	if err != nil {
		ep.Client.CloseAll()
		return nil, defErr.StrConcat(protocol.FAILED_TO_EXTRACT_RN, err)
	}
	return rn, nil
}

// step 9: verify hash and check for hash
func (ep *EncFlowProxy) recheckHash(rn *protocol.HandShakeMsg) error {
	verified := ep.ClientAsymmCipher.PubVerify(rn.Hasher, rn.Signature)
	if !verified {
		ep.Client.CloseAll()
		return errors.New(protocol.BILATERY_SIGNATURE_FAILURE)
	}
	hashX := utils.Uint64ToLittleEndianBytes(rn.Nonce)
	hashX = append(hashX, rn.Kern...)
	hashX = append(hashX, rn.Timestamp...)
	recheck_hash := ep.HashCipher.CalculateHash(hashX)
	status, descript := utils.CompareByteSliceEqualOrNot(recheck_hash, rn.Hasher)
	if !status {
		ep.Client.CloseAll()
		return errors.New(protocol.P_PREFIX + protocol.BILATERY_HASH_ACK_FAILURE + descript)
	}
	return nil
}

func (ep *EncFlowProxy) writeResponse(proxy_client_handshake *protocol.HandShakeMsg) error {
	if ep.rpk == nil {
		ep.Client.CloseAll()
		return errors.New(protocol.FAILED_TO_VALIDATE_RN)
	}
	tmpKey := protocol.GenerateSessionKey(
		[]byte(ep.StreamCipher.GetKey()),
		ep.rpk.Kern,
		ep.rpk.Nonce,
		proxy_client_handshake.Nonce,
		ep.StreamCipher,
		ep.HashCipher,
	)
	ep.StreamCipher.SetKey(tmpKey)

	// TOFIX: localhost will fail if proxy not sleep here
	time.Sleep(time.Microsecond)

	cnt, err := ep.EncWrite2Client(ep.rpk.Kern)
	currLen := uint64(len(ep.rpk.Kern)) + ep.StreamCipher.WithIvAttached()
	if err != nil || uint64(cnt) != currLen {
		ep.Client.CloseAll()
		return err
	}
	return nil
}

func (ep *EncFlowProxy) readFinish() error {
	mission_failed := func() {
		ep.rSignal <- false
		ep.Client.CloseAll()
	}
	_finish, cnt, err := ep.DecReadViaClient()
	currLen := protocol.SafeGainTimestampHashLen() + ep.StreamCipher.WithIvAttached()
	if uint64(cnt) != currLen || err != nil {
		mission_failed()
		return defErr.StrConcat(protocol.P_PREFIX+protocol.BILATERY_ACK_FINISHED_FAILURE, err)
	}
	if !protocol.AckFlowValidation(
		ep.HashCipher,
		_finish,
		[]byte(protocol.HANDHLT),
		ep.ackTimCheck,
		&ep.ackRec,
		ep.pingRef,
		false) {
		mission_failed()
		return errors.New(protocol.P_PREFIX + protocol.BILATERY_ACK_FINISHED_FAILURE)
	}
	ep.rSignal <- true
	return nil
}

func (ep *EncFlowProxy) writeFinish() error {
	curr, res := protocol.AckToTimestampHash(ep.HashCipher, []byte(protocol.HANDHLT))
	cnt, err := ep.EncWrite2Client(append(curr, res...))
	currLen := protocol.SafeGainTimestampHashLen() + ep.StreamCipher.WithIvAttached()
	if uint64(cnt) != currLen || err != nil {
		ep.Client.CloseAll()
		return defErr.StrConcat(
			protocol.P_PREFIX+protocol.BILATERY_FINISHED_FAILURE,
			err)
	}
	return nil
}

func (ep *EncFlowProxy) shakeHandWriteCoroutine() (werr error) {
	if !<-ep.rSignal {
		werr = errors.New(protocol.P_PREFIX + protocol.BILATERY_INVALID_HELLO)
		return
	}
	werr = ep.writeStep1()
	if werr != nil {
		return
	}
	werr = ep.writeStep2()
	if werr != nil {
		return
	}
	proxy_client_handshake, werr := ep.GeneratePresessionKey()
	if werr != nil {
		return
	}

	// TODO: can encryption here resist DDos?
	enc_flow, err := ep.cPubEncrypt(proxy_client_handshake)
	if err != nil {
		werr = err
		return
	}
	flow1, flow2 := utils.BytesSpliterInHalfChanceField(enc_flow)

	werr = ep.writeStep3(1) // ack cflow1
	if werr != nil {
		return
	}
	werr = ep.writeStep4(flow1, 1) // send pflow1
	if werr != nil {
		return
	}

	// TODO: can callee here here resist DDos?
	werr = ep.writeStep3(2) // ack cflow2
	if werr != nil {
		return
	}

	werr = ep.writeStep4(flow2, 2) // send pflow2
	if werr != nil {
		return
	}
	if !<-ep.rSignal { // wait successful check and then send response
		werr = errors.New(protocol.AN_INVALID_CFLOW)
		return
	}

	werr = ep.writeResponse(proxy_client_handshake)
	if werr != nil {
		return
	}
	if !<-ep.rSignal { // wait finish and then send finish
		werr = errors.New(protocol.AN_INVALID_CFLOW)
		return
	}

	// TODO: can callee below have the ability to resist DDos?
	werr = ep.writeFinish()
	return
}

func (ep *EncFlowProxy) shakeHandReadCoroutine() (rerr error) {
	rerr = ep.ProxyReadHello()
	if rerr != nil {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return
	}
	ep.rSignal <- true
	// TODO: estimate DDos?
	rerr = ep.readStep1()
	if rerr != nil {
		return
	}
	rerr = ep.readStep2()
	if rerr != nil {
		return
	}
	cflow1, rerr := ep.readStep3()
	if rerr != nil {
		return
	}
	rerr = ep.readStep4( /* ackpflow1 */ )
	if rerr != nil {
		return
	}
	cflow2, rerr := ep.readStep3()
	if rerr != nil {
		return
	}
	rerr = ep.readStep4( /* ackpflow2 */ )
	if rerr != nil {
		return
	}
	ep.rpk, rerr = ep.rnAndDecrypt(cflow1, cflow2)
	if rerr != nil {
		ep.rSignal <- false
		return
	}
	rerr = ep.recheckHash(ep.rpk)
	if rerr != nil {
		ep.rSignal <- false
		return
	}
	ep.rSignal <- true
	rerr = ep.readFinish()
	return
}

func (ep *EncFlowProxy) clientAddrSpliter() (string, string) {
	domain := ep.Client.Conn.RemoteAddr().String()
	pos := 0
	for i := len(domain) - 1; i > 0; i-- {
		if domain[i] == ':' {
			pos = i
			break
		}
	}
	return domain[:pos], domain[pos:]
}

/*
 * todo: `ping` is not the final silver bullet for network connectivity due to several ineluctable issues.
 * 		we need other protocols to dress up as pingers or resolve conflicts on current spot.
 * 		Model-Free Adaptive Predictive Control... ?
 */
func (ep *EncFlowProxy) Shakehand() (werr error, rerr error) {
	ip, _ := ep.clientAddrSpliter()
	ping_ref, ok := service.PingWithoutPrint(ip, 3, 4, 5, 5)
	if !ok {
		werr = errors.New(protocol.BILATERY_FAILED_TO_PING)
		rerr = errors.New(protocol.BILATERY_FAILED_TO_PING)
		return
	}
	ep.pingRef = ping_ref
	wch, rch := make(chan error), make(chan error)
	functor := func() {
		ep.ackTimCheck, ep.ackRec = new([8][]byte), 0
	}
	functor()
	defer functor()
	go func() { rch <- ep.shakeHandReadCoroutine(); close(rch) }()
	go func() { wch <- ep.shakeHandWriteCoroutine(); close(wch) }()
	werr, rerr = <-wch, <-rch
	// TODO: reset (pri, pub) keypair.
	return
}
