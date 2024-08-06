// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>

package protocol

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
	custom "bingoproxy/protocol/custom"
	service "bingoproxy/service/pingTimer"
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
func (ep *EncFlowProxy) cPubEncrypt(handshake *custom.HandShakeMsg) ([]byte, error) {
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

func (ep *EncFlowProxy) extractHandShakeMsg(msg []byte) (*custom.HandShakeMsg, error) {
	var (
		nonce_ed uint64 = 8
		iv_ed           = nonce_ed + ep.KeyLen + ep.IvLen
		hash_ed         = iv_ed + ep.HashCipher.GetHashLen()
		sign_ed         = hash_ed + ep.AsymmCipher.GetSignatureLen()
	)
	now := custom.SafeReadTimeLen()
	if uint64(len(msg)) != now+sign_ed {
		return &custom.HandShakeMsg{}, errors.New(custom.CLIENT_FAKE_HANDSHAKE)
	}

	var handshakemsg custom.HandShakeMsg = custom.HandShakeMsg{
		Nonce:     utils.LittleEndianBytesToUint64([8]byte(msg[:nonce_ed])),
		Kern:      msg[nonce_ed:iv_ed],
		Hasher:    msg[iv_ed:hash_ed],
		Signature: msg[hash_ed:sign_ed],
		Timestamp: msg[sign_ed:],
	}
	return &handshakemsg, nil
}

/* Must ensure the pubkey has been generated before invoking this. */
func (ep *EncFlowProxy) GeneratePresessionKey() (*custom.HandShakeMsg, error) {
	key, iv, err := custom.GeneratePresessionKey(ep.StreamCipher)
	if err != nil {
		return nil, err
	}
	nonceIn64, nonce, err := custom.GenerateRandUint64WithByteRepresentation()
	if err != nil {
		return nil, err
	}
	now := []byte(custom.SafeResetLen())
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
	hasher := ep.HashCipher.CalculateHashOnce(kern)
	signature, err := ep.AsymmCipher.PemSign(hasher)
	if err != nil {
		return nil, err
	}
	server_hello := custom.HandShakeMsg{
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
		// client use the same asymmetric-crypto-suite
		ep.ClientAsymmCipher = &asymmetricciphers.SM2{}
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
	case byte(cryptoprotect.PICK_CHACHA20POLY_256):
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
		ep.HashCipher = &hashciphers.Sha3_512{}
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
		ep.CompOption = &zipper.IdCompresser{}
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
		ep.Client.CloseConn()
		return err
	}
	return nil
}

// step 1 wait ack PPUB
func (ep *EncFlowProxy) readStep1() error {
	ackppub, _, err := ep.Client.Read()
	if !custom.AckFlowValidator(
		ep.HashCipher,
		ackppub,
		[]byte(custom.ACKPPUB),
		ep.ackTimCheck,
		&ep.ackRec,
		ep.pingRef,
		false) {
		ep.Client.CloseConn()
		return defErr.StrConcat(custom.INVALID_ACKPPUB, err)
	}
	return nil
}

// step 2 recv CPUB
func (ep *EncFlowProxy) readStep2() error {
	should_kill := func() {
		ep.wNeedBytes <- nil
		ep.Client.CloseConn()
	}
	pub, _, err := ep.Client.Read()
	if err != nil {
		should_kill()
		return defErr.StrConcat(custom.RECV_COMP_CPUB_FAILURE, err)
	}
	p, err := ep.CompOption.DecompressMsg(pub)
	if err != nil {
		should_kill()
		return err
	}
	ep.wNeedBytes <- &p
	return nil
}

// step 2 ack CPUB
func (ep *EncFlowProxy) writeStep2() error {
	cpub := <-ep.wNeedBytes
	if cpub == nil || uint64(len(*cpub)) != ep.AsymmCipher.GetPubLen() {
		ep.Client.CloseConn()
		return errors.New(custom.INVALID_CPUB_LENGTH)
	}
	now, curr_ack := custom.AckToTimestampHash(ep.HashCipher, []byte(custom.ACKCPUB))
	now = append(now, curr_ack...)
	/*
		From the perspective of information theory, the entropy of ciphertext is rather higher than plaintext
		and therefore ciphertext is more likely in arousing the suspicion.
		Nevertheless, I think the sliced handshake payload will need compressing.
	*/
	cnt, err := ep.Client.Write(now)
	if cnt != uint(len(now)) || err != nil {
		ep.Client.CloseConn()
		return errors.New(custom.SEND_ACKCPUB_FAILURE)
	}
	ep.ClientAsymmCipher.SetPub(cpub)
	return nil
}

// step4 send pflow1 | pflow2 and wait for ack
func (ep *EncFlowProxy) writeStep4(pflow []byte, turn int) error {
	pf, err := ep.CompOption.CompressMsg(pflow)
	if err != nil {
		ep.Client.CloseConn()
		return errors.New(custom.COMPRESS_PFLOW_FAILURE)
	}
	cnt, err := ep.Client.Write(pf)
	if err != nil || cnt != uint(len(pf)) {
		ep.Client.CloseConn()
		return defErr.StrConcat(custom.SEND_COMP_PFLOW_FAILURE, err)
	}
	// log.Println(`wait pflow`, turn)
	pack := <-ep.wNeedBytes
	if pack == nil {
		return errors.New(`unable to gain pflow`)
	}
	var choice []byte
	defer func() { choice = nil }()
	switch turn {
	case 1:
		choice = []byte(custom.ACKPPK1)
	case 2:
		choice = []byte(custom.ACKPPK2)
	default:
		return errors.New(custom.BI_INVALID_ACKPFLOW)
	}

	if !custom.AckFlowValidator(
		ep.HashCipher, *pack, choice,
		ep.ackTimCheck, &ep.ackRec,
		ep.pingRef, true) {
		ep.Client.CloseConn()
		return errors.New(custom.PARSE_ACKPFLOW_FAILURE)
	}
	return nil
}

// step3 recv ackpflow1 | ackpflow2
func (ep *EncFlowProxy) readStep4() error {
	ackppk, cnt, err := ep.Client.Read()
	if uint64(cnt) != custom.SafeGainTimestampHashLen() || err != nil {
		ep.wNeedBytes <- nil
		ep.Client.CloseConn()
		return defErr.StrConcat(custom.PARSE_ACKPFLOW_FAILURE, err)
	}
	ep.wNeedBytes <- &ackppk
	return nil
}

// step3 ack cflow1 | cflow2
func (ep *EncFlowProxy) writeStep3(turn int) error {
	var choice []byte
	defer func() { choice = nil }()
	switch turn {
	case 1:
		choice = []byte(custom.ACKCPK1)
	case 2:
		choice = []byte(custom.ACKCPK2)
	default:
		return errors.New(custom.P_PREFIX + custom.BI_INVALID_ACKCFLOW)
	}
	if !<-ep.rSignal {
		ep.Client.CloseConn()
		return errors.New(custom.P_PREFIX + custom.BI_INNER_SIGNAL_FAILED)
	}
	curr, res := custom.AckToTimestampHash(ep.HashCipher, choice)
	cnt, err := ep.Client.Write(append(curr, res...))

	if uint64(cnt) != custom.SafeGainTimestampHashLen() || err != nil {
		ep.Client.CloseConn()
		return defErr.StrConcat(custom.SEND_ACKCFLOW_FAILURE, err)
	}
	return nil
}

// step3 recv cflow1 | cflow2
func (ep *EncFlowProxy) readStep3() ([]byte, error) {
	mission_failed := func(err error) ([]byte, error) {
		ep.rSignal <- false
		ep.Client.CloseConn()
		return nil, err
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
func (ep *EncFlowProxy) rnAndDecrypt(cpk1, cpk2 []byte) (*custom.HandShakeMsg, error) {
	cpk := append(cpk1, cpk2...)
	failed := func(inp string, err error) (*custom.HandShakeMsg, error) {
		ep.Client.CloseConn()
		return nil, defErr.StrConcat(inp, err)
	}
	rn_pck, err := ep.decryptHandShakeMsg(cpk)
	if err != nil {
		return failed(custom.P_PREFIX+custom.BI_BAD_PEM_DECRYPTION, err)
	}
	rn, err := ep.extractHandShakeMsg(rn_pck)
	if err != nil {
		return failed(custom.EXTRACT_RN_FAILURE, err)
	}
	return rn, nil
}

// step 9: verify hash and check for hash
func (ep *EncFlowProxy) recheckHash(rn *custom.HandShakeMsg) error {
	verified := ep.ClientAsymmCipher.PubVerify(rn.Hasher, rn.Signature)
	if !verified {
		ep.Client.CloseConn()
		return errors.New(custom.BI_SIGNATURE_FAILURE)
	}
	hashX := utils.Uint64ToLittleEndianBytes(rn.Nonce)
	hashX = append(hashX, rn.Kern...)
	hashX = append(hashX, rn.Timestamp...)
	recheck_hash := ep.HashCipher.CalculateHashOnce(hashX)
	status, descript := utils.CmpByte2Slices(recheck_hash, rn.Hasher)
	if !status {
		ep.Client.CloseConn()
		return errors.New(custom.P_PREFIX + custom.BI_HASH_ACK_FAILURE + descript)
	}
	return nil
}

func (ep *EncFlowProxy) writeResponse(proxy_client_handshake *custom.HandShakeMsg) error {
	if ep.rpk == nil {
		ep.Client.CloseConn()
		return errors.New(custom.INVALID_RN)
	}
	tmpKey := custom.GenerateSessionKey(
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
		ep.Client.CloseConn()
		return err
	}
	return nil
}

func (ep *EncFlowProxy) readFinish() error {
	mission_failed := func() {
		ep.rSignal <- false
		ep.Client.CloseConn()
	}
	_finish, cnt, err := ep.DecReadViaClient()
	currLen := custom.SafeGainTimestampHashLen() + ep.StreamCipher.WithIvAttached()
	if uint64(cnt) != currLen || err != nil {
		mission_failed()
		return defErr.StrConcat(custom.P_PREFIX+custom.BI_ACK_FINISHED_FAILED, err)
	}
	if !custom.AckFlowValidator(
		ep.HashCipher,
		_finish,
		[]byte(custom.HANDHLT),
		ep.ackTimCheck,
		&ep.ackRec,
		ep.pingRef,
		false) {
		mission_failed()
		return errors.New(custom.P_PREFIX + custom.BI_ACK_FINISHED_FAILED)
	}
	ep.rSignal <- true
	return nil
}

func (ep *EncFlowProxy) writeFinish() error {
	curr, res := custom.AckToTimestampHash(ep.HashCipher, []byte(custom.HANDHLT))
	cnt, err := ep.EncWrite2Client(append(curr, res...))
	currLen := custom.SafeGainTimestampHashLen() + ep.StreamCipher.WithIvAttached()
	if uint64(cnt) != currLen || err != nil {
		ep.Client.CloseConn()
		return defErr.StrConcat(custom.P_PREFIX+custom.BI_FINISHED_FAILURE, err)
	}
	return nil
}

func (ep *EncFlowProxy) shakeHandWriteCoroutine() (werr error) {
	if !<-ep.rSignal {
		werr = errors.New(custom.P_PREFIX + custom.BI_INVALID_HELLO)
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
	flow1, flow2 := utils.BytesSplitInHalfChanceField(enc_flow)

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
	if !<-ep.rSignal {
		werr = errors.New(custom.INVALID_CFLOW)
		return
	}

	werr = ep.writeResponse(proxy_client_handshake)
	if werr != nil {
		return
	}
	if !<-ep.rSignal {
		werr = errors.New(custom.INVALID_CFLOW)
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
		ep.Client.CloseConn()
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
	pos := utils.FindPosCutNetworkAddrPort(domain)
	return domain[:pos], domain[pos:]
}

func (ep *EncFlowProxy) checkChan() bool {
	return ep.rSignal == nil || ep.wNeedBytes == nil
}

/*
 * todo: `ping` is not the final silver bullet for network connectivity due to several ineluctable issues.
 * 		we need other protocols to dress up as pingers or resolve conflicts on current spot.
 * 		Model-Free Adaptive Predictive Control... ?
 */
func (ep *EncFlowProxy) Shakehand() (werr error, rerr error) {
	if ep.checkChan() {
		ep.initChannel()
	}
	defer ep.deleteChannel()

	ip, _ /* port */ := ep.clientAddrSpliter()
	ping_ref, ok := service.PingWithoutPrint(ip, 3, 4, 5, 5)
	if !ok {
		werr = errors.New(custom.BI_FAILED_TO_PING)
		rerr = errors.New(custom.BI_FAILED_TO_PING)
		return
	}
	ep.pingRef = ping_ref

	wch, rch := make(chan error), make(chan error)
	ep.ackTimCheck, ep.ackRec = new([8][]byte), 0
	defer func() {
		ep.ackTimCheck, ep.ackRec = nil, 0
		ep.rpk = nil
	}()
	go func() { rch <- ep.shakeHandReadCoroutine(); close(rch) }()
	go func() { wch <- ep.shakeHandWriteCoroutine(); close(wch) }()
	werr, rerr = <-wch, <-rch
	return
}
