// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package proxy

import (
	"errors"
	"log"
	"time"

	cryptoprotect "selfproxy/cryptoProtect"
	zipper "selfproxy/cryptoProtect/zipper"
	defErr "selfproxy/defErr"
	protocol "selfproxy/protocol"
	utils "selfproxy/utils"
)

/*
TODO: speed limitation for preventing DDos.
	we need tact for single ip
		 		 for fake ips
*/

/*
invoke this after initialize `client_asymmetric_pub`.

	serialize the shakehand-msg into bytes, then encrypt with client_pub
*/
func (ep *EncFlowProxy) cPubEncrypt(shakehand *protocol.ShakeHandMsg) ([]byte, error) {
	serialization := make([]byte, 0)
	serialization = append(serialization, shakehand.Kern[:]...)
	serialization = append(serialization, utils.Uint64ToBytesInLittleEndian(shakehand.Nonce)...)
	serialization = append(serialization, shakehand.Hasher[:]...)
	serialization = append(serialization, shakehand.Signature[:]...)
	serialization = append(serialization, shakehand.Timestamp...)
	encrypt_msg, err := ep.ClientAsymmCipher.PubEncrypt(serialization)
	return encrypt_msg, err
}

func (ep *EncFlowProxy) decryptShakehandMsg(enc []byte) ([]byte, error) {
	dec, err := ep.AsymmCipher.PemDecrypt(enc)
	return dec, err
}

func (ep *EncFlowProxy) extractShakeHandMsg(msg []byte) (*protocol.ShakeHandMsg, error) {
	var (
		iv_ed    = cryptoprotect.KeySize + cryptoprotect.IVSize
		nonce_ed = iv_ed + 8
		hash_ed  = nonce_ed + cryptoprotect.HashSize
		sign_ed  = hash_ed + cryptoprotect.SignSize
	)
	if uint64(len(msg)-sign_ed) != protocol.TIME_LEN.SafeReadTimeLen() {
		return &protocol.ShakeHandMsg{}, errors.New(`fake shakehand-msg`)
	}
	var (
		ker    [cryptoprotect.KeySize + cryptoprotect.IVSize]byte
		hasher [cryptoprotect.HashSize]byte
		signer [cryptoprotect.SignSize]byte
	)
	copy(ker[:], msg[:iv_ed])
	copy(hasher[:], msg[nonce_ed:hash_ed])
	copy(signer[:], msg[hash_ed:sign_ed])

	var shakehandmsg protocol.ShakeHandMsg = protocol.ShakeHandMsg{
		Kern:      ker,
		Nonce:     utils.BytesToUint64([8]byte(msg[iv_ed:nonce_ed])),
		Hasher:    hasher,
		Signature: signer,
		Timestamp: msg[sign_ed:],
	}
	return &shakehandmsg, nil
}

func (ep *EncFlowProxy) ProxyReadHello( /* TODO: token should be extracted from config*/ ) error {
	client_hello, _, _ := ep.Client.Read()
	// TODO: TokenLen gain from config. Otherwise the authentication is not used at all.
	/*
		if cnt != 4+auth.TokenLen || err != nil {
			return defErr.DescribeThenConcat(`unable to read crypto domain or err:`, err)
		}
		token := client_hello[4:]
		state, descript := auth.AuthValidation(token)
		if !state {
			return errors.New(descript)
		}
	*/
	_crypto_suite := [4]byte(client_hello[:4])
	crypto_suite := utils.BytesToUint32(_crypto_suite)
	var functor func(uint32, int) byte = func(u uint32, i int) byte { return byte((u >> i) & 0xFF) }

	switch functor(crypto_suite, 0) {
	case byte(cryptoprotect.PICK_SM2):
		ep.AsymmCipher = &cryptoprotect.SM2{}
		ep.ClientAsymmCipher = &cryptoprotect.SM2{} // use the same asymmetric-crypto-suite
		ep.AsymmCipher.GenerateKeyPair()
	default:
		return errors.New(`unsupported asymmetric cipher`)
	}

	switch functor(crypto_suite, 8) {
	case byte(cryptoprotect.PICK_ZUC):
		ep.StreamCipher = &cryptoprotect.ZUC{}
	case byte(cryptoprotect.PICK_SALSA20):
		ep.StreamCipher = &cryptoprotect.Salsa20{}
	case byte(cryptoprotect.PICK_AES_OFB_256):
		ep.StreamCipher = &cryptoprotect.AES_OFB{}
	case byte(cryptoprotect.PICK_AES_CTR_256):
		ep.StreamCipher = &cryptoprotect.AES_CTR{}
	case byte(cryptoprotect.PICK_AES_GCM_256):
		ep.StreamCipher = &cryptoprotect.AES_GCM{}
	case byte(cryptoprotect.PICK_SM4_OFB_256):
		ep.StreamCipher = &cryptoprotect.SM4_OFB{}
	case byte(cryptoprotect.PICK_SM4_CTR_256):
		ep.StreamCipher = &cryptoprotect.SM4_CTR{}
	case byte(cryptoprotect.PICK_SM4_GCM_256):
		ep.StreamCipher = &cryptoprotect.SM4_GCM{}
	case byte(cryptoprotect.PICK_CHACHA20POLY1305_256):
		ep.StreamCipher = &cryptoprotect.Chacha20poly1305{}
	default:
		return errors.New(`unsupported stream cipher`)
	}

	switch functor(crypto_suite, 16) {
	case byte(cryptoprotect.PICK_SM3):
		ep.HashCipher = &cryptoprotect.SM3{}
	case byte(cryptoprotect.PICK_SHA256):
		ep.HashCipher = &cryptoprotect.Sha256{}
	case byte(cryptoprotect.PICK_SHA3_256):
		ep.HashCipher = &cryptoprotect.Sha3_256{}
	case byte(cryptoprotect.PICK_BLAKE2B256):
		ep.HashCipher = &cryptoprotect.Blake2b256{}
	case byte(cryptoprotect.PICK_BLAKE2S256):
		ep.HashCipher = &cryptoprotect.Blake2s256{}
	default:
		return errors.New(`unsupported hash cipher`)
	}

	switch functor(crypto_suite, 24) {
	case byte(cryptoprotect.PICK_NULL_COMP):
		ep.CompOption = &zipper.IdCompress{}
	case byte(cryptoprotect.PICK_ZLIB_COMP):
		ep.CompOption = &zipper.Zlib{}
	default:
		return errors.New(`unsupproted compression algorithm`)
	}
	return nil
}

/* Must ensure the pubkey has been generated before invoking this. */
func (ep *EncFlowProxy) GeneratePresessionKey() (*protocol.ShakeHandMsg, error) {
	key, iv, err := cryptoprotect.GeneratePresessionKey()
	if err != nil {
		return nil, err
	}

	nonceIn64, nonce, err := protocol.GenerateRandUint64WithByteRepresentation()
	if err != nil {
		return nil, err
	}
	str_now := protocol.TIME_LEN.SafeResetLen()
	now := []byte(str_now)

	iv_ed := cryptoprotect.KeySize + cryptoprotect.IVSize
	kern := make([]byte, iv_ed+8)
	var (
		KeyIv     [cryptoprotect.KeySize + cryptoprotect.IVSize]byte
		hasher    [cryptoprotect.HashSize]byte
		signature [cryptoprotect.SignSize]byte
	)
	ep.StreamCipher.SetKey(key)
	ep.StreamCipher.SetIv(iv)

	copy(KeyIv[:cryptoprotect.KeySize], key)
	copy(KeyIv[cryptoprotect.KeySize:], iv)

	copy(kern[:iv_ed], KeyIv[:])
	copy(kern[iv_ed:iv_ed+8], nonce)
	kern = append(kern, now...)
	hashInCalc := ep.HashCipher.CalculateHash(kern)
	copy(hasher[:], hashInCalc)

	_signature, err := ep.AsymmCipher.PemSign(hasher[:])
	if err != nil {
		return nil, err
	}
	copy(signature[:], _signature)
	server_hello := protocol.ShakeHandMsg{
		Kern:      KeyIv,
		Nonce:     nonceIn64,
		Hasher:    hasher,
		Signature: signature,
		Timestamp: now,
	}

	return &server_hello, nil
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
	if !protocol.AckFlowValidation(ep.HashCipher, ackppub, []byte(protocol.ACKPPUB), &ep.ackTimCheck, &ep.ackRec) {
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`unexpected cnt or err:`, err)
	}
	return nil
}

// step 2 recv CPUB
func (ep *EncFlowProxy) readStep2() error {
	pub, _, err := ep.Client.Read()
	if err != nil {
		ep.wNeedBytes <- []byte(``)
		ep.Client.CloseAll()
		return err
	}
	p, err := ep.CompOption.DecompressMsg(pub)
	if err != nil {
		ep.wNeedBytes <- []byte(``)
		ep.Client.CloseAll()
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
		return errors.New(`fake cpub`)
	}
	now, curr_ack := protocol.AckToTimestampHash(ep.HashCipher, []byte(protocol.ACKCPUB))
	now = append(now, curr_ack...)
	// TODO: compress hash or not only for pubkey but should compress all?
	// From the perspective of information theory, the entropy of ciphertext is rather higher than plaintext
	// and therefore ciphertext is more likely in arousing the suspicion.
	// Nevertheless, I think the sliced handshake payload will need this.
	cnt, err := ep.Client.Write(now)
	if cnt != uint(len(now)) || err != nil {
		ep.Client.CloseAll()
		return errors.New(`ack-cpub sending failure`)
	}
	ep.ClientAsymmCipher.SetPub(cpub)
	return nil
}

// step4 send pflow1 | pflow2 and wait for ack
func (ep *EncFlowProxy) writeStep4(pflow []byte, turn int) error {
	pf, err := ep.CompOption.CompressMsg(pflow)
	if err != nil {
		ep.Client.CloseAll()
		return errors.New(`unable to compress pflow`)
	}
	cnt, err := ep.Client.Write(pf)
	if err != nil || cnt != uint(len(pf)) {
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`inproperly write to proxy`, err)
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
		return errors.New(`invalid turn`)
	}

	if !protocol.AckFlowValidation(ep.HashCipher, pack, choice, &ep.ackTimCheck, &ep.ackRec) {
		ep.Client.CloseAll()
		return errors.New("client: proxy send a fraud ack-cpk ")
	}
	return nil
}

// step3 recv ackpflow1 | ackpflow2
func (ep *EncFlowProxy) readStep4() error {
	ackppk, cnt, err := ep.Client.Read()
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		ep.wNeedBytes <- []byte(``)
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`ackpck failed or err:`, err)
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
		return errors.New(`invalid turn`)
	}
	if !<-ep.rSignal {
		ep.Client.CloseAll()
		return errors.New(`failed to recv cpack which is accessed from ep.rSignal`)
	}
	curr, res := protocol.AckToTimestampHash(ep.HashCipher, choice)
	cnt, err := ep.Client.Write(append(curr, res...))

	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`incorrectly send ack-cpk`, err)
	}
	return nil
}

// step3 recv cflow1 | cflow2
func (ep *EncFlowProxy) readStep3() ([]byte, error) {
	cf, _, err := ep.Client.Read()
	if err != nil {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return []byte(``), err
	}
	cflow, err := ep.CompOption.DecompressMsg(cf)
	if err != nil {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return []byte(``), err
	}
	ep.rSignal <- true
	return cflow, nil
}

// step 8 parse rn, combine p.nonce, c.nonce, rn and presession key to generate session key
func (ep *EncFlowProxy) rnAndDecrypt(cpk1, cpk2 []byte) (*protocol.ShakeHandMsg, error) {
	cpk := append(cpk1, cpk2...)
	rn_pck, err := ep.decryptShakehandMsg(cpk)
	if err != nil {
		ep.Client.CloseAll()
		return nil, defErr.DescribeThenConcat(`client-pem-decrypt failed:`, err)
	}
	rn, err := ep.extractShakeHandMsg(rn_pck)
	if err != nil {
		ep.Client.CloseAll()
		return nil, defErr.DescribeThenConcat(`extract-rn failed`, err)
	}
	return rn, nil
}

// step 9: verify hash and check for hash
func (ep *EncFlowProxy) recheckHash(rn *protocol.ShakeHandMsg) error {
	verified := ep.ClientAsymmCipher.PubVerify(rn.Hasher[:], rn.Signature[:])
	if !verified {
		ep.Client.CloseAll()
		return errors.New(`failed to verify signature`)
	}
	hashX := append(rn.Kern[:], utils.Uint64ToBytesInLittleEndian(rn.Nonce)...)
	hashX = append(hashX, rn.Timestamp...)
	recheck_hash := [32]byte(ep.HashCipher.CalculateHash(hashX))
	status, descript := utils.CompareByteSliceEqualOrNot(recheck_hash[:], rn.Hasher[:])
	if !status {
		ep.Client.CloseAll()
		return errors.New("HashError:" + descript)
	}
	return nil
}

func (ep *EncFlowProxy) writeResponse(proxy_client_shakehand *protocol.ShakeHandMsg) error {
	if ep.rpk == nil {
		ep.Client.CloseAll()
		return errors.New(`rn validation failed`)
	}
	tmpKey := protocol.GenerateSessionKey(
		[32]byte(ep.StreamCipher.GetKey()),
		ep.rpk.Kern,
		ep.rpk.Nonce,
		proxy_client_shakehand.Nonce,
		ep.HashCipher,
	)
	ep.StreamCipher.SetKey(tmpKey[:])

	// TOFIX: localhost will fail if not sleeping here
	time.Sleep(time.Microsecond)

	cnt, err := ep.EncWrite2Client(ep.rpk.Kern[:])
	if err != nil || cnt != uint(len(ep.rpk.Kern)) {
		ep.Client.CloseAll()
		return err
	}
	return nil
}

func (ep *EncFlowProxy) readFinish() error {
	_finish, cnt, err := ep.DecReadViaClient()
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`proxy: unexpected cut or err:`, err)
	}
	if !protocol.AckFlowValidation(ep.HashCipher, _finish, []byte(protocol.HANDHLT), &ep.ackTimCheck, &ep.ackRec) {
		ep.rSignal <- false
		ep.Client.CloseAll()
		return errors.New(`client finished failed`)
	}
	ep.rSignal <- true
	return nil
}

func (ep *EncFlowProxy) writeFinish() error {
	curr, res := protocol.AckToTimestampHash(ep.HashCipher, []byte(protocol.HANDHLT))
	cnt, err := ep.EncWrite2Client(append(curr, res...))
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		ep.Client.CloseAll()
		return defErr.DescribeThenConcat(`failed to send final finish or err:`, err)
	}
	return nil
}

func (ep *EncFlowProxy) shakeHandWriteCoroutine() (werr error) {
	if !<-ep.rSignal {
		werr = errors.New(`quit for invalid client-hello`)
		return
	}
	werr = ep.writeStep1()
	if werr != nil {
		return
	}
	// log.Println(`PPUB has sent`)
	werr = ep.writeStep2()
	if werr != nil {
		return
	}
	// log.Println(`ackcpub has sent`)
	proxy_client_shakehand, werr := ep.GeneratePresessionKey()
	if werr != nil {
		return
	}

	// TODO: can here resist DDos?
	enc_flow, err := ep.cPubEncrypt(proxy_client_shakehand)
	if err != nil {
		werr = err
		return
	}
	flow1, flow2 := utils.BytesSpliterInHalfChanceField(enc_flow)

	// TODO: can here resist DDos?
	werr = ep.writeStep3(1) // ack cflow1
	if werr != nil {
		return
	}
	// log.Println(`ackcflow1 has sent`)
	werr = ep.writeStep4(flow1, 1) // send pflow1
	if werr != nil {
		return
	}

	// log.Println(`pflow1 has sent`)
	// TODO: can here resist DDos?
	werr = ep.writeStep3(2) // ack cflow2
	if werr != nil {
		return
	}

	// log.Println(`ackcflow2 has sent`)
	werr = ep.writeStep4(flow2, 2) // send pflow2
	if werr != nil {
		return
	}
	// log.Println(`pflow2 has sent`)
	if !<-ep.rSignal { // wait successful check and then send response
		werr = errors.New(`invalid cpack`)
		return
	}

	werr = ep.writeResponse(proxy_client_shakehand)
	if werr != nil {
		return
	}
	if !<-ep.rSignal { // wait finish and then send finish
		werr = errors.New(`invalid cpack`)
		return
	}

	// TODO: can such command below have the ability to resist DDos?
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
	// log.Println(`ackppub has recv`)
	rerr = ep.readStep2()
	if rerr != nil {
		return
	}
	// log.Println(`cpub has recv`)
	cflow1, rerr := ep.readStep3()
	if rerr != nil {
		return
	}
	// log.Println(`cflow1 has recv`)
	rerr = ep.readStep4( /* ackpflow1 */ )
	if rerr != nil {
		return
	}
	// log.Println(`ackpflow1 has recv`)
	cflow2, rerr := ep.readStep3()
	if rerr != nil {
		return
	}
	// log.Println(`cflow2 has recv`)
	rerr = ep.readStep4( /* ackpflow2 */ )
	if rerr != nil {
		return
	}
	// log.Println(`ackpflow2 has recv`)
	ep.rpk, rerr = ep.rnAndDecrypt(cflow1, cflow2)
	if rerr != nil {
		log.Println(`failed to dec, send false signal to ep-writer`)
		ep.rSignal <- false
		return
	}
	// log.Println(`rn has dec`)
	rerr = ep.recheckHash(ep.rpk)
	if rerr != nil {
		log.Println(`failed to validate hash, send false signal to ep-writer`)
		ep.rSignal <- false
		return
	}
	// log.Println(`hash has passed`)
	ep.rSignal <- true
	rerr = ep.readFinish()
	return
}

func (ep *EncFlowProxy) Shakehand() (werr error, rerr error) {
	wch, rch, functor := make(chan error), make(chan error), func() { ep.ackTimCheck, ep.ackRec = [8][]byte{}, 0 }
	functor()
	defer functor()
	defer close(wch)
	defer close(rch)
	go func() { rch <- ep.shakeHandReadCoroutine() }()
	go func() { wch <- ep.shakeHandWriteCoroutine() }()
	werr, rerr = <-wch, <-rch
	// TODO: reset (pri, pub) keypair.
	return
}
