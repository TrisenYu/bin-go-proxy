// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package client

import (
	"crypto/rand"
	"errors"
	"log"
	"time"

	cryptoprotect "bingoproxy/cryptoProtect"
	zipper "bingoproxy/cryptoProtect/zipper"
	defErr "bingoproxy/defErr"
	protocol "bingoproxy/protocol"
	service "bingoproxy/service"
	utils "bingoproxy/utils"
)

/*
invoke this after gaining the proxy pubkey.

	serialize the handshake-msg into bytes and encrypt with proxy's pubkey.
*/
func (c *Client) pPubEncryptHandShakeMsg(handshake *protocol.HandShakeMsg) ([]byte, error) {
	serialization := make([]byte, 0)
	serialization = append(serialization, handshake.Kern[:]...)
	serialization = append(serialization, utils.Uint64ToBytesInLittleEndian(handshake.Nonce)...)
	serialization = append(serialization, handshake.Hasher[:]...)
	serialization = append(serialization, handshake.Signature[:]...)
	serialization = append(serialization, handshake.Timestamp...)
	encrypt_msg, err := c.ProxyAsymmCipher.PubEncrypt(serialization)
	return encrypt_msg, err
}

/* invoke this after generating pubkey */
func (c *Client) generateRN() (*protocol.HandShakeMsg, error) {
	var (
		iv_ed    = cryptoprotect.KeySize + cryptoprotect.IVSize
		nonce_ed = iv_ed + 8
	)
	rn := [cryptoprotect.KeySize + cryptoprotect.IVSize]byte{}
	_, err := rand.Reader.Read(rn[:])
	if err != nil {
		return nil, err
	}
	nonceIn64, nonce, err := protocol.GenerateRandUint64WithByteRepresentation()
	if err != nil {
		return nil, err
	}

	str_now := protocol.TIME_LEN.SafeResetLen()
	now := []byte(str_now)
	kern := make([]byte, nonce_ed+len(now))
	copy(kern[:iv_ed], rn[:])
	copy(kern[iv_ed:nonce_ed], nonce)
	copy(kern[nonce_ed:], now)

	var (
		hasher     [cryptoprotect.HashSize]byte
		signature  [cryptoprotect.SignSize]byte
		hashInCalc = c.HashCipher.CalculateHash(kern)
	)
	copy(hasher[:], hashInCalc[:])
	_signature, err := c.AsymmCipher.PemSign(hasher[:])
	if err != nil {
		return nil, err
	}
	copy(signature[:], _signature[:cryptoprotect.SignSize])
	client_hello := protocol.HandShakeMsg{
		Kern:      rn,
		Nonce:     nonceIn64,
		Hasher:    hasher,
		Signature: signature,
		Timestamp: now,
	}
	return &client_hello, nil
}

// Hard-encode HandShakeMsg.
func (c *Client) extractHandShakeMsg(msg []byte) (*protocol.HandShakeMsg, error) {
	var (
		iv_ed    = cryptoprotect.IVSize + cryptoprotect.KeySize
		nonce_ed = iv_ed + 8
		hash_ed  = nonce_ed + cryptoprotect.HashSize
		sign_ed  = hash_ed + cryptoprotect.SignSize
	)
	if uint64(len(msg)-sign_ed) != protocol.TIME_LEN.SafeReadTimeLen() {
		return &protocol.HandShakeMsg{}, errors.New(protocol.PROXY_FAKE_HANDSHAKE)
	}

	var (
		ker    [cryptoprotect.KeySize + cryptoprotect.IVSize]byte
		hasher [cryptoprotect.HashSize]byte
		signer [cryptoprotect.SignSize]byte
	)
	copy(ker[:], msg[:iv_ed])
	copy(hasher[:], msg[nonce_ed:hash_ed])
	copy(signer[:], msg[hash_ed:sign_ed])

	var handshakemsg protocol.HandShakeMsg = protocol.HandShakeMsg{
		Kern:      ker,
		Nonce:     utils.BytesToUint64([8]byte(msg[iv_ed:nonce_ed])),
		Hasher:    hasher,
		Signature: signer,
		Timestamp: msg[sign_ed:],
	}
	return &handshakemsg, nil
}

/*
TODO: Remote handshake.

Client or Proxy will directly disconnect if any error emerges during Stage handshake.

Client send clientHello to login proxy.
	clientHello contains a crypto-suite number which indicates the corresponding crypto algorithms to be
	utilized and a access-token generated by login proxy beforehand.

Once the access-token is verified, proxy will generate its (pri, pub) key pair and send the pub key to client and wait for ack.
Otherwise this connection will be immediately aborted. This method is suitable for subsequent use.

After client acknowleges the PPUB, Client should send CPUB to proxy and wait for ack.
Once receiving ack, then generates a handshake-Msg and divides it into two parts, and the first part will possess 50~60 percent.

Send each part sequentially while receiving the proxy-handshakeMsg and wait for corresponding ack and verify the validation.

And then generate session key from the message and send `finish` to proxy and wait for proxy response.
*/

func (c *Client) SendClientHelloPayload(asym_cfg, flow_cfg, hash_cfg, zip_cfg, access_token string) error {
	var choice uint32 = 0x00000000

	switch asym_cfg {
	case `sm2`:
		fallthrough
	default:
		choice |= uint32(cryptoprotect.PICK_SM2)
		c.AsymmCipher = &cryptoprotect.SM2{}
		c.ProxyAsymmCipher = &cryptoprotect.SM2{}
		c.AsymmCipher.GenerateKeyPair()
	}

	switch flow_cfg {
	case `salsa20`:
		choice |= uint32(cryptoprotect.PICK_SALSA20) << 8
		c.StreamCipher = &cryptoprotect.Salsa20{}
	case `aes-ofb-256`:
		choice |= uint32(cryptoprotect.PICK_AES_OFB_256) << 8
		c.StreamCipher = &cryptoprotect.AES_OFB{}
	case `aes-ctr-256`:
		choice |= uint32(cryptoprotect.PICK_AES_CTR_256) << 8
		c.StreamCipher = &cryptoprotect.AES_CTR{}
	case `aes-gcm-256`:
		// not recommanded?
		choice |= uint32(cryptoprotect.PICK_AES_GCM_256) << 8
		c.StreamCipher = &cryptoprotect.AES_GCM{}
	case `sm4-ofb-256`:
		choice |= uint32(cryptoprotect.PICK_SM4_OFB_256) << 8
		c.StreamCipher = &cryptoprotect.SM4_OFB{}
	case `sm4-ctr-256`:
		choice |= uint32(cryptoprotect.PICK_SM4_CTR_256) << 8
		c.StreamCipher = &cryptoprotect.SM4_CTR{}
	case `sm4-gcm-256`:
		choice |= uint32(cryptoprotect.PICK_SM4_GCM_256) << 8
		c.StreamCipher = &cryptoprotect.SM4_GCM{}
	case `chacha20poly1305`:
		choice |= uint32(cryptoprotect.PICK_CHACHA20POLY1305_256) << 8
		c.StreamCipher = &cryptoprotect.Chacha20poly1305{}
	case `zuc`:
		fallthrough
	default:
		choice |= uint32(cryptoprotect.PICK_ZUC) << 8
		c.StreamCipher = &cryptoprotect.ZUC{}
	}

	switch hash_cfg {
	case `sha256`:
		choice |= uint32(cryptoprotect.PICK_SHA256) << 16
		c.HashCipher = &cryptoprotect.Sha256{}
	case `sha3-256`:
		choice |= uint32(cryptoprotect.PICK_SHA3_256) << 16
		c.HashCipher = &cryptoprotect.Sha3_256{}
	case `blake2b256`:
		choice |= uint32(cryptoprotect.PICK_BLAKE2B256) << 16
		c.HashCipher = &cryptoprotect.Blake2b256{}
	case `blake2s256`:
		choice |= uint32(cryptoprotect.PICK_BLAKE2S256) << 16
		c.HashCipher = &cryptoprotect.Blake2s256{}
	case `sm3`:
		fallthrough
	default:
		choice |= uint32(cryptoprotect.PICK_SM3) << 16
		c.HashCipher = &cryptoprotect.SM3{}
	}

	switch zip_cfg {
	case `zlib`:
		choice |= uint32(cryptoprotect.PICK_ZLIB_COMP) << 24
		c.CompOption = &zipper.Zlib{}
	case `null`:
		fallthrough
	default:
		choice |= uint32(cryptoprotect.PICK_NULL_COMP) << 24
		c.CompOption = &zipper.IdCompress{}
	}
	/* payload:
	   choice token
	*/
	res := make([]byte, 4+len(access_token))
	copy(res[:4], utils.Uint32ToBytesInLittleEndian(choice))
	copy(res[4:], []byte(access_token))

	cnt, err := c.MiProxy.Write(res)
	if cnt != uint(len(res)) || err != nil {
		err = defErr.DescribeThenConcat(`payload-len-mismatch or err:`, err)
	}
	return err
}

// step 1 wait for PPUB
func (c *Client) readStep1() error {
	ppub, _, err := c.MiProxy.Read()
	if err != nil {
		c.wNeedBytes <- []byte{}
		c.MiProxy.CloseAll()
		return errors.New(protocol.FAILED_TO_RECV_COMP_PPUB)
	}
	dep, err := c.CompOption.DecompressMsg(ppub)
	if uint64(len(dep)) != c.AsymmCipher.GetPubLen() || err != nil {
		c.wNeedBytes <- []byte{}
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`ppub may be invalid or `, err)
	}
	c.wNeedBytes <- dep
	return nil
}

// step 1 ack PPUB
func (c *Client) writeStep1() error {
	ppub := <-c.wNeedBytes
	if uint64(len(ppub)) != c.AsymmCipher.GetPubLen() {
		c.MiProxy.CloseAll()
		return errors.New(protocol.INVALID_PPUB_LENGTH)
	}

	c.ProxyAsymmCipher.SetPub(ppub)
	time.Sleep(time.Microsecond * 500)

	now, res := protocol.AckToTimestampHash(c.HashCipher, []byte(protocol.ACKPPUB))
	// TODO: compress the ack-pub?
	cnt, err := c.MiProxy.Write(append(now, res...))
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(protocol.FAILED_TO_SEND_ACKPPUB, err)
	}
	return nil
}

// step 2 wait for ack CPUB
func (c *Client) readStep2() error {
	ackcpub, _, err := c.MiProxy.Read()
	if !protocol.AckFlowValidation(
		c.HashCipher, ackcpub, []byte(protocol.ACKCPUB),
		c.ackTimCheck, &c.ackRec, c.pingRef, false) {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`unexpected cut or err:`, err)
	}
	return nil
}

// step 2 send CPUB
func (c *Client) writeStep2() error {
	time.Sleep(time.Microsecond * 500)
	if err := c.sendPub(); err != nil {
		c.MiProxy.CloseAll()
		return err
	}
	return nil
}

// step3 send and wait for ack of cflow1 | cflow2
func (c *Client) writeStep3(cflow []byte, turn int) error {
	time.Sleep(time.Microsecond * 500)
	// TODO: time sensitive and can we use another way to fend off side-channel attack?
	cf, err := c.CompOption.CompressMsg(cflow)
	if err != nil {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(protocol.FAILED_TO_COMPRESS_CFLOW, err)
	}
	cnt, err := c.MiProxy.Write(cf)
	if err != nil || cnt != uint(len(cf)) {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(protocol.FAILED_TO_SEND_COMP_CFLOW, err)
	}
	cack := <-c.wNeedBytes
	var choice []byte
	switch turn {
	case 1:
		choice = []byte(protocol.ACKCPK1)
	case 2:
		choice = []byte(protocol.ACKCPK2)
	default:
		return errors.New(protocol.CLIENT_PREFIX + protocol.INTERLOCKING_TURN_INVALID_ACKCFLOW)
	}
	if !protocol.AckFlowValidation(c.HashCipher, cack, choice, c.ackTimCheck, &c.ackRec, c.pingRef, true) {
		c.MiProxy.CloseAll()
		return errors.New(protocol.FAILED_TO_PARSE_ACKCFLOW)
	}
	return nil
}

// step3 wait for ackcflow1 | ackcflow2
func (c *Client) readStep3() error {
	ackcpk, cnt, err := c.MiProxy.Read()
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		c.wNeedBytes <- []byte{}
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`client: ackcpk failed or err:`, err)
	}
	c.wNeedBytes <- ackcpk
	return nil
}

// step3 ack pflow1 | pflow2
func (c *Client) writeStep4(turn int) error {
	var choice []byte
	switch turn {
	case 1:
		choice = []byte(protocol.ACKPPK1)
	case 2:
		choice = []byte(protocol.ACKPPK2)
	default:
		return errors.New(protocol.CLIENT_PREFIX + protocol.INTERLOCKING_TURN_INVALID_ACKPFLOW)
	}
	// log.Println(`curr choice`, string(choice))
	if !<-c.rDoneSignal {
		c.MiProxy.CloseAll()
		return errors.New(`failed to recv ppack1 which is accessed from c.rSignal`)
	}
	now, res := protocol.AckToTimestampHash(c.HashCipher, choice)
	cnt, err := c.MiProxy.Write(append(now, res...))
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`incorrectly send ack-ppk`, err)
	}
	return nil
}

// step3 read pflow1 | pflow2
func (c *Client) readStep4() ([]byte, error) {
	pf, _, err := c.MiProxy.Read()
	if err != nil {
		c.rDoneSignal <- false
		c.MiProxy.CloseAll()
		return []byte{}, err
	}
	pflow, err := c.CompOption.DecompressMsg(pf)
	if err != nil {
		c.rDoneSignal <- false
		c.MiProxy.CloseAll()
		return []byte{}, err
	}
	c.rDoneSignal <- true
	return pflow, nil
}

func (c *Client) pflowConcatAndDecrypt(pflow1, pflow2 []byte) (*protocol.HandShakeMsg, error) {
	enc_flow := append(pflow1, pflow2...)
	flow, err := c.AsymmCipher.PemDecrypt(enc_flow)
	if err != nil {
		c.MiProxy.CloseAll()
		return nil, err
	}
	presessionkey, err := c.extractHandShakeMsg(flow)
	if err != nil {
		c.MiProxy.CloseAll()
		return nil, err
	}
	return presessionkey, nil
}

// step 9: verify sign and check hash
func (c *Client) recheckHash(presessionkey *protocol.HandShakeMsg) error {
	verified := c.ProxyAsymmCipher.PubVerify(presessionkey.Hasher[:], presessionkey.Signature[:])
	if !verified {
		c.MiProxy.CloseAll()
		return errors.New(protocol.FAILED_TO_VERIFY_SIGNATURE)
	}
	hashX := append(presessionkey.Kern[:], utils.Uint64ToBytesInLittleEndian(presessionkey.Nonce)...)
	hashX = append(hashX, presessionkey.Timestamp...)

	recheck_hash := c.HashCipher.CalculateHash(hashX)
	status, descript := utils.CompareByteSliceEqualOrNot(recheck_hash[:], presessionkey.Hasher[:])
	if !status {
		c.MiProxy.CloseAll()
		return errors.New("HashError :=" + descript)
	}
	return nil
}

// step 10: generate sessionKey and wait for rn
func (c *Client) readChallenge(presessionkey *protocol.HandShakeMsg) error {
	rn := c.rn
	tmpKey := protocol.GenerateSessionKey(
		[cryptoprotect.KeySize]byte(presessionkey.Kern[:cryptoprotect.KeySize]),
		rn.Kern,
		rn.Nonce,
		presessionkey.Nonce,
		c.HashCipher,
	)
	c.StreamCipher.SetKey(tmpKey[:])
	c.StreamCipher.SetIv(presessionkey.Kern[cryptoprotect.KeySize : cryptoprotect.KeySize+cryptoprotect.IVSize])
	resp_rn, _, err := c.DecRead()
	status, descript := utils.CompareByteSliceEqualOrNot(resp_rn, rn.Kern[:])
	if !status {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`fake rn sent by proxy. Abort connection due to `+descript, err)
	}
	return nil
}

func (c *Client) writeFinish() error {
	curr, res := protocol.AckToTimestampHash(c.HashCipher, []byte(protocol.HANDHLT))
	cnt, err := c.EncWrite(append(curr, res...))
	if uint64(cnt) != protocol.TIME_LEN.SafeReadTimeLen()+4 || err != nil {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`failed to send finish or err:`, err)
	}
	return nil
}

// step 12 read finish
func (c *Client) readFinish() error {
	_finish, _, err := c.DecRead()
	if !protocol.AckFlowValidation(
		c.HashCipher, _finish,
		[]byte(protocol.HANDHLT),
		c.ackTimCheck, &c.ackRec, c.pingRef, false) || err != nil {
		c.MiProxy.CloseAll()
		return defErr.DescribeThenConcat(`fake fin or err:`, err)
	}
	return nil
}

func (c *Client) shakeHandReadCoroutine() (rerr error) {
	if !<-c.wNotifiedSignal {
		rerr = errors.New(`quit for client-hello failure`)
		return
	}

	rerr = c.readStep1()
	if rerr != nil {
		return
	}
	// log.Println(`ppub has recv`)
	rerr = c.readStep2()
	if rerr != nil {
		return
	}
	// log.Println(`ackcpub has recv`)
	rerr = c.readStep3( /* 1 read ackcflow1 */ )
	if rerr != nil {
		return
	}
	// log.Println(`ackcflow1 has recv`)
	pflow1, rerr := c.readStep4() // read pflow1
	if rerr != nil {
		return
	}
	// log.Println(`pflow1 has recv`)
	rerr = c.readStep3( /*2 read ackcflow2 */ )
	if rerr != nil {
		return
	}
	// log.Println(`ackcflow2 has recv`)
	pflow2, rerr := c.readStep4() // read pflow2
	if rerr != nil {
		return
	}
	// log.Println(`pflow2 has recv`)
	presessionkey, rerr := c.pflowConcatAndDecrypt(pflow1, pflow2)
	if rerr != nil {
		c.wNotifiedSignal <- false
		return
	}
	// log.Println(`presessionkey has dec`)
	rerr = c.recheckHash(presessionkey)
	if rerr != nil {
		c.wNotifiedSignal <- false
		return
	}
	// log.Println(`presession-hash has dec`)
	rerr = c.readChallenge(presessionkey)
	if rerr != nil {
		c.wNotifiedSignal <- false
		return
	}
	c.wNotifiedSignal <- true
	rerr = c.readFinish()
	return
}

func (c *Client) shakeHandWriteCoroutine() (werr error) {
	/* todo:  token and the related configuration read via config.go */
	werr = c.SendClientHelloPayload(`sm2`, `sm4-ctr-256`, `blake2s256`, `hello world, bed`, `zlib`)
	if werr != nil {
		c.wNotifiedSignal <- false
		c.MiProxy.CloseAll()
		return
	}
	c.wNotifiedSignal <- true
	time.Sleep(time.Millisecond)
	werr = c.writeStep1()
	if werr != nil {
		return
	}
	// log.Println(`ackppub has sent`)
	werr = c.writeStep2()
	if werr != nil {
		return
	}
	// log.Println(`cpub has sent`)
	c.rn, werr = c.generateRN()
	if werr != nil {
		c.MiProxy.CloseAll()
		return
	}
	enc_rn, err := c.pPubEncryptHandShakeMsg(c.rn)
	if err != nil {
		c.MiProxy.CloseAll()
		return
	}
	flow1, flow2 := utils.BytesSpliterInHalfChanceField(enc_rn)
	werr = c.writeStep3(flow1, 1) // send cflow1
	if werr != nil {
		return
	}
	// log.Println(`cflow1 has sent`)
	werr = c.writeStep4(1) // ack pflow1
	if werr != nil {
		return
	}
	// log.Println(`ackppk1 has sent`)
	werr = c.writeStep3(flow2, 2) // send cflow2
	if werr != nil {
		return
	}
	// log.Println(`cflow2 has sent`)
	werr = c.writeStep4(2) // ack pflow2
	if werr != nil {
		return
	}
	// log.Println(`ackppk2 has sent`)
	if jud := <-c.wNotifiedSignal; !jud {
		werr = errors.New(`handshake failed in the middle knowing from reader coroutine`)
		return
	}
	werr = c.writeFinish()
	return
}

func (c *Client) clientAddrSpliter() (string, string) {
	domain := c.MiProxy.Conn.RemoteAddr().String()
	pos := 0
	for i := len(domain) - 1; i > 0; i-- {
		if domain[i] == ':' {
			pos = i
			break
		}
	}
	return domain[:pos], domain[pos:]
}

func (c *Client) Shakehand() (werr error, rerr error) {
	ip, _ := c.clientAddrSpliter()
	ping_ref, ok := service.PingWithoutPrint(ip, 3, 5, 5)
	if !ok {
		log.Println(protocol.CLIENT_PREFIX + protocol.FAILED_TO_PING_AND_MEASURE)
		werr = errors.New(protocol.FAILED_TO_PING_AND_MEASURE)
		rerr = errors.New(protocol.FAILED_TO_PING_AND_MEASURE)
		return
	}
	c.pingRef = ping_ref
	functor := func() { c.ackTimCheck, c.ackRec = new([8][]byte), 0 }
	wch, rch := make(chan error), make(chan error)
	functor()
	defer functor()
	defer close(wch)
	defer close(rch)
	go func() { rch <- c.shakeHandReadCoroutine() }()
	go func() { wch <- c.shakeHandWriteCoroutine() }()
	werr, rerr = <-wch, <-rch
	return
}
