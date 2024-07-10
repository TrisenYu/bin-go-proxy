// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"

	cryptoprotect "selfproxy/cryptoProtect"
	utils "selfproxy/utils"
)

const (
	/* Ten thousand year with the same format as long as all systems are ongoing. */
	TIME_FORMAT      string = "2006-01-02 15:04:05.000000"
	TIME_ZONE_STRING string = "Asia/Shanghai"

	/*
		Do not send the plaintext but send the injective result generated from hash(ack+timesalt).
		The ack datafield can be configured manually for better replay-attack resistance, but the corresponding
		modification should be correctly passed to client.
	*/
	/* shakehand: stage 1. */
	ACKCPUB string = `ACK-CPUB` // Proxy ack cpub
	ACKPPUB string = `ACK-PPUB` // Client ack ppub
	/* shakehand: stage 2 */
	ACKPPK1 string = `ACK-PPK1` // Client ack ppk1
	ACKPPK2 string = `ACK-PPK2` // Client ack ppk2
	ACKCPK1 string = `ACK-CPK1` // Proxy ack cpk1
	ACKCPK2 string = `ACK-CPK2` // Proxy ack cpk2
	/* shakehand: stage 3 */
	HANDHLT string = `FINISHED` // Client ack p-rn | proxy recv c-ack-p-rn
)

type (
	SharedTimeFormat struct {
		timeLen, yearLen uint64
		mutter, yummy    sync.RWMutex
	}

	ShakeHandMsg struct {
		Kern      [cryptoprotect.KeySize + cryptoprotect.IVSize]byte // login-proxy: key-iv client <- rn  48 bytes
		Nonce     uint64                                             // random-nonce                       8 bytes
		Hasher    [cryptoprotect.HashSize]byte                       // hash of concat(kern, nonce)       32 bytes
		Signature [cryptoprotect.SignSize]byte                       // signature of hash                 64 bytes
		Timestamp []byte                                             // timestamp
	}
)

// Regularly update TIME_LEN.

var (
	calibrated_time_accesser = func() string { return time.Now().In(TIME_ZONE).Format(TIME_FORMAT) }
	TIME_ZONE, _             = time.LoadLocation(TIME_ZONE_STRING)
	TIME_LEN                 = SharedTimeFormat{
		timeLen: uint64(len(calibrated_time_accesser())),
		yearLen: uint64(len(time.Now().In(TIME_ZONE).Format(`2006`))),
	}
)

// safely gain current length of timestamp.
func (t *SharedTimeFormat) SafeReadTimeLen() uint64 {
	var res uint64
	t.mutter.RLock()
	res = t.timeLen
	t.mutter.RUnlock()
	return res
}

// safely gain current length of year in timestamp.
func (t *SharedTimeFormat) SafeReadYearLen() uint64 {
	var res uint64
	t.yummy.RLock()
	res = t.yearLen
	t.yummy.RUnlock()
	return res
}

func (t *SharedTimeFormat) SafeResetLen() string {
	res := calibrated_time_accesser()
	t.mutter.Lock()
	t.timeLen = uint64(len(res))
	t.mutter.Unlock()

	t.yummy.Lock()
	t.yearLen = uint64(len(time.Now().Format(`2006`)))
	t.yummy.Unlock()
	return res
}

var sbox = [...]byte{
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
}

/*
	+----+----+----+----+----+----+----+----+
	|c   |p   |c   |p   |c   |p   |c   |p   |
	+----+----+----+----+----+----+----+----+
*/
// xor pressionkey with blowfish_sbox => hash as key
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
		key[i] = (key[i] + sbox[key[i]] + sbox[key[(i-1+keySize)%keySize]]) & 0xFF
	}
	return [32]byte(hash_obj.CalculateHash(key))
}

func GenerateRandUint64WithByteRepresentation() (uint64, []byte, error) {
	nonce := make([]byte, 8)
	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return 0, []byte(``), err
	}
	var nonceIn64 uint64 = 0
	for i := 0; i < 8; i++ {
		nonceIn64 |= uint64(nonce[i]) << (i << 3)
	}
	return nonceIn64, nonce, nil
}

// hash(timestamp + ack)[:4] => send with timestamp as current ack
func AckToTimestampHash(hash_fn cryptoprotect.HashCipher, ack_payload []byte) (time_salt []byte, res []byte) {
	time_salt = []byte(calibrated_time_accesser())
	_res := hash_fn.CalculateHash(append(time_salt, ack_payload...))
	res = _res[:4]
	return
}

func hasSaved(checkTime, stage_ack []byte, tmpTimeStamps *[8][]byte, rec_cnt *int) bool {
	flag1, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(ACKCPUB))
	flag2, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(ACKPPUB))
	flag3, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(HANDHLT))

	if flag1 || flag2 {
		*rec_cnt = 0
		now := []byte(calibrated_time_accesser())
		TimeStampMinus(now, checkTime)
		tmpTimeStamps[0] = now[:]
		*rec_cnt += 1
		return false
	}

	for idx := 0; idx < *rec_cnt; idx++ {
		innerFlag, _ := utils.CompareByteSliceEqualOrNot(tmpTimeStamps[idx][:], checkTime[:])
		if innerFlag || !TimeStampCmp(checkTime, tmpTimeStamps[idx]) {
			/* check whether the timestamp has existed or not And
			   whether the timestamp violates the monotonically increasing order and
			   attempts to cause a birthday problem.
			*/
			return true
		}
	}

	// TODO: the interval between two timestamps should be accepted in 1~1.5 TTL(public network) or 0~1 TTL(localhost).
	TimeStampMinus(checkTime, tmpTimeStamps[*rec_cnt-1])
	tmpTimeStamps[*rec_cnt] = checkTime
	*rec_cnt += 1
	if flag3 {
		*tmpTimeStamps = [8][]byte{}
		*rec_cnt = 0
	}
	return false
}

// validate if ack is up to standard by semantic consistency
func AckFlowValidation(
	hash_fn cryptoprotect.HashCipher,
	ack_flow []byte,
	stage_ack []byte,
	tmpTimeStamps *[8][]byte,
	rec_cnt *int,
) bool {
	time_len := TIME_LEN.SafeReadTimeLen()
	if uint64(len(ack_flow)) != time_len+4 {
		return false
	}
	time_salt := make([]byte, time_len+8)
	copy(time_salt[:time_len], ack_flow[:time_len])
	if hasSaved(time_salt[:time_len], stage_ack, tmpTimeStamps, rec_cnt) {
		return false
	}
	trunc_it := ack_flow[time_len : time_len+4]
	copy(time_salt[time_len:time_len+8], stage_ack)
	check_it := hash_fn.CalculateHash(time_salt)
	flag, _ := utils.CompareByteSliceEqualOrNot(check_it[:4], trunc_it)
	return flag
}

/*
input must be standard timestamp, which is shown below.

	xxxxx-02-02 23:59:59.233333333
	0    ^   4  7  a  d  0       9
	     |               1       1
	  yearlen

the way for turning it into bigInt is to sub each byte with 48 and remove space,dash,colon and point

	xxxxx0202235959233333333

TODO:
*/
func TimeStampToBigInt(input []byte) *big.Int {
	year_len := TIME_LEN.SafeReadYearLen()
	inp := make([]byte, year_len+25 /* magic 25 */)
	copy(inp[:], input[:])
	var (
		mon_st  uint64                       = year_len + 0x1
		day_st  uint64                       = year_len + 0x4
		our_st  uint64                       = year_len + 0x7
		min_st  uint64                       = year_len + 0xa
		sec_st  uint64                       = year_len + 0xd
		mil_st  uint64                       = year_len + 0x10
		minus48 func([]byte, uint64, uint64) = func(i []byte, l, r uint64) {
			for idx := l; idx < r; idx++ {
				i[idx] -= 48
			}
		}
	)

	minus48(inp, 0, year_len)      // year
	minus48(inp, mon_st, mon_st+2) // mon
	minus48(inp, day_st, day_st+2) // day
	minus48(inp, our_st, our_st+2) // hour
	minus48(inp, min_st, min_st+2) // minn
	minus48(inp, sec_st, sec_st+2) // sec
	minus48(inp, mil_st, mil_st+9) // milli micro nano sec

	resizer := make([]byte, year_len+19)
	copy(resizer[:year_len], inp[:year_len]) // year
	copy(resizer[year_len:year_len+2], inp[mon_st:mon_st+2])
	copy(resizer[year_len+2:year_len+4], inp[day_st:day_st+2])
	copy(resizer[year_len+4:year_len+6], inp[our_st:our_st+2])
	copy(resizer[year_len+6:year_len+8], inp[min_st:min_st+2])
	copy(resizer[year_len+8:year_len+10], inp[sec_st:sec_st+2])
	copy(resizer[year_len+10:year_len+19], inp[mil_st:mil_st+9])
	tmp := new(big.Int)
	return tmp.SetBytes(resizer[:year_len+19])
}

func TimeStampCmp(inp1, inp2 []byte) bool {
	val1, val2 := TimeStampToBigInt(inp1), TimeStampToBigInt(inp2)
	res := val1.Cmp(val2)
	return res > 0
}

func TimeStampMinus(inp_maxn, inp_minn []byte) {
	val1, val2 := TimeStampToBigInt(inp_maxn), TimeStampToBigInt(inp_minn)
	tmp := new(big.Int)
	// 30_0000 * 1000 m / s * 0.191 s = 57300 => 28650 km
	// (ping from China to Argentina and receive response from Agentina to China)
	/*
		Assuming that the existing(2024) data link does not pass through satellites
		but uses optical fibers or transoceanic cables.

		For the communicating parties, an intermediary would only be able to successfully deceive both parties
		And continuously eavesdrop on the communication content if he/she effectively utilizes this communication protocol
		And is geographically very close to either party.

		However, no matter what, relying on ping operations to measure communication time
		In order to determine if the parties are under a man-in-the-middle attack
		is likely to be less effective than a specially trained AI prediction.

		Technically we should collect the historical ping data and combine the network conditions
		(like degree of congestion, changing topology) to determine. But all of this are laborious.

		To effectively cope with this, I drew inspiration from `closed-loop control`.

			Output_of_Controller = Kp( err(t) + T_i^{-1} Integrate err(t) dt + T_d d(err(t)) / dt )

		the discrete form of RHS is ~ Kp(err[t] + T_i^{-1} (t-0)sum_{x=0}^{t}err[x] + T_d (err[t]-err[t-1])/△t )
	*/
	sub := tmp.Sub(val1, val2).Bytes()
	utils.BytesHexForm(sub)
}
