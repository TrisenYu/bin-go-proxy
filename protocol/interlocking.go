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

// 两 4 字节随机数合计 8 字节。按如下方式从低组别往高组别异或 32 字节 pressionkey 中的 8 组首字节。
/*
	+----+----+----+----+----+----+----+----+
	|c   |p   |c   |p   |c   |p   |c   |p   |
	+----+----+----+----+----+----+----+----+
*/
// 随后需要重整化 rn 并进一步混淆 pressionkey
func GenerateSessionKey(prekey [32]byte, rn [48]byte, cnonce, pnonce uint64) [32]byte {
	key := make([]byte, 32)
	for i := 0; i < 32; i += 4 {
		shift, flag := i/4, i/8
		if flag&1 == 1 {
			key[i] = prekey[i] ^ byte(pnonce>>uint64(shift<<3))
		} else {
			key[i] = prekey[i] ^ byte(cnonce>>uint64(shift<<3))
		}
	}
	var (
		renormalizer = func(b byte) uint16 {
			switch b {
			case 0:
				return 0x119
			case 0xFF:
				return 0x125
			default:
				return uint16(b)
			}
		}
		curr = renormalizer(rn[0])
	)
	for i := 1; i < 48; i++ {
		fetch := renormalizer(rn[i])
		curr_res := uint32(curr) * uint32(fetch)

		ll := uint8(curr_res & 0xFF)
		lh := uint8((curr_res >> 8) & 0xFF)
		hl := uint8((curr_res >> 16) & 0xFF)
		mixup := ll ^ hl ^ lh

		curr = uint16(uint8(fetch&0xFF) ^ uint8((fetch>>8)&0xFF) ^ mixup)
		key[i%32] = byte((uint16(key[i%32]) + uint16(mixup)) % 0x100)
	}
	return [32]byte(key)
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
	flag1, _ := utils.CompareByteArrEQ(stage_ack, []byte(ACKCPUB))
	flag2, _ := utils.CompareByteArrEQ(stage_ack, []byte(ACKPPUB))
	flag3, _ := utils.CompareByteArrEQ(stage_ack, []byte(HANDHLT))

	if flag1 || flag2 {
		*rec_cnt = 0
		now := []byte(calibrated_time_accesser())
		TimeStampMinus(now, checkTime)
		tmpTimeStamps[0] = now[:]
		*rec_cnt += 1
		return false
	}

	for idx := 0; idx < *rec_cnt; idx++ {
		innerFlag, _ := utils.CompareByteArrEQ(tmpTimeStamps[idx][:], checkTime[:])
		if innerFlag || !TimeStampCmp(checkTime, tmpTimeStamps[idx]) {
			/* check whether the timestamp has existed or not And
			   whether the timestamp violates the monotonically increasing order */
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
	flag, _ := utils.CompareByteArrEQ(check_it[:4], trunc_it)
	return flag
}

/*
约定：入参 input 一定是时间戳

	xxxxx-02-02 23:59:59.233333333
	0    ^   4  7  a  d  0       9
		 |               1       1
		yearlen

除去空格、间隔符`-`、冒号、小数点所占的 6 位，还有：

	xxxxx0202235959233333333
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
	// TODO: 实现相差判断。超出某个值的就不接受。
	utils.BytesHexForm(tmp.Sub(val1, val2).Bytes())
}
