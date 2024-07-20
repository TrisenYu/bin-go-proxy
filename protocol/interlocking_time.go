package protocol

import (
	"log"
	"math/big"
	"sync"
	"time"

	cryptoprotect "bingoproxy/cryptoProtect"
	utils "bingoproxy/utils"
)

const (
	/* Ten thousand year with the same format as long as all systems are ongoing. */
	TIME_FORMAT                 string = "2006-01-02 15:04:05.000000"
	TIME_ZONE_STRING            string = "Asia/Shanghai"
	CHOPPING_LENGTH_OF_HASH_VAL uint64 = 8

	/*
		Do not send the plaintext but send the injective result generated from hash(ack+timesalt).
		The ack datafield can be configured manually for better replay-attack resistance, but the corresponding
		modification should be correctly passed to client.
	*/
	/* handshake: stage 1. */
	ACKCPUB string = `ACK-CPUB` // Proxy ack cpub
	ACKPPUB string = `ACK-PPUB` // Client ack ppub
	/* handshake: stage 2 */
	ACKPPK1 string = `ACK-PPK1` // Client ack ppk1
	ACKPPK2 string = `ACK-PPK2` // Client ack ppk2
	ACKCPK1 string = `ACK-CPK1` // Proxy ack cpk1
	ACKCPK2 string = `ACK-CPK2` // Proxy ack cpk2
	/* handshake: stage 3 */
	HANDHLT string = `FINISHED` // Client ack p-rn | proxy recv c-ack-p-rn
)

type SharedTimeFormat struct {
	timeLen, yearLen uint64
	mutter, yummy    sync.RWMutex
}

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

func (t *SharedTimeFormat) SafeSetTimeFromTimeStamp(inp time.Time) {
	t.yummy.Lock()
	t.yearLen = uint64(len(inp.Format(`2006`)))
	t.yummy.Unlock()

	t.mutter.Lock()
	t.timeLen = uint64(len(inp.Format(TIME_FORMAT)))
	t.mutter.Unlock()
}

// hash(timestamp + ack)[:CHOPPING_LENGTH_OF_HASH_VAL] => send with timestamp as current ack
func AckToTimestampHash(hash_fn cryptoprotect.HashCipher, ack_payload []byte) (time_salt []byte, res []byte) {
	time_salt = []byte(calibrated_time_accesser())
	_res := hash_fn.CalculateHash(append(time_salt, ack_payload...))
	res = _res[:CHOPPING_LENGTH_OF_HASH_VAL]
	return
}

func hasSaved(
	checkTime, stage_ack []byte,
	tmpTimeStamps *[8][]byte,
	rec_cnt *int,
	ping_val int64,
	hasCryptoBurden bool,
) bool {
	flag1, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(ACKCPUB))
	flag2, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(ACKPPUB))
	flag3, _ := utils.CompareByteSliceEqualOrNot(stage_ack, []byte(HANDHLT))

	if flag1 || flag2 {
		*rec_cnt = 0
		now := []byte(calibrated_time_accesser())
		// It is better to check the ACKCPUB / ACKPPUB received time here. But in localhost it is relatively sophicated to control.
		// TimeStampMinus(now, checkTime)
		tmpTimeStamps[0] = now[:]
		*rec_cnt += 1
		return false
	}
	var upper_bound, lower_bound int64
	if hasCryptoBurden {
		upper_bound = ping_val*5/2 + (ping_val % 1000)
		lower_bound = ping_val/2 - (ping_val % 1000)
	} else {
		upper_bound = ping_val*3/2 + (ping_val % 1000)
		lower_bound = ping_val/2 + (ping_val % 1000)
	}
	for idx := 0; idx < *rec_cnt; idx++ {
		innerFlag, _ := utils.CompareByteSliceEqualOrNot(tmpTimeStamps[idx][:], checkTime[:])
		if innerFlag || !TimeStampCmp(checkTime, tmpTimeStamps[idx]) {
			/*
			   check whether the timestamp has existed or not And
			   whether the timestamp violates the monotonically increasing order and
			   attempts to cause a birthday problem.
			*/
			return true
		}
	}

	jiffy := TimeStampMinus(checkTime, tmpTimeStamps[*rec_cnt-1])

	if jiffy < lower_bound || jiffy > upper_bound {
		log.Println(`suspection: man in the middle attack`, jiffy, ping_val, lower_bound, upper_bound)
		return true
	}
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
	ping_val int64,
	hasCryptoBurden bool,
) bool {
	time_len := TIME_LEN.SafeReadTimeLen()
	if uint64(len(ack_flow)) != time_len+CHOPPING_LENGTH_OF_HASH_VAL {
		return false
	}
	time_salt := make([]byte, time_len+8)
	copy(time_salt[:time_len], ack_flow[:time_len])
	if hasSaved(time_salt[:time_len], stage_ack, tmpTimeStamps, rec_cnt, ping_val, hasCryptoBurden) {
		return false
	}
	trunc_it := ack_flow[time_len : time_len+CHOPPING_LENGTH_OF_HASH_VAL]
	copy(time_salt[time_len:time_len+8], stage_ack)
	check_it := hash_fn.CalculateHash(time_salt)
	flag, _ := utils.CompareByteSliceEqualOrNot(check_it[:CHOPPING_LENGTH_OF_HASH_VAL], trunc_it)
	return flag
}

/*
input must be standard timestamp, which is shown below.

	xxxxx-02-02 23:59:59.2333333333
	0    ^   4  7  a  d  0 23 56  9
	     |               1        1
	  yearlen

the way for turning it into bigInt is to sub each byte with 48 and remove space,dash,colon and point

	xxxxx0202235959233333333
*/
func TimeStampToBigInt(input []byte) *big.Int {
	year_len := TIME_LEN.SafeReadYearLen()
	inp := make([]byte, year_len+25 /* magic 25 */)
	copy(inp[:], input[:])
	var (
		mon_st uint64 = year_len + 0x1
		day_st uint64 = year_len + 0x4
		our_st uint64 = year_len + 0x7
		min_st uint64 = year_len + 0xa
		sec_st uint64 = year_len + 0xd
		mil_st uint64 = year_len + 0x10
	)

	resizer := make([]byte, year_len+19)
	copy(resizer[:year_len], inp[:year_len])
	copy(resizer[year_len:year_len+2], inp[mon_st:mon_st+2])
	copy(resizer[year_len+2:year_len+4], inp[day_st:day_st+2])
	copy(resizer[year_len+4:year_len+6], inp[our_st:our_st+2])
	copy(resizer[year_len+6:year_len+8], inp[min_st:min_st+2])
	copy(resizer[year_len+8:year_len+10], inp[sec_st:sec_st+2])
	copy(resizer[year_len+10:year_len+19], inp[mil_st:mil_st+9])
	tmp := new(big.Int)
	res, _ := tmp.SetString(string(resizer[:year_len+16]), 10)
	return res
	// the nano-second measured is not precise now. maybe we can omit it.
}

func TimeStampCmp(inp1, inp2 []byte) bool {
	val1, val2 := TimeStampToBigInt(inp1), TimeStampToBigInt(inp2)
	res := val1.Cmp(val2)
	return res > 0
}

/*
(ping from China to Argentina and receive response from Agentina to China)
30_0000 * 1000 m / s * 0.191 s = 57300 => 28650 km

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

the discrete form of RHS is ~

	Kp(err[t] + T_i^{-1} (t-0)sum_{x=0}^{t}err[x] + T_d (err[t]-err[t-1])/△t )
*/

// return jiffy(us).
func TimeStampMinus(inp_maxn, inp_minn []byte) int64 {
	out, _ := time.Parse(TIME_FORMAT, string(inp_maxn))
	out1, _ := time.Parse(TIME_FORMAT, string(inp_minn))
	res_us := time.Duration(out.Sub(out1)).Microseconds()
	return res_us
}
