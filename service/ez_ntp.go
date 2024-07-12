// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
// ACKNOWLEDGEMENT: ksmeow.moe/ntp/
// _                github.com/vladimirvivien/go-ntp-client/blob/master/time.go
package service

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

const ntpEpochOffset = 2208988800

// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Delay                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Dispersion                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Reference ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                     Reference Timestamp (64)                  +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Origin Timestamp (64)                    +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Receive Timestamp (64)                   +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Transmit Timestamp (64)                  +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

var ntp_server_list = [...]string{
	"time.windows.com:123",
	"time.apple.com:123",
	"time.cloudflare.com:123",
	"time.nist.gov:123",
	"pool.ntp.org:123",
	"us.pool.ntp.org:123",
	"ntp.ntsc.ac.cn:123",
	"cn.pool.ntp.org:123",
	"stdtime.gov.hk:123",
	"ntp.tencent.com:123",
	"ntp.aliyun.com:123",
}

type ntp_pack struct {
	Settings       uint8  // leap yr indicator, ver number, and mode
	Stratum        uint8  // stratum of local clock
	Poll           int8   // poll exponent
	Precision      int8   // precision exponent
	RootDelay      uint32 // root delay
	RootDispersion uint32 // root dispersion
	ReferenceID    uint32 // reference id
	RefTimeSec     uint32 // reference timestamp sec
	RefTimeFrac    uint32 // reference timestamp fractional
	OrigTimeSec    uint32 // origin time secs
	OrigTimeFrac   uint32 // origin time fractional
	RxTimeSec      uint32 // receive time secs
	RxTimeFrac     uint32 // receive time frac
	TxTimeSec      uint32 // transmit time secs
	TxTimeFrac     uint32 // transmit time frac
}

// 00 011 011 (or 0x1B)
// |  |   +-- client mode (3)
// |  + ----- version (3)
// + -------- leap year indicator, 0 no warning

func AccessCurrTime(idx int) (time.Time, error) {
	var res time.Time
	if idx >= len(ntp_server_list) {
		idx = 6
	}
	conn, err := net.Dial("udp", ntp_server_list[idx])
	if err != nil {
		return res, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return res, err
	}
	req := &ntp_pack{Settings: 0x1B}
	if err = binary.Write(conn, binary.BigEndian, req); err != nil {
		return res, err
	}
	rsp := &ntp_pack{}
	if err = binary.Read(conn, binary.BigEndian, rsp); err != nil {
		return time.Time{}, err
	}
	secs := float64(rsp.TxTimeSec) - ntpEpochOffset
	nanos := (int64(rsp.TxTimeFrac) * 1e9) >> 32 // convert fractional to nanos
	res = time.Unix(int64(secs), nanos)
	log.Println(res)
	return res, nil
}
