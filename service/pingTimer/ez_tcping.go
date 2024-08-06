//go:build linux
// +build linux

package service

// ACKNOWLEDGE: https://leandrofroes.github.io/posts/An-in-depth-look-at-Golang-Windows-calls/
// 				https://www.lnsec.cn/archives/53/

import (
	"errors"
	"log"
	"sync"
	"syscall"
	"time"

	"bingoproxy/defErr"
	utils "bingoproxy/utils"
)

func measureTime(
	remoteSlice []byte,
	localFd /* read-only */ int,
) (time.Time, error) {
	var (
		res        time.Time
		failed_cnt int = 0
	)
	buf := make([]byte, 1600)
retry:
	cnt, address, err := syscall.Recvfrom(localFd, buf, 0)

	if failed_cnt > 3 || err != nil {
		return time.Time{}, defErr.StrConcat(`ran out of retry-cnt or triggered an err: `, err)
	}

	switch now := address.(type) {
	case *syscall.SockaddrInet4:
		f, _ := utils.CmpByte2Slices((*now).Addr[:], remoteSlice)
		if !f {
			failed_cnt += 1
			goto retry
		}
	case *syscall.SockaddrInet6:
		f, _ := utils.CmpByte2Slices((*now).Addr[:], remoteSlice)
		if !f {
			failed_cnt += 1
			goto retry
		}
	default:
		failed_cnt += 1
		goto retry
	}
	res = time.Now()
	parser := NewTCPHeader(buf[:cnt])
	if parser.HasFlag(TCP_RST) { /* TODO: provide the callback function to judge the logic. */
		goto end
	}
	goto retry
end:
	return res, nil
}

/*
a FIN packet(more invisible than the SYN Scan):
  - to a closed port => get a RST back.
  - no response      =>  either dropped by the firewall or the port is open.

Since we want to control the process of handshake for measuring RTT, we have to use raw socket provided by OS.

However, many system always return RST, which leads to the impossibility to know if a port is open or closed,
For instance: __Windows__ does this but not UNIX.

But Assume our clients are granted the authority to control the port rather than always sending rst.

**Address passing to current function should be in the shape of `ip:port`.**
if any parameter violates against the role, throw an error and return -1 as corresponding RTT.
*/
func TCPPing(remoteAddr, localAddr string) (int64, error) {
	var sport, dport uint16

	remoteSlice, dport, posr, err := utils.SplitAddrSlicePortUint16(remoteAddr)
	if err != nil {
		log.Println(len(remoteSlice), dport, err)
		return -1, err
	}
	localSlice, sport, posl, err := utils.SplitAddrSlicePortUint16(localAddr)
	if err != nil {
		log.Println(len(localSlice), sport, err)
		return -1, err
	}
	_t, err := utils.CheckIpType(remoteAddr[:posr])
	if err != nil {
		return -1, err
	}
	_t1, err := utils.CheckIpType(localAddr[:posl])
	if err != nil {
		return -1, err
	}
	remote_type, local_type := int(_t), int(_t1)
	var (
		fd, choice                  int
		localAddress, remoteAddress syscall.Sockaddr
	)
	fn1 := func(t, port int, inp []byte, ptr *syscall.Sockaddr) {
		switch t {
		case 4:
			*ptr = &syscall.SockaddrInet4{
				Addr: [4]byte(inp[len(inp)-4:]),
				Port: port,
			}
		case 6:
			*ptr = &syscall.SockaddrInet6{
				Addr: [16]byte(inp),
				Port: port,
			}
		default:
			*ptr = nil
		}
	}
	fn2 := func(ptr syscall.Sockaddr) error {
		switch now := ptr.(type) {
		case *syscall.SockaddrInet4:
			return syscall.Bind(fd, now)
		case *syscall.SockaddrInet6:
			return syscall.Bind(fd, now)
		default:
			return errors.New(`invalid type`)
		}
	}
	fn1(local_type, int(sport), localSlice, &localAddress)
	fn1(remote_type, int(dport), remoteSlice, &remoteAddress)
	if local_type == 4 {
		choice = syscall.AF_INET
	} else if local_type == 6 {
		choice = syscall.AF_INET6
	}
	// bullshit windows. WE CAN NOT DIRECTLY CONTROL RAW SOCKET NOW!
	fd, err = syscall.Socket(choice, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(fd)
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1600*20)
	if err != nil {
		log.Println(err)
		return -1, err
	}
	// TOFIX: syscall.Bind

	if err = fn2(localAddress); err != nil {
		return -1, err
	}
	log.Println(`bind done`)
	var st, ed time.Time

	// TODO: other probing schedule...
	packet := SetTcpHeader(
		localSlice,
		remoteSlice,
		sport,
		dport,
		TCP_FIN)

	var (
		wg    sync.WaitGroup
		cherr chan error
	)
	wg.Add(1)
	go func() {
		_ed, _err := measureTime(remoteSlice, fd)
		ed = _ed
		cherr <- _err
		close(cherr)
		wg.Done()
	}()
	st = time.Now()
	if err = syscall.Sendto(fd, packet, 0, remoteAddress); err != nil {
		log.Println(`failed...`, err)
		return -1, err
	}
	if err = <-cherr; err != nil {
		log.Println(`failed...`, err)
		return -1, err
	}
	// receive rst | ack or rst
	return ed.Sub(st).Microseconds(), nil
}

func init() {
	log.SetFlags(log.Lshortfile | log.Lmicroseconds)
}
