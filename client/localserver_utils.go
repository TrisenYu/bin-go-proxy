package client

import (
	"net"

	interceptor "selfproxy/Interceptor"
)

func InitToProxy() error {
	// TODO
	return nil
}

func SetInterceptor() {
	tmp_interceptor, err := interceptor.GainInterceptor()
	if err != nil {
		panic(err)
	}
	LocalInterceptor = tmp_interceptor
}

func HandleLocalConn(conn net.Conn) {
	// TODO
}

func InterceptorLoop() {
	for !JudExitFlag.SafeReadState() {
		conn, err := LocalInterceptor.Accept()
		if err != nil {
			continue
		}
		go HandleLocalConn(conn)
	}
	ExitInterceptor()
}

func ExitInterceptor() {
}
