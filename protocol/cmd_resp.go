package protocol

/* 指定由客户端来控制代理端访问自身想访问的网络地址。代理端提供访问反馈或者数据报文。 */

const (
	CMD_PAYLOAD_LEN  uint  = 24
	CMD_RPORT_ED     uint  = 2 + CMD_PAYLOAD_LEN
	CMD_ADDR_ED      uint  = 2 + CMD_RPORT_ED
	PROTOCOL_VERSION uint8 = 0xCA
	/* 24 字节 */
	CMD_refresh_sessionkey string = `REFRESH-CURR-SESSION-KEY` // 切换 sessionkey
	CMD_disconnect_with_ep string = `CLIENT-DISCONNECT-HOPING` // 停止通信
	CMD_alter_aloof_server string = `NEED-ALTER-REMOTE-SERVER` // 切换 remote server
	CMD_client_ready4_dual string = `CLIENT-IS-READY-FOR-DUAL` // 客户已经准备好通信
	/* 16 字节。*/
	RESP_recv_server_addrp string = `SERVER-IS-RECVED` // 第一次认可通信值
	RESP_fail2_conn2server string = `SERVER-DIAL-FAIL` // 服务不可到达
	RESP_server_acknowlege string = `SERVERCONN-SETUP` // 建立远端服务连接
	RESP_abort_the_operate string = `MALICIOUSOPERATE` // 丢弃操作命令之响应
)
