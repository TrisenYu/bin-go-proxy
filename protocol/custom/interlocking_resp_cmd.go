// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package protocol

const (
	CMD_PAYLOAD_LEN  uint  = 24
	CMD_RPORT_ED     uint  = 2 + CMD_PAYLOAD_LEN
	CMD_ADDR_ED      uint  = 2 + CMD_RPORT_ED
	PROTOCOL_VERSION uint8 = 0xCA
	/* 24 bytes */
	CMD_refresh_sessionkey string = `REFRESH-CURR-SESSION-KEY` // switch sessionkey
	CMD_disconnect_with_ep string = `CLIENT-DISCONNECT-HOPING` // abort connection
	CMD_alter_aloof_server string = `NEED-ALTER-REMOTE-SERVER` // switch remote server
	CMD_client_ready4_dual string = `CLIENT-IS-READY-FOR-DUAL` // prepare for flow-forwarding
	/* 16 bytes */
	RESP_recv_server_addrp string = `SERVER-IS-RECVED` // response to describe that the message has been received
	RESP_fail2_conn2server string = `SERVER-DIAL-FAIL` // remote server is unreachable
	RESP_server_acknowlege string = `SERVERCONN-SETUP` // set up connection with remote server
	RESP_abort_the_operate string = `MALICIOUSOPERATE` // response to indicate that the operation has been gave up
)
