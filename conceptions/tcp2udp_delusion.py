# SPDX-LICENSE-IDENTIFIER: GPL-2.0
# (C) 2024 Author: <kisfg@hotmail.com>
# THESE CODE ARE ONLY FOR PROOVING CONCEPT.
import socket, threading, time
CURR_LOCALHOST = ("localhost", 3194)
LOCK_ME = threading.Semaphore(1)


def safely_print(payload: str) -> None:
	LOCK_ME.acquire()
	print(payload)
	LOCK_ME.release()


def tcp_try_hack() -> None:
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	time.sleep(2)
	try:
		tcp.connect(CURR_LOCALHOST)
		tcp.sendall(b'what can I say?')
		datum = tcp.recv(1024)
		safely_print(datum.decode('iso-8859-1'))
		tcp.close()
	except Exception as ef:
		safely_print(f"tcp_try_hack: we catch an err: {ef}")


def normal_udp_server() -> None:
	udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp_server.bind(CURR_LOCALHOST)
	udp_server.settimeout(3.0)
	try:
		data, addr = udp_server.recvfrom(2048)
		safely_print(data.decode('iso-8859-1'))
	except Exception as e:
		safely_print(f"normal_udp_server: we got an err in udp server: {e}")
		udp_server.close()
		exit(0)
	


if __name__ == "__main__":
	print()
	tnet: list[threading.Thread] = [
		threading.Thread(target=tcp_try_hack, args=()),
	    threading.Thread(target=normal_udp_server, args=())
	]
	for item in tnet:
		item.start()
	for item in tnet:
		item.join()
