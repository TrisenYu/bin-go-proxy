# SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
# (C) 2024 Author: <kisfg@hotmail.com>
"""
REFERENCE: 
	[1] Calnex.时间和时间误差网络同步指南[J/OL].www.calnexsol.cn/docman/techlib/timing-and-sync-lab/577-time-and-time-error-ch-cx5013-v1-3/file,2016年5月.
"""

import threading
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

STRESS_BLUE: str = "\033[1;34m"
END_FONT_COLOR: str = "\033[0m"

localAddr = ("localhost", 9977)					# LocalHost
remoteWindowsAddr = ("10.23.235.121", 9977)		# Class A Network(Intranet)


def tcp_fin_scan(ip: str, port: int) -> None:
	"""
		:param ip: ip to host.
		:param port: port to certain application running on the host.
		:return: None.

		a FIN packet(more invisible than the SYN Scan):
			- to a closed port => get a RST back.
			- no response      =>  either dropped by the firewall or the port is open.

		However, many system always return RST, which leads to the impossibility to know if a port is open or closed,
		For instance: __Windows__ does this but not UNIX.

		But Assume our client obtain the ability to control the port rather than always sending rst.

	"""
	payload = IP(dst=ip)/TCP(dport=port, flags="F")
	ans = sr1(payload, timeout=1, verbose=1)
	if ans is None:
		print(f"{STRESS_BLUE}({ip},{port}){END_FONT_COLOR} is open.")
	elif ans is not None and ans[TCP].flags == 'RA':  # RST ACK
		ans.display()
		print(f"{STRESS_BLUE}({ip},{port}){END_FONT_COLOR} is close or is in unknownState.")


ENABLE: bool = False
if __name__ == "__main__":
	print()
	tnet: list[threading.Thread] = [
		threading.Thread(target=tcp_fin_scan, args=(localAddr[0], localAddr[1]))]
	if ENABLE:
		tnet.append(threading.Thread(target=tcp_fin_scan, args=(remoteWindowsAddr[0], remoteWindowsAddr[1])))

	for item in tnet:
		item.start()
	for item in tnet:
		item.join()
