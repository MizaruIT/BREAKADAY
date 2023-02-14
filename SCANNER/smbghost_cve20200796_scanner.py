#!/usr/bin/python3
'''CHECKING FOR THE VULNERABILITY SMBGHOST ON A TARGET $IP $PORT'''
import socket
import struct
import sys
from netaddr import IPNetwork

def scanner(ip, port):
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    # subnet = sys.argv[1]
    subnet = ip
    # port = sys.argv[2]

    for ip in IPNetwork(subnet):

        sock = socket.socket(socket.AF_INET)
        sock.settimeout(3)

        try:
            sock.connect(( str(ip),  port ))
        except Exception:
            sock.close()
            continue

        sock.send(pkt)

        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)

        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
            # print(f"{ip}:{port} = NOT VULNERABLE TO CVE-2020-0796")
            return {"ip":ip,"port":port,"vulnerableToSMBGhost":False}
        else:
            # print(f"{ip}:{port} = VULNERABLE TO CVE-2020-0796")
            return {"ip":ip,"port":port,"vulnerableToSMBGhost":True}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        exit(f'Usage: {sys.argv[0]} target_ip port')
    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    print(f"Scanning for SMBGhost attack on ip:{target_ip}, port:{port}...")
    verdict = scanner(target_ip, port)
    if verdict:
        results_csv = ''.join([f"{verdict[i]}," if i != list(verdict)[-1] else f"{verdict[i]}" for i in verdict])
        print(f"Results = {results_csv}")
