#!/usr/bin/env python3
'''CHECKING FOR SMB SIGNING ON A TARGET $IP $PORT'''
import sys
import nmap

def scan(ip, port):
    scanner = nmap.PortScanner()
    try:
        check = scanner.scan(hosts=str(ip),arguments=f"-Pn -p {port} --script smb2-security-mode.nse")
        if ("hostscript" in str(check)) and ("disabled" in str(check)):
            return {"ip":ip,"port":port,"isSMBSigningEnabled":True}
        elif ("hostscript" in str(check)) and ("enabled but not required" in str(check)):
            return {"ip":ip,"port":port,"isSMBSigningEnabled":"TrueButNotRequired"}
        else:
            return {"ip":ip, "port":port, "isSMBSigningEnabled":True}
    except Exception:
        print(f"Error checking {ip}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        exit(f'Usage: {sys.argv[0]} target_ip port')
    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    print(f"Scanning for SMB Signing status on ip:{target_ip}, port:{port}...")
    verdict = scan(target_ip, port)
    if verdict:
        results_csv = ''.join([f"{verdict[i]}," if i != list(verdict)[-1] else f"{verdict[i]}" for i in verdict])
        print(f"Results = {results_csv}")
