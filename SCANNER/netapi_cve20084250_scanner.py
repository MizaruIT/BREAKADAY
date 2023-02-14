#!/usr/bin/env python3
import nmap
import sys

def scan(ip, port):
    scanner = nmap.PortScanner()
    # print(f"Do you really want to scan {ip}:{port} for this attack?\nIn most cases, the systems will crash...")
    # answer = input("Enter your answer (yes/no):")
    # if answer == "yes":
    try:
        check = scanner.scan(hosts=str(ip),arguments=f"-Pn -p {port} --script smb-vuln-ms08-067.nse")
        if ("VULNERABLE" in str(check)):
            print()
            return {"ip":ip,"port":port,"vulnerableToNetapi":True}
        else:
            print()
            return {"ip":ip,"port":port,"vulnerableToNetapi":False}
    except:
        print(f"Error checking {ip}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        exit(f'Usage: {sys.argv[0]} target_ip port')
    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    print(f"Scanning for NetApi (CVE-2008-4250) attack on ip:{target_ip}, port:{port}...")
    verdict = scan(target_ip, port)
    if verdict:
        results_csv = ''.join([f"{verdict[i]}," if i != list(verdict)[-1] else f"{verdict[i]}" for i in verdict])
        print(f"Results = {results_csv}")
