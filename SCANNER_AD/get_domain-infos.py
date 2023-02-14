#!/usr/bin/env python3
'''PYTHON SCRIPT TO GET INFORMATION ABOUT AN ACTIVE DIRECTORY SUCH AS
- DOMAIN CONTROLLERS
- DOMAIN
'''

import os
import sys
import nmap

cwd = os.getcwd()

def scan_domain(network_ip, subnet):
    nm = nmap.PortScanner()
    nm.scan(f"{network_ip}/{subnet}", arguments="-p389 -sV -Pn")
    nmap_csv = nm.csv()
    list_dcs = [line.split(";")[0] for line in nmap_csv.splitlines() if "Microsoft Windows Active Directory LDAP" in line]
    domains_name = [line.split(";")[8].split(":")[1].split(",")[0].strip() for line in nmap_csv.splitlines() if "Microsoft Windows Active Directory LDAP" in line]
    with open(f"{cwd}/known-data/accounts/domain-controllers_list.txt", "a+", encoding="UTF-8") as output:
        for dc_ip in list_dcs:
            if os.path.isfile(f"{cwd}/known-data/accounts/domain-controllers_list.txt"):
                output.seek(0)
                if dc_ip in output.read():
                    continue
            output.write(f",{dc_ip}")
        output.close()

    with open(f"{cwd}/known-data/accounts/domain-infos_list.txt", "a+", encoding="UTF-8") as output:
        for domain_name in domains_name:
            if os.path.isfile(f"{cwd}/known-data/accounts/domain-infos_list.txt"):
                output.seek(0)
                if domain_name in output.read():
                    continue
            output.write(f"{domain_name},{domain_name.split('.')[0]},{domain_name.split('.')[-1]}")
        output.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        exit(f'Usage: {sys.argv[0]} target_ip subnet')
    network_ip = sys.argv[1]
    subnet = int(sys.argv[2])
    scan_domain(network_ip, subnet)
