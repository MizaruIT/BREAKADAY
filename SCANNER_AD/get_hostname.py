#!/usr/bin/env python3
'''GET HOSTNAME VALUE FROM AN ACTIVE DIRECTORY'''

import sys
import base64
import csv
import os
import socket
import ldap


FUNCTIONALITYLEVELS = {
    b"0": "2000",
    b"1": "2003 Interim",
    b"2": "2003",
    b"3": "2008",
    b"4": "2008 R2",
    b"5": "2012",
    b"6": "2012 R2",
    b"7": "2016"
}

DOMAIN_ADMIN_GROUPS = [
    "Domain Admins",
    "Domain-Admins",
    "Domain Administrators",
    "Domain-Administrators",
    "Domänen Admins",
    "Domänen-Admins",
    "Domain Admins",
    "Domain-Admins",
    "Domänen Administratoren",
    "Domänen-Administratoren",
]

# Privileged builtin AD groups relevant to look for
BUILTIN_PRIVILEGED_GROUPS = DOMAIN_ADMIN_GROUPS + [
    "Administrators",  # Builtin administrators group for the domain
    "Enterprise Admins",
    "Schema Admins",  # Highly privileged builtin group
    "Account Operators",
    "Backup Operators",
    "Server Management",
    "Konten-Operatoren",
    "Sicherungs-Operatoren",
    "Server-Operatoren",
    "Schema-Admins",
]


class LDAPSearchResult(object):
    """A helper class to work with raw search results
    Copied from here: https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2
    """

    dn = ''

    def __init__(self, entry_tuple):
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return

        self.attrs = ldap.cidict.cidict(attrs)

    def get_attributes(self):
        return self.attrs

    def has_attribute(self, attr_name):
        return attr_name in self.attrs

    def get_attr_values(self, key):
        return self.attrs[key]

    def get_attr_names(self):
        return self.attrs.keys()

    def get_dn(self):
        return self.dn

    def get_print_value(self, value):
        isprintable = False
        try:
            dec_value = value.decode()
            isprintable = dec_value.isprintable()
            if isprintable:
                value = dec_value
        except UnicodeDecodeError:
            pass
        if not isprintable:
            value = base64.b64encode(value).decode()

        return value

    def pretty_print(self):
        attrs = self.attrs.keys()
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                print(f"{attr}: {self.get_print_value(value)}")

    def getCSVLine(self):
        attrs = self.attrs.keys()
        lineValues = []
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                lineValues.append(self.get_print_value(value))

        return lineValues


class LDAPSession(object):
    def __init__(self, dc_ip='', username='', password='', domain=''):

        if dc_ip:
            self.dc_ip = dc_ip
        else:
            self.get_set_DC_IP(domain)

        self.username = username
        self.password = password
        self.domain = domain

        self.con = self.initializeConnection()
        self.domainBase = ''
        self.is_binded = False

    def initializeConnection(self):
        if not self.dc_ip:
            self.get_set_DC_IP(self.domain)

        con = ldap.initialize(f'ldap://{self.dc_ip}')
        con.set_option(ldap.OPT_REFERRALS, 0)
        return con

    def unbind(self):
        self.con.unbind()
        self.is_binded = False

    def get_set_DC_IP(self, domain):
        """
        if domain is provided, do a _ldap._tcp.domain to try and find DC, or maybe a "host -av domain" eventually ?
        if no domain is provided, do a multicast and hope it's in the search domain
        if can't find anything, return error and require dc_ip set manually
        """
        try:
            dc_ip = socket.gethostbyname(domain)
        except Exception:
            print("[!] Unable to locate domain controller IP through host lookup. Please provide manually")
            # sys.exit(1)
            return

        self.dc_ip = dc_ip

    def getDefaultNamingContext(self):
        try:
            newCon = ldap.initialize(f'ldap://{self.dc_ip}')
            newCon.simple_bind_s('', '')
            res = newCon.search_s("", ldap.SCOPE_BASE, '(objectClass=*)')
            rootDSE = res[0][1]
        except ldap.LDAPError as e:
            print("[!] Error retrieving the root DSE")
            print(f"[!] {e}")
            # sys.exit(1)
            return

        if 'defaultNamingContext' not in rootDSE:
            print("[!] No defaultNamingContext found!")
            # sys.exit(1)
            return

        defaultNamingContext = rootDSE['defaultNamingContext'][0].decode()

        self.domainBase = defaultNamingContext
        newCon.unbind()
        return defaultNamingContext

    def do_bind(self):
        try:
            self.con.simple_bind_s(self.username, self.password)
            self.is_binded = True
            return True
        except ldap.INVALID_CREDENTIALS:
            print("[!] Error: invalid credentials")
            # sys.exit(1)
            return False
        except ldap.LDAPError as e:
            print(f"[!] {e}")
            # sys.exit(1)
            return False

    def whoami(self):
        try:
            current_dn = self.con.whoami_s()
        except ldap.LDAPError as e:
            print(f"[!] {e}")
            # sys.exit(1)
            return

        return current_dn

    def do_ldap_query(self, base_dn, subtree, objectFilter, attrs, page_size=1000):
        """
        actually perform the ldap query, with paging
        copied from another LDAP search script I found: https://github.com/CroweCybersecurity/ad-ldap-enum
        found this script well after i'd written most of this one. oh well
        """
        more_pages = True
        cookie = None

        ldap_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

        allResults = []

        while more_pages:
            msgid = self.con.search_ext(base_dn, subtree, objectFilter, attrs, serverctrls=[ldap_control])
            result_type, rawResults, message_id, server_controls = self.con.result3(msgid)

            allResults += rawResults

            # Get the page control and get the cookie from the control.
            page_controls = [c for c in server_controls if
                             c.controlType == ldap.controls.SimplePagedResultsControl.controlType]

            if page_controls:
                cookie = page_controls[0].cookie

            if not cookie:
                more_pages = False
            else:
                ldap_control.cookie = cookie

        return allResults

    def get_search_results(self, results):
        # takes raw results and returns a list of helper objects
        res = []
        arr = []
        if type(results) == tuple and len(results) == 2:
            (code, arr) = results
        elif type(results) == list:
            arr = results

        if len(results) == 0:
            return res

        for item in arr:
            resitem = LDAPSearchResult(item)
            if resitem.dn:  # hack to workaround "blank" results
                res.append(resitem)

        return res

    def doCustomSearch(self, base, objectFilter, attrs):
        try:
            rawResults = self.do_ldap_query(base, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error doing search")
            print(f"[!] {e}")
            # sys.exit(1)
            return

        return self.get_search_results(rawResults)

    def getAllComputers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']

        objectFilter = '(objectClass=Computer)'
        base_dn = self.domainBase

        try:
            rawComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving computers")
            print(f"[!] {e}")
            # sys.exit(1)
            return

        return self.get_search_results(rawComputers), attrs

    def getComputerDict(self, computerResults, ipLookup=False):
        """returns dict object of computers and attributes
        if iplookup speficied will add IP addresses through simple host lookup
        returns dictionary of computers in the domain with DN as key"""
        computersDict = {}
        for computer in computerResults:
            computerInfo = {}
            dn = computer.dn
            for attr in computer.get_attr_names():
                computerInfo[attr] = ','.join(computer.get_attr_values(attr))

            if 'dNSHostName' in computerInfo:
                hostname = computerInfo['dNSHostName']
            else:
                hostname = computerInfo['cn'] + self.domain

            try:
                computerInfo['IP'] = socket.gethostbyname(hostname)
            except Exception:
                print("error")
                computerInfo['IP'] = ""

            computersDict[dn] = computerInfo

        return computersDict

def prettyPrintDictionary(results, attrs=None, separator=","):
    # helper function to pretty print(a dictionary of dictionaries, like the one returned in getComputerDict
    keys = set()
    common_attrs = ['cn', 'IP', 'dNSHostName', 'userPrincipalName', 'operatingSystem', 'operatingSystemVersion',
                    'operatingSystemServicePack']
    attrs = []

    for dn, computer in results.iteritems():
        for key in computer:
            keys.add(key)

    for attr in common_attrs:
        if attr in keys:
            attrs.append(attr)
            keys.remove(attr)
    for attr in keys:
        attrs.append(attr)
    print(", ".join(attrs))

    for dn, computer in results.items():
        line = []
        for attr in attrs:
            if attr in computer:
                line.append(computer[attr])
            else:
                line.append(' ')
        print(separator.join(line))


def bye(ldapSession):
    ldapSession.unbind()
    print("\n[*] Bye!")
    # sys.exit(1)
    return



def run(username, password, dc_ip, domain):
    print(username, password, dc_ip, domain)
    ldapSession = LDAPSession(dc_ip=dc_ip, username=username, password=password, domain=domain)
    cwd = os.getcwd()
    print(f"[+] Using Domain Controller at: {ldapSession.dc_ip}")
    print("[+] Getting defaultNamingContext from Root DSE")
    print(f"[+]\tFound: {ldapSession.getDefaultNamingContext()}")
    print("[+] Attempting bind")
    if not ldapSession.do_bind():
        return
    if ldapSession.is_binded:
        print("[+]\t...success! Binded as: ")
        print(f"[+]\t {ldapSession.whoami()}")

    attrs = ''
    print("\n[+] Enumerating all AD computers")
    allComputers, searchAttrs = ldapSession.getAllComputers(attrs=attrs)
    if not allComputers:
        bye(ldapSession)
    print(f"[+]\tFound {len(allComputers)} computers: \n")

    allComputersDict = ldapSession.getComputerDict(allComputers, ipLookup=True)
    prettyPrintDictionary(allComputersDict, attrs=searchAttrs)

    # writeResults(allComputers, searchAttrs, filename)
    with open(f"{cwd}/known-data/accounts/computers_list.txt", 'w', newline='', encoding="UTF-8") as csv_file:
        writer = csv.writer(csv_file, delimiter="\t")
        writer.writerow(attrs)
        writer.writerows((result.getCSVLine() for result in allComputers))
        writer.close()

    bye(ldapSession)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        exit(f'Usage: {sys.argv[0]} username password dc_ip domain_name\nExample: python3 FILE user1 user1password 192.168.1.1 essos')
    username = sys.argv[1]
    password = sys.argv[2]
    dc_ip = sys.argv[3]
    domain_name = sys.argv[4]
    run(f"{username}", password, dc_ip, domain_name)
    # Example: run("essos\\jorah.mormont", "H0nnor!", "192.168.56.12", "meereen.essos.local")

    # it worked:  ldapdomaindump 192.168.56.10 -u 'north.sevenkingdoms.local\jon.snow' -p 'iknownothing' 
    # it worked with windapsearch: python3 windapsearch/windapsearch.py --dc-ip 192.168.56.10 -u jon.snow@north.sevenkingdoms.local -p iknownothing --computers
    # [+] Using Domain Controller at: 192.168.56.10
    # [+] Getting defaultNamingContext from Root DSE
    # [+]	Found: DC=sevenkingdoms,DC=local
    # [+] Attempting bind
    # [+]	...success! Binded as: 
    # [+]	 u:NORTH\jon.snow

    # [+] Enumerating all AD computers
    # [+]	Found 1 computers: 

    # cn: KINGSLANDING
    # operatingSystem: Windows Server 2019 Datacenter Evaluation
    # operatingSystemVersion: 10.0 (17763)
    # dNSHostName: kingslanding.sevenkingdoms.local

    # it worked:
    # python3 windapsearch.py --dc-ip 192.168.56.11 -u jon.snow@north.sevenkingdoms.local -p iknownothing --computers -r -C -o .
    # r = to resolve IP address
