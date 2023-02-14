#!/usr/bin/env python3
'''CHECKING FOR THE VULNERABILITY: CVE-2019-1040 ON A TARGET'''
import sys
import logging
import argparse
import codecs
import calendar
import struct
import time
from impacket.examples.logger import ImpacketFormatter
from impacket.smbconnection import SMBConnection, SessionError
#from impacket.smb3structs import *
from impacket import ntlm
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5

def parse_creds(target):
    creds, remote_name = target.rsplit('@', 1)
    if ':' in creds:
        colon_split = creds.split(':', 1) # dom/user, pass
        password = colon_split[1]
        creds = colon_split[0]
    else:
        password = ''

    if '/' in creds:
        slash_split = creds.split("/", 1)
        dom = slash_split[0].strip()
        user = slash_split[1].strip()
    else:
        dom = ''
        user = creds

    return dom, user, password, remote_name

# Slightly modified version of impackets computeResponseNTLMv2
def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='', nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
    av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
        aTime = av_pairs[NTLMSSP_AV_TIME][1]
    else:
        aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
        av_pairs[NTLMSSP_AV_TIME] = aTime
    av_pairs[NTLMSSP_AV_FLAGS] = b'\x02' + b'\x00' * 3
    serverName = av_pairs.getData()

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

orig_type1 = ntlm.getNTLMSSPType1
# Wrapper to remove signing flags
def mod_getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    return orig_type1(workstation, domain, False, use_ntlmv2)

class checker(object):
    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.creds_validated = False

    def validate_creds(self, remote_host):
        try:
            smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
            smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except SessionError as exc:
            if 'STATUS_LOGON_FAILURE' in str(exc):
                logging.error('Error validating credentials - make sure the supplied credentials are correct')
            else:
                print(f'Unexpected Exception while validating credentials against {remote_host}: {exc}')
            # raise KeyboardInterrupt
        except Exception:
            print(f'Error during connection to {remote_host}. TCP/445 refused, timeout?')

    def check(self, remote_host):
        # Validate credentials first
        if not self.creds_validated:
            self.validate_creds(remote_host)
            self.creds_validated = True

        # Now start scanner
        try:
            smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
        except Exception:
            return
        ntlm.computeResponseNTLMv2 = mod_computeResponseNTLMv2
        try:
            smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            print(f'{remote_host}:{self.__port} = VULNERABLE TO CVE-2019-1040 (authentication was accepted)', remote_host)
            return {"ip":remote_host,"port":self.__port,"vulnerableToMICRA":True}
        except SessionError as exc:
            if 'STATUS_INVALID_PARAMETER' in str(exc):
                print(f'{remote_host}:{self.__port} = NO VULNERABLE TO CVE-2019-1040 (authentication was rejected)')
                return {"ip":remote_host,"port":self.__port,"vulnerableToMICRA":False}
            else:
                logging.warning('Unexpected Exception while authenticating to %s: %s', remote_host, exc)

        smbClient.close()


# Process command-line arguments.
def scan(ip, port, domain, username, password, hashes=None):
    lookup = checker(username, password, domain, int(port), hashes)
    results = lookup.check(ip)
    return results


if __name__ == '__main__':
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    parser = argparse.ArgumentParser(description="CVE-2019-1040 scanner - Connects over SMB and attempts to authenticate with invalid NTLM packets. If accepted, target is vulnerable to MIC remove attack")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    group = parser.add_argument_group('connection')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    domain, username, password, remote_name = parse_creds(options.target)
    if password == '' and username == '':
        logging.error("Please supply a username/password (you can't use this scanner with anonymous authentication)")
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    print(f"Scanning for Remove MIC attack on domain:{domain}, IP: {options.target_ip}, port: {options.port}, and username: {username}...")
    lookup = checker(username, password, domain, int(options.port), options.hashes)
    try:
        results = lookup.check(options.target)
    except KeyboardInterrupt:
        sys.exit(1)
    if results:
        results_csv = ''.join([f"{results[i]}," if i != list(results)[-1] else f"{results[i]}" for i in results])
        print(f"Results = {results_csv}")
