# SyncLAPS

Read LAPS passwords from Active Directory **when all you have is a machine certificate** — no PKINIT, no user credentials, no direct read rights on `ms-Mcs-AdmPwd`.

Built and proven during real external/internal penetration tests (authorized engagements, 2026).

## The problem

A very common dead-end in AD CS attack chains (ESC8 relay, Certighost, cert template abuse):

1. You relay/coerce NTLM auth to a Certificate Authority and obtain a **machine certificate of a Domain Controller** (or another host).
2. You try PKINIT — and the KDC rejects it (`KDC_ERR_PADATA_TYPE_NOSUPP`), because PKINIT for machine accounts is frequently unavailable.
3. Standard LAPS tooling (`netexec -M laps`, `Get-LAPSPassword`,ldapsearch) requires **direct READ access** to `ms-Mcs-AdmPwd` (the BloodHound `ReadLAPSPassword` edge). A machine cert doesn't give you that.

Result: you're holding a DC-grade credential and cannot use it. This tool is the way through.

## How it works

`SyncLAPS` authenticates to a Domain Controller via **Schannel** — the client certificate itself is the identity (SASL EXTERNAL bind, no Kerberos at all) — and then abuses the replication-style directory search:

- sends the **LDAP DirSync control** (`1.2.840.113556.1.4.841`, hand-encoded in BER since ldap3 doesn't ship it),
- with `flags=0` (important: `OBJECT_SECURITY` 0x1 changes the rights check and **suppresses** the filtered attribute set),
- which makes the DC return the filtered attribute set — including `ms-Mcs-AdmPwd` / `msLAPS-Password` — to any account holding
  `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-In-Filtered-Set` (the BloodHound **`SyncLAPSPassword`** edge).

A machine account normally has exactly those replication rights. Hence: DC cert → Schannel → DirSync → every LAPS password in the domain.

## Usage

```bash
pip install ldap3

python3 sync_laps.py <DC_IP> <BASE_DN> <CERT> <KEY> [LDAP_FILTER]

# example (lab):
python3 sync_laps.py 192.168.56.10 "DC=lab,DC=local" dc01.crt dc01.key "(sAMAccountName=WS01$)"
```

Operational note discovered the hard way: AD accepts SASL EXTERNAL (client-cert mapping) **only over 389 + StartTLS**, not over LDAPS/636. The tool handles this automatically.

## Requirements for the target

| Requirement | Check (BloodHound/Cypher) |
|---|---|
| Certificate maps to a machine account (Schannel) | cert SAN = `HOST/DC$` etc. |
| Machine account has `GetChanges`/`GetChangesAll`-style replication rights on the domain | edge `SyncLAPSPassword` |
| LAPS (legacy or Windows LAPS) deployed | attribute `ms-Mcs-AdmPwd` / `msLAPS-Password` present |

## Defense / detection

- Monitor LDAP searches with the DirSync control from non-DC accounts (`Event ID 5136`/`4662` replication-style access, SACL on the domain object).
- Restrict certificate template enrollment so machine certs can't be obtained via relay (EPA + Channel Binding on CA endpoints).
- Windows LAPS + rotation limits blast radius; consider `DS-Replication-Get-Changes` audit rules.

## Legal

For authorized security assessments only. The technique (DirSync filtered-set abuse, SyncLAPSPassword edge) is publicly documented — see BloodHound docs and the LAPS operational guidance. This repo is an independent, protocol-level implementation.

## Credits

Technique surface: BloodHound `SyncLAPSPassword` edge, MS-DRSR DirSync control spec. Implementation: original, written for and validated in authorized engagements.
