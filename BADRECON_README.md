# BadRecon

**Active Directory & AD CS Enumeration Framework**

https://github.com/osherjacobs/AD-Lab-Research/blob/main/badrecon.py

BadRecon is a Python-based Active Directory and AD CS enumeration framework focused on identity graph extraction and detection engineering signal generation in modern hardened Windows environments.

It was built as a byproduct of lab work reproducing Bad Successor (CVE-2025-53779) and Golden dMSA attack chains on Windows Server 2025. The immediate problem: every existing Python LDAP library failed the bind against LDAP-signing-enforced Server 2025. BadRecon solves that using impacket's NTLM backend.

This is a research and lab tool, not a production-grade framework. The goal is not enumeration for its own sake — it is structured visibility into identity relationships, delegation boundaries, certificate issuance risk surfaces, and the detection signal each one generates.

Built with assistance from Claude (Anthropic). Each module builds on existing research and tooling; the implementation, assembly, and detection framing are original contributions. Origins are documented in the credits table below.

---

## Important Warning / Disclaimer

**This tool is provided for authorized security research, defensive analysis, and authorized penetration testing only.**

- Use of this tool against systems you do not own or do not have explicit written permission to test may violate applicable laws.
- The author assumes **no liability** for any misuse, damage, or legal consequences resulting from the use of this software.
- **Use entirely at your own risk.**

By using BadRecon, you acknowledge that you are responsible for ensuring full compliance with all relevant laws, regulations, and organizational policies.

---

## License

```
BadRecon — Active Directory enumeration and attack surface mapping
Copyright (c) 2026 Osher Jacobs
https://github.com/osherjacobs/AD-Lab-Research

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

---

## Design Goals

Modern Active Directory environments require tooling that reflects three realities:

- Legacy LDAP tooling assumptions no longer hold in hardened domains — LDAP signing enforcement breaks most Python LDAP stacks against Server 2022/2025
- Identity compromise paths are graph-based, not object-based
- Detection engineering requires relationship-aware telemetry, not flat enumeration

BadRecon focuses on:

- Reproducible LDAP access under hardened configurations (NTLM + signing, port 389)
- Relationship-first data modeling — identity and permission graph extraction
- Detection-oriented normalization of AD and AD CS artifacts

---

## Requirements

```bash
pip3 install impacket ldap3
```

Python 3.10+. Tested against Windows Server 2022 and 2025 with LDAP signing enforced. LDAPS not required.

---

## Usage

```bash
python3 badrecon.py -d <DC_IP> -u <user@domain.local> -p '<password>' [--module <module>]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-d`, `--dc` | DC IP or hostname |
| `-u`, `--user` | Username in `user@domain.local` format |
| `-p`, `--password` | Password |
| `--module` | Module to run (default: `all`) |
| `--group-dn` | DN for recursive group membership lookup |
| `--filter` | Raw LDAP filter — passthrough query |
| `--base` | Custom search base DN (default: domain base) |

---

## Capabilities

### Identity & Directory Enumeration — `--module users/computers/groups`

- All users with adminCount, password policy flags, disabled accounts
- Password policy — min length, max age, complexity, lockout threshold, parsed to human-readable values
- Kerberoastable accounts (`--module kerberoast`) — SPN holders
- AS-REP roastable accounts (`--module asrep`) — DONT_REQ_PREAUTH
- Computer objects with OS version, DC isolation
- All groups with distinguished names
- Recursive group membership via `LDAP_MATCHING_RULE_IN_CHAIN` (`--group-dn`)
- Accounts with `msDS-KeyCredentialLink` set — Shadow Credentials surface

LDAP filters adapted from PowerView (PowerShellMafia/HarmJ0y) — MIT licensed.

**Detection note:** `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) in EID 1644 logs is a high-fidelity signal. Legitimate tooling rarely uses it.

---

### Delegation Surface — `--module delegation`

- Unconstrained delegation — users and computers (`TRUSTED_FOR_DELEGATION`)
- Constrained delegation — `msDS-AllowedToDelegateTo`
- S4U2Self — protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`)
- RBCD targets — `msDS-AllowedToActOnBehalfOfOtherIdentity` set

---

### ACL Edge Enumeration — `--module acledges`

Reads `nTSecurityDescriptor` on privileged objects and returns BloodHound-style directed edges:

```json
{"from": "Domain Admins", "to": "CN=krbtgt,...", "edge": "WriteDacl"}
{"from": "Key Admins",    "to": "DC=domain,...", "edge": "WriteKeyCredentialLink"}
{"from": "Domain Controllers", "to": "DC=domain,...", "edge": "DS-Replication-Get-Changes-All"}
```

Covers: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `WriteKeyCredentialLink`, `WriteMember`, `WriteAllowedToAct`, `ForceChangePassword`, `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`.

No Neo4j. No SharpHound. No binary on disk.

Targets: adminCount=1 users, all computers, all groups, all GPOs, domain root object.

Note: deliberately excluded from `--module all` — slow on large domains, explicit opt-in only.

---

### Managed Service Accounts — `--module msa`

Enumerates gMSA and dMSA accounts separately with:

- `msDS-ManagedPasswordId` — hex blob containing the embedded KDS root key GUID
- `kds_root_key_guid` — decoded GUID, extracted automatically from the blob
- `msDS-ManagedPasswordInterval` — rotation interval
- `msDS-GroupMSAMembership` — principals allowed to retrieve the managed password (parsed to SIDs)
- `msDS-DelegatedMSAState` — dMSA migration state (3 = migration complete)
- `msDS-SupersededServiceAccountDN` — for dMSA: the account this supersedes
- `whenCreated`, `whenChanged`

**Why this matters:** Resetting privileged account passwords does not invalidate credentials derived from the KDS root key. `msDS-ManagedPasswordId` contains the KDS GUID that goldendMSA uses for offline credential derivation. Standard IR procedures do not touch the KDS root key.

**Detection note:** Baseline this output. Unexpected new accounts or changes to retrieval principals (`msDS-GroupMSAMembership`) after a security incident are high-fidelity persistence indicators. `msDS-ManagedPasswordId` drift on an existing account warrants investigation.

Golden dMSA research by Adi Malyanker, Semperis.

---

### AD CS Enumeration — `--module adcs`

CA discovery and certificate template enumeration with ESC classification based on SpecterOps ESC research framework (where applicable):

| ESC | Condition |
|-----|-----------|
| ESC1 | Enrollee supplies SAN + client auth EKU + low-priv enrollment |
| ESC2 | Any Purpose EKU or no EKU restriction + low-priv enrollment |
| ESC3 | Certificate Request Agent EKU + low-priv enrollment + no RA signature |
| ESC4 | Low-priv write access to template DACL |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA |
| ESC7 | Low-priv manage CA / manage certificates rights |
| ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` set |

Output separates CA details, template catalog, and ESC findings.

---

### GPO / OU / Schema / DNS / DFS

- GPO names and SYSVOL paths (`--module gpo`)
- OU structure with gpLink (`--module ou`)
- Extended rights catalog — DCSync rights visible (`--module acl`)
- DNS zones (`--module dns`)
- DFS namespaces (`--module dfs`)

---

### Raw Filter Passthrough

```bash
# Accounts with SIDHistory set
python3 badrecon.py -d <DC> -u <user> -p '<pass>' --filter "(sIDHistory=*)"

# Objects modified recently
python3 badrecon.py -d <DC> -u <user> -p '<pass>' --filter "(whenChanged>=20260511000000.0Z)"

# Search config partition
python3 badrecon.py -d <DC> -u <user> -p '<pass>' \
  --filter "(cn=VulnTemplate)" \
  --base "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
```

---

## Detection Engineering Notes

BadRecon was built alongside detection engineering work, not after it. Each module surfaces attack-relevant attributes and the telemetry that would catch them:

| Signal | EID / Source | Default? |
|--------|-------------|---------|
| `LDAP_MATCHING_RULE_IN_CHAIN` queries | EID 1644 | No — requires DS Access auditing |
| `msDS-ManagedPasswordId` read | EID 4662 (SACL on KDS container) | No — requires SACL |
| ESC3 enrollment by non-admin | ADCS request logs | No — requires CA auditing |
| Unexpected WriteDacl on domain root | EID 4662 | No — requires SACL |
| DS-Replication-Get-Changes-All grant | EID 5136 | Yes — if DS Changes auditing enabled |
| `msDS-KeyCredentialLink` modification | EID 5136 | No — requires object-level auditing |

None of these alert without explicit configuration.

---

## Architecture

- Pure Python
- LDAP transport: impacket NTLM backend (port 389)
- Security descriptor parsing: impacket `SR_SECURITY_DESCRIPTOR`
- SID resolution: well-known SIDs + domain RID table, domain SID auto-detected at bind
- Output: structured JSON to stdout
- No external graph database dependency
- No binary deployment required

---

## Environment

Tested against:
- Windows Server 2025 Datacenter (Build 26100)
- Windows Server 2022 Standard
- Domain functional level: Windows Server 2016+
- LDAP signing: Enforced
- LDAPS: Not required

---

## Research Foundations & Credits

| Component | Source | License |
|-----------|--------|---------|
| LDAP filter set | Adapted from PowerView (Harmj0y / PowerShellMafia) | MIT |
| LDAP transport | impacket (Fortra) | Apache 2.0 |
| Filter escaping | ldap3 (Giovanni Cannata) | LGPL |
| Golden dMSA / MSA module framing | Adi Malyanker, Semperis | Published research |
| ADCS ESC classification | SpecterOps ESC research framework (where applicable) | Published research |
| LLM-assisted development | Claude (Anthropic) | Tooling aid |
| Implementation & detection engineering | Osher Jacobs | Original work |

---

## NOTICE

BadRecon is an independent implementation and does not include or redistribute proprietary code from referenced research or tooling projects.

All third-party components are used under their respective licenses (MIT, Apache 2.0, LGPL) and remain the property of their original authors.

This project does not claim endorsement by any referenced researchers or organizations.

---

## Disclaimer

This tool is intended for authorized security testing, research, and defensive analysis only. Users are responsible for ensuring compliance with applicable laws and organizational policies.
