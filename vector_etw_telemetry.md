<img width="1915" height="1080" alt="PERFVIEW1" src="https://github.com/user-attachments/assets/0a91498c-bf1c-4fa1-baf0-73d7d4f900a6" />

# Defender Engine Telemetry — UNC-Hosted LSASS Credential Access
## ETW Analysis via Microsoft-Antimalware-Engine Provider

**Target:** Windows Server 2019 Standard Evaluation (Build 17763.8644) — lab2019.local PDC  
**Tooling:** Windows Performance Recorder (`wpr -start GeneralProfile -filemode`) + PerfView 3.x  
**Provider:** `Microsoft-Antimalware-Engine` (captured via GeneralProfile; `Microsoft-Windows-Threat-Intelligence` inaccessible — see §6)  
**Execution:** UNC-hosted ConfuserEx-obfuscated .NET LSASS dumper via DCOM lateral movement (MMC20)  
**Test date:** 26 May 2026  
**Methodology:** Operational assumption analysis — documenting what the defensive stack actually observes

---

## Epistemic Note

This document distinguishes explicitly between three claim types:

- **Observed:** directly present in the ETW event data
- **Inferred:** reasonable interpretation, stated as inference
- **Unknown:** not determinable from this data alone

Where prior analysis crossed these boundaries, this writeup uses tighter formulations. Reviewers (including external feedback incorporated here) correctly identified several overreaches in draft analysis; those have been corrected throughout.

---

## 1. Background and Methodology

The Vector series documents where defensive stack assumptions exceed their actual guarantees. This addendum focuses not on whether the technique worked — that was established in the primary writeup — but on what the Defender engine observably did during execution.

The trace was collected by starting `wpr -start GeneralProfile -filemode` on the target DC, triggering the full UNC dump chain from Kali (impacket-dcomexec MMC20 + UNC-hosted binary), and stopping the trace after dump retrieval. PerfView was used to parse the resulting ETL and export per-provider CSV data from `Microsoft-Antimalware-Engine` event types.

The primary writeup documented:
- EID 4663 PROCESS_VM_READ against lsass.exe with `\Device\Mup\` process representation
- Sysmon EID 1 zeroed IMPHASH + UNC image path cluster
- No Defender alerts (fresh ConfuserEx hash)

This document adds the engine-internal view: what evaluation paths fired, in what sequence, with what results.

---

## 2. The Visibility Ceiling: Microsoft-Windows-Threat-Intelligence

Before examining what was observed, it is worth documenting what could not be observed.

An attempt was made to capture raw kernel telemetry from the `Microsoft-Windows-Threat-Intelligence` ETW provider using SilkETW v8, running as Domain Administrator:

```
[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 0
Unhandled Exception: System.UnauthorizedAccessException:
Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   at ...TraceEventSession.EnableProvider(...)
```

This is not a privilege issue. The provider is kernel-registered and requires the consuming process to run at **Protected Process Light (PPL) Anti-Malware level** — a protection tier reserved for co-signed security vendor drivers approved by Microsoft. Domain Administrator and NT AUTHORITY\SYSTEM both fail identically.

**Implication:** The telemetry documented in this writeup — from `Microsoft-Antimalware-Engine` — represents the ceiling of what a non-EDR defender can observe at this layer. The raw kernel callback sequence (what fired before Defender's verdict logic ran, what was consumed internally without surfacing to any log) is architecturally inaccessible without a PPL-level consumer. This is not a configuration gap. It is enforced by design.

---

## 3. Observed Engine Decision Path

### 3.1 USN Cache Lookup

**Provider:** `Microsoft-Antimalware-Engine/CacheTask/CacheLookup`

```
Time:       34850.982ms
FileName:   \\192.168.1.218\share\curnxc1.exe
CacheName:  USN Cache
Result:     MISS

Time:       34860.710ms
FileName:   \\192.168.1.218\share\curnxc1.exe
CacheName:  USN Cache
Result:     MISS
```

**Observed:** Two USN cache lookups for the UNC-hosted binary, both returning MISS. Two threads (5,268 and 4,244) queried in parallel ~10ms apart.

**Inference:** USN (Update Sequence Number) is the Windows filesystem change journal. A MISS is consistent with the binary having no local filesystem record — expected behaviour for UNC-hosted execution. The engine could not return a cached verdict and proceeded to further evaluation.

**Note:** All system DLLs, mmc.exe, cmd.exe, and conhost.exe returned `Result=32,769` (known good) from the MOAC reputation cache — none required re-evaluation. The UNC binary was the only executable in the relevant time window that produced a MISS requiring a different evaluation path.

---

### 3.2 MOAC (Cloud Reputation) Lookup

**Provider:** `Microsoft-Antimalware-Engine/CacheTask/MOACLookup`

**Observed:** No MOACLookup event for `\\192.168.1.218\share\curnxc1.exe` is present in the captured trace.

**What this means (tightly stated):** No MOACLookup event for the UNC executable was observed in this trace. This does not prove that no cloud reputation query occurred — it proves that none was observed at this provider verbosity. Possible explanations include: an alternate evaluation path was taken; the lookup was keyed to a stream or resource object rather than a file object; or the event fired under a different category not captured here.

**What can be said:** The UNC binary did not exhibit the same observable USN→MOAC event pattern seen for other executables in this trace. The subsequent events (§3.3) show a different evaluation path was followed.

---

### 3.3 AMFilter Intercept — Kernel Minifilter Layer

**Provider:** `Microsoft-Antimalware-AMFilter/AMFilter_FileScan`

Two `AMFilter_FileScan` events were surfaced by filtering PerfView on process name `nxc`:

```
Event 1:
  Time:                    34,289.598ms
  Process:                 cmd (7936)
  FileName:                \Device\Mup\192.168.1.218\share\curnxc1.exe
  Reason:                  OnOpen
  IoStatusBlockForNewFile: 4,294,967,295

Event 2:
  Time:                    34,811.434ms
  Process:                 curnxc1 (7728)
  FileName:                \Device\HarddiskVolume4\ProgramData\lsass.dmp
  Reason:                  OnOpen
```

**Observed:** The AMFilter kernel minifilter driver intercepted two file open operations: the UNC binary open by cmd.exe, and the lsass.dmp open by curnxc1.exe. Both events carry `Reason=OnOpen` — these are filter-level intercepts at file open time, not scan results.

**Timing relationship:** The AMFilter intercept of the UNC binary (34,289.598ms) precedes the StreamScanRequest Start (34,289.752ms) by approximately 0.15ms. The observable sequence is: minifilter intercept → engine scan request. This ordering is consistent with the expected architecture: the filter driver intercepts the file operation and hands off to the engine for evaluation.

**IoStatusBlockForNewFile: 4,294,967,295 (0xFFFFFFFF):** This field on the UNC binary open event is observable but its precise interpretation in this context is unknown. The value is consistent with a read-only network share fetch rather than a local file creation, though other interpretations are possible. This is noted as an observation rather than a conclusion.

**What this adds:** The AMFilter events confirm that the Defender filter driver layer observed both file open operations at the kernel level — the UNC binary fetch and the dump file write. The filter layer is a distinct instrumentation surface from the engine scan layer documented in §3.5 and §3.9. Observation at the filter layer does not in itself imply any particular engine verdict or action.

**What this does not show:** The AMFilter_FileScan events do not include verdict or action fields in this capture. Whether the filter layer passed, blocked, or deferred either file open cannot be determined from these events alone — the absence of a block is inferred from the successful execution documented in the primary writeup, not from these events directly.

---

### 3.4 Stream Scan — Binary Execution

**Provider:** `Microsoft-Antimalware-Engine/StreamScanRequestTask`

```
Start:
  Time:     34289.752ms
  Id:       1,646,603,497
  Path:     \Device\Mup\192.168.1.218\share\curnxc1.exe
  Process:  \Device\HarddiskVolume4\Windows\System32\cmd.exe
  Reason:   2  (on-execute / on-read)
  PID:      7,936

Stop:
  Time:     34328.090ms
  Id:       1,646,603,497
  Duration: 38.338ms
  Result:   [no ThreatName, no Action fields populated]
```

**Observed:** A stream-level scan of the UNC binary was triggered as cmd.exe fetched and executed it from the network share. The scan completed in 38ms. No prevention or detection action is observable from this event.

**Context:** This is the same scan surface that produced `Detection Origin: Network share / DetectionType: FastPath / Name: Trojan:Win32/Bearfoos.B!ml` with the previously-classified binary hash. The same scan path fired with the fresh ConfuserEx hash and produced no observable action.

**\Device\Mup\ consistency:** The UNC path representation in the stream scan Process field matches the representation observed in EID 4663 and BmProcessContextStart (§3.6). The `\Device\Mup\` notation is the kernel's canonical representation of UNC-hosted executables — consistent across the security audit subsystem, the behavior monitor, and the stream scan engine.

---

### 3.5 Runtime Memory Scan

**Provider:** `Microsoft-Antimalware-Engine/ScanRequestTask`

```
Start:
  Time:               34851.888ms
  Id:                 03256DC5D552EF4F8CC4D989A2C75092
  Type:               Resource
  ScanSource:         8  (behavior monitor triggered)
  FirstResourceType:  processmemoryscan
  FirstResourcePath:  pid:7728,ProcessStart:134243052301182421
  Flags:              268,435,460 (0x10000004 — async)

Stop:
  Time:               34881.321ms
  Id:                 03256DC5D552EF4F8CC4D989A2C75092
  Duration:           29.433ms
  Result:             [no ThreatName, no Action fields populated]
```

**Observed:** The behavior monitor (ScanSource=8) triggered a process memory scan against PID 7728 (curnxc1.exe) at runtime. The scan completed in 29ms. No prevention or detection action is observable from this event.

**Inference:** Following the USN MISS, a runtime memory evaluation path was observed via processmemoryscan. The observable sequence transitioned from stream scan and cache activity to a runtime processmemoryscan — consistent with the absence of a local file object to evaluate.

**What this does not prove:** That the memory scan was the only evaluation that occurred. Other evaluation paths may have run concurrently or asynchronously.

---

### 3.6 Behavior Monitor Execution Context

**Provider:** `Microsoft-Antimalware-Engine/BehaviorMonitorTask/BmProcessContextStart`

```
Time:             34340.426ms
PID:              7,728
ProcessContextId: 0x229b588ad20
ImagePath:        \Device\Mup\192.168.1.218\share\curnxc1.exe
```

**Observed:** The behavior monitor registered curnxc1.exe as a tracked execution context using the `\Device\Mup\` UNC path. This is the third independent telemetry surface (alongside EID 4663 and StreamScanRequest) to represent the binary using this notation.

**Full execution chain visible in BmProcessContextStart:**

| Time (ms) | PID | Image |
|---|---|---|
| 34020 | 8124 | mmc.exe — DCOM entry point |
| 34210 | 7936 | cmd.exe — spawned by MMC20 |
| 34222 | 6680 | conhost.exe |
| 34340 | 7728 | `\Device\Mup\192.168.1.218\share\curnxc1.exe` |

The DCOM lateral movement chain is fully visible to the behavior monitor.

**BmProcessContextStop (PID 7728):**
```
Time:             69771.138ms
TerminationTime:  134,243,052,307,798,794
Result:           [no verdict fields]
```

**Observed:** The behavior monitor closed the execution context for curnxc1.exe at process termination with no deferred verdict attached.

---

### 3.7 LSASS Handle Acquisition — Visibility Gap

**Provider:** `Microsoft-Antimalware-Engine/BehaviorMonitorTask/BmOpenProcess`

The BmOpenProcess events present in the trace show process handle acquisitions observed by the behavior monitor. The entry most relevant to curnxc1.exe:

```
Time:        34349.068ms
PID:         7,936  (cmd.exe)
TargetPID:   7,728  (curnxc1.exe)
AccessMask:  2,097,151 (0x1FFFFF — PROCESS_ALL_ACCESS)
WasHardened: False
```

**Observed:** cmd.exe (the DCOM-spawned parent) opening a handle to curnxc1.exe with PROCESS_ALL_ACCESS was observed by the behavior monitor. `WasHardened=False` — ASR hardening was not applied to this process open.

**Observed gap:** No BmOpenProcess event with TargetPID corresponding to lsass.exe is present in the captured trace data for the relevant time window.

**What this means (tightly stated):** The LSASS access observed in Security auditing (EID 4663, Access Mask 0x10 PROCESS_VM_READ) was not visible in the BmOpenProcess events collected here. This does not prove the behavior monitor did not observe the handle acquisition — possible explanations include provider coverage limitations at this verbosity, timing differences between the audit subsystem and behavior monitor callbacks, PPL instrumentation boundaries, or different telemetry classification for protected process access.

**WasHardened=False on all entries** is observed but cannot be interpreted as proof that ASR rules were not configured or would not block — ASR behavior is policy-, mode-, and version-dependent and requires direct testing to establish.

---

### 3.8 Dump File Scanning

**Provider:** `Microsoft-Antimalware-Engine/StreamScanRequestTask`

Two scans of `C:\ProgramData\lsass.dmp`:

```
Scan 1 (on-write):
  Id:       1,646,603,498
  Start:    34811.559ms
  Stop:     34822.500ms
  Duration: 10.940ms
  Reason:   2  (on-write)
  Process:  \Device\Mup\192.168.1.218\share\curnxc1.exe
  Result:   [no ThreatName, no Action]

Scan 2 (on-close):
  Id:       1,646,603,499
  Start:    34959.279ms
  Stop:     37290.317ms
  Duration: 2,331.038ms
  Reason:   5  (on-close)
  Process:  \Device\Mup\192.168.1.218\share\curnxc1.exe
  Result:   [no ThreatName, no Action]
```

**Observed:** Defender scanned lsass.dmp on both write (11ms) and close (2,331ms). The on-close scan was materially longer than both the binary stream scan (38ms) and runtime memory scan (29ms). No prevention or detection action is observable from either scan.

**Connection to prior research:** In earlier research (April 2026, Vector 4), Defender's runtime enforcement layer was observed to degrade dump write throughput by approximately 30-45x — from seconds to 30-45 minutes — without blocking completion and without emitting any standard audit events (no EID 1116/1117, no EID 10). The precise mechanism was not isolated in that session. The current ETW trace may be observing components of that mechanism: the AMFilter intercepts at file open time (§3.3), the behavior-monitor-triggered processmemoryscan at runtime (§3.5), and the 2,331ms on-close scan of lsass.dmp are all candidates. Whether any of these individually or in combination accounts for the throughput degradation observed in April remains an open question requiring controlled isolation testing.

**Note on comparability:** The binary used in Vector 4 was a minimal ~17-line C# implementation — a deliberately sparse scan surface presenting almost no behavioral or structural profile to the engine. The memory walker used in this chain is substantially more complex (~200-300 lines). The throughput degradation observed in April therefore occurred against the simpler binary, which makes it the more striking finding: a minimal implementation with almost no observable surface still triggered runtime enforcement significant enough to degrade write throughput 30-45x. Whether the more complex implementation used here would produce materially different runtime enforcement behavior under a local-write scenario remains untested in a controlled side-by-side.

---

### 3.9 Cloud Interaction (Spynet/MAPS)

**Provider:** `Microsoft-Antimalware-Service`

```
SendReportStart:        36742.005ms
SendReportComplete:     37287.350ms   (545ms round trip)
HandleResponseComplete: 37287.827ms   (~0.5ms after complete)
```

**Timing correlation:**
- lsass.dmp on-close scan start: 34959ms
- Spynet report sent: 36742ms
- Spynet report complete: 37287ms
- lsass.dmp on-close scan stop: 37290ms

The cloud interaction was temporally correlated with the lsass.dmp on-close scan. The report completed approximately 3ms before the scan Stop event.

**What is known:** A MAPS-related interaction occurred after the activity. The report round-trip was 545ms. The response was handled immediately. No subsequent detection or prevention action is observable in the trace following the response.

**What is not known:** The payload content of the report. The ETW events at this verbosity level contain only timestamps and ActivityIDs — no report contents, file references, or behavioral descriptors are visible. Whether this was a lightweight telemetry ping, a behavioral signal summary, a cloud scoring request, or something else cannot be determined from this data alone.

**SubmitSamplesConsent=0 — precise interpretation:**
`SubmitSamplesConsent=0` was set on this host. This setting suppresses binary sample submission to Microsoft. It does not suppress all Microsoft communication. The Spynet interaction above occurred regardless. The correct statement is: *sample submission suppression should not be interpreted as network silence — telemetry-related communication still occurred.* Whether that communication contained execution-specific context or was unrelated background telemetry cannot be established from this trace alone.

---

## 4. Complete Engine Decision Sequence

The following timeline represents observed events only. Gaps between events do not imply absence of activity — they reflect the limits of what was captured.

| Time (ms) | Event | Observable Result |
|---|---|---|
| 34289 | StreamScan Start — `\Device\Mup\...\curnxc1.exe` (Reason=2) | — |
| 34328 | StreamScan Stop — 38ms | No action observed |
| 34340 | BmProcessContextStart — `\Device\Mup\...` registered | — |
| 34349 | BmOpenProcess — cmd.exe → curnxc1.exe, WasHardened=False | — |
| 34811 | StreamScan Start — lsass.dmp (Reason=2, on-write) | — |
| 34822 | StreamScan Stop — 11ms | No action observed |
| 34850 | USN Cache MISS × 2 — `\\192.168.1.218\share\curnxc1.exe` | — |
| 34851 | ScanRequestTask Start — processmemoryscan pid:7728 | — |
| 34881 | ScanRequestTask Stop — 29ms | No action observed |
| 34959 | StreamScan Start — lsass.dmp (Reason=5, on-close) | — |
| 36742 | Spynet SendReportStart | — |
| 37287 | Spynet SendReportComplete + HandleResponseComplete | No action observed |
| 37290 | StreamScan Stop — 2,331ms | No action observed |
| 69771 | BmProcessContextStop — PID 7728 terminated | No verdict attached |

---

## 5. What This Data Does and Does Not Show

### What is well-supported

- The Defender behavior monitor observed and tracked the full execution chain: mmc.exe → cmd.exe → `\Device\Mup\...\curnxc1.exe`
- The `\Device\Mup\` kernel UNC path representation is consistent across EID 4663, BmProcessContextStart, and StreamScanRequest — it is the kernel's canonical representation, not a logging artifact of any single subsystem
- A stream scan of the UNC binary occurred on execution (Reason=2), taking 38ms
- The behavior monitor triggered a runtime process memory scan (ScanSource=8), taking 29ms
- lsass.dmp was scanned on both write (11ms) and close (2,331ms)
- A MAPS interaction occurred temporally correlated with the dump file on-close scan
- No prevention or detection action is observable in any of the above events
- The execution context was closed at process termination with no deferred verdict

### What requires caution

- Absence of MOACLookup for the UNC binary does not prove no cloud reputation query occurred — it proves none was observed at this verbosity
- Absence of BmOpenProcess for LSASS does not prove the behavior monitor did not observe the handle acquisition
- "No action fields" strongly suggests no actionable detection but does not prove a clean verdict in the strictest sense — deferred or cloud-side decisions are not captured here
- WasHardened=False does not prove ASR rules would not block under a different configuration
- The Spynet report content is unknown — behavioral telemetry may or may not have included execution-specific context

### What remains open

- Whether ASR "Block credential stealing from LSASS" in Block mode would intervene — requires direct testing
- Whether MDE's behavioral analytics layer would generate an alert from the Spynet telemetry — separate from AV prevention
- The content and classification of the Spynet report
- Whether post-execution cloud re-evaluation assigned a verdict outside this trace window

### Negative finding synthesis

Notably absent from the trace are observable prevention actions, signature or classification events, and post-execution verdict transitions within the capture window. Absence of evidence is not evidence of absence — deferred verdicts, cloud-side decisions, and events below the provider verbosity ceiling are not captured here. Within those constraints, however, no telemetry surface in this dataset showed an actionable detection during the observed execution window. The research question was not whether the technique would eventually be detected, but what the engine observably did during execution. The answer from this dataset: every major scan path fired; none produced an observable action.

---

## 6. The Telemetry Ceiling

The finding that most directly informs defensive architecture is not any individual event — it is the access denial on `Microsoft-Windows-Threat-Intelligence`.

The events documented above are what the `Microsoft-Antimalware-Engine` provider surfaced: the engine's internal evaluation steps. What is not present is the kernel callback layer — what the OS observed before any evaluation logic ran, the raw PROCESS_VM_READ callback at the kernel boundary, the memory region access patterns.

Based on the observed access controls around `Microsoft-Windows-Threat-Intelligence`, direct observation of that lower-layer telemetry required PPL Anti-Malware level in this test scenario. In practice that means EDR vendors with co-signed kernel drivers. The implication for blue teams is structural: the telemetry available to a defender running best-practice Sysmon + audit policy + SIEM is not a subset of EDR telemetry due to configuration choices. It is a subset due to architectural enforcement. The gap is not closable by tuning.

The practical ceiling for non-EDR defensive visibility in this scenario:
- EID 4663 (security audit — PROCESS_VM_READ, `\Device\Mup\` path)
- Sysmon EID 1 (zeroed IMPHASH, UNC image path, absent PE metadata)
- `Microsoft-Antimalware-Engine` events (stream scan, memory scan, process context)

Everything below that — the kernel callback sequence, the raw THREATINT events, the pre-verdict observation layer — was not accessible in this test scenario without PPL-level access.

---

## 7. Scope and Validity Constraints

- Single target: Server 2019 Build 17763.8644, Defender AV only, no MDE, no WDAC
- `SubmitSamplesConsent=0` — non-default; suppresses sample upload, does not prevent all cloud communication
- Trace captured via `wpr -start GeneralProfile` — does not enable `Microsoft-Windows-Threat-Intelligence` provider (PPL-gated)
- PerfView ETW data represents one execution run; non-deterministic engine behaviour is possible across runs
- Claims limited to what is observable in the captured event data; inferences stated explicitly as such

---

*Target: Windows Server 2019 Build 17763.8644 — lab2019.local PDC*  
*Defender AV: 1.451.93.0 / Engine: 1.1.26040.8*  
*Trace date: 26 May 2026*  
*Methodology: Operational assumption analysis — trust assumptions as attack surfaces*  
*External review incorporated: epistemic discipline feedback from independent reviewers*
