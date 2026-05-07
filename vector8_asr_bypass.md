# Vector 8 — ASR Rule 9e6c4e1f Bypass via Pure NTAPI LSASS Dump

## Environment

- **Target:** WIN-52H4TKKPD9C (Windows Server 2025, 24H2)
- **Build:** 26100.32690
- **Defender Signatures:** 1.449.490.0 (updated 2026-05-07)
- **RTP:** Enabled
- **ASR Rule:** `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` — Block mode (action=1)

## On Source and Tooling

This document is a detection and telemetry record. No source code, compiled tooling, or operational instructions are published alongside it. The technique is documented to the degree necessary to understand the detection surface — not to enable reproduction. Screenshots are provided as evidence of findings. The binary described here will not be shared.


## Technique

Custom C# tool. Pure NTAPI memory walk. Minidump assembled in memory. No MiniDumpWriteDump. No dbghelp.dll. No comsvcs. Streamed over TCP to attacker machine. Nothing written to disk.

The approach operates below the level of standard user-mode hooks. By avoiding MiniDumpWriteDump and dbghelp.dll entirely, the technique bypasses the API-level patterns that many host-based controls pattern-match against. Whether ASR rule 9e6c4e1f specifically looks for these call patterns or uses a different detection mechanism is not yet determined — but the result is the same: no telemetry, no block.

By assembling the minidump in heap memory and streaming directly over TCP, no file object is created on the target. This eliminates the filesystem filter driver trigger that catches traditional credential dumpers at the write stage.

## Execution Contexts Tested

### Remote
Execution via scheduled task (goexec/tsch) from attacker machine.  
Total operation time: ~200ms.  
Nothing written to disk on target.

### Local
Same tool executed directly on target machine (curpipe.exe from C:\Windows\Tasks).

**Execution output:**
- SeDebugPrivilege: enabled
- LSASS PID: 900
- Handle: 0x744
- Regions walked: 665 — 59,252,736 bytes in 23ms
- Dump built: 59,279,096 bytes in 47ms
- Sent to attacker: 45ms
- **Total: 115ms**

ASR rule confirmed active immediately prior to execution via Get-MpPreference (action=1).

## Result

Full LSASS credential extraction succeeded in both execution contexts.

- NT hash: extracted
- SHA1: extracted
- DPAPI master key: extracted
- Kerberos material: extracted

## ASR Telemetry

Post-execution query against Microsoft-Windows-Windows Defender/Operational:

- EID 1121 (block): none
- EID 1122 (audit): none
- EID 1131: none
- EID 1132: none

Rule confirmed active via Get-MpPreference immediately after execution in both cases.

## Observations

Both remote and local execution contexts bypass ASR rule `9e6c4e1f` without triggering any telemetry. The bypass does not appear to be execution-context dependent — suggesting the rule logic is not parent-process aware in a way that would differentiate these scenarios.

This is a single test against a single technique in a controlled lab environment. No conclusions are drawn about the general effectiveness of ASR rules or Defender.

The finding is narrow: this specific technique, in this configuration, at this patch level, produced no ASR telemetry and was not blocked in either execution context.

Whether this reflects a gap in rule coverage, a detection logic limitation, or a configuration dependency is not yet determined. Further research is indicated.

## Detection Indicators for Defenders

ASR and standard Defender signatures failed to detect this technique. Defenders should consider behavioral indicators:

- **Sysmon EID 10** — Process access events where TargetImage is lsass.exe and GrantedAccess includes 0x1410 or 0x1010, particularly where the call stack origin is unexpected or unknown.
- **Network anomaly** — Any process communicating over non-standard ports with an unusually high data-to-time ratio. ~60MB transmitted in under 200ms is a clear outlier worth flagging regardless of destination.
- **NtReadVirtualMemory call patterns** — ETW-based telemetry targeting direct NTAPI calls to LSASS address space, pre-correlated with network egress events in the same process lifetime.

Pre-correlated detection across process access, memory read, and network egress is required. In most environments that correlation does not happen within the sub-second window this technique operates in.

## Credential Guard Note

Credential Guard, where enabled and correctly configured, provides meaningful mitigation against LSASS credential extraction — specifically for the material it protects (NT hashes, TGTs in certain configurations).

However, two caveats apply:

1. **Coverage is not universal.** Not all credential material is protected. DPAPI master keys and certain Kerberos artifacts may remain accessible depending on configuration.

2. **Credential Guard itself has documented bypass paths.** SpecterOps research (October 2025) demonstrated that Credential Guard can be circumvented under specific conditions. This limits its value as a standalone control.

Neither observation is a reason to avoid enabling Credential Guard — it raises the bar meaningfully. But it reinforces the core finding: no single control can be assumed to hold unconditionally.

Layered defenses remain the correct posture. Further research is indicated across all of these boundaries.

## ELK/Sysmon Telemetry

While ASR produced no telemetry, a pre-instrumented Sysmon/ELK stack detected activity within the same execution window. 321 alerts fired against WIN-52H4TKKPD9C, all HIGH severity.

### Alerts fired

**Sysmon - Outbound Network Connection from Windows Tasks Binary** — 309 alerts (HIGH)  
Primary volume signal. An outbound TCP connection from a binary executing in C:\Windows\Tasks is anomalous by definition. This rule fired on the network egress component of the operation.

**Sysmon - Binary Execution from Windows Tasks** — 6 alerts (HIGH)  
Location-based detection. Any binary executing from C:\Windows\Tasks is flagged regardless of behavior. Rule is execution-path aware, not payload-aware.

**Sysmon - Unsigned Binary with Zeroed IMPHASH** — 5 alerts (MEDIUM)  
PE characteristic detection. curpipe.exe presents with IMPHASH=00000000000000000000000000000000 and Company="-" — indicators of a custom compiled binary with no publisher signature. This fires on binary properties, not on what the binary does.

**Sysmon - WMI Remote Process Execution** — 1 alert (HIGH)  
Delivery artifact. DismHost.exe spawned by WmiPrvSE.exe — a side effect of the goexec/tsch execution chain, not of the dump operation itself.

<img width="1920" height="916" alt="SIEM2" src="https://github.com/user-attachments/assets/9749e088-9240-40f5-a82c-c04f867a157b" />

<img width="1877" height="974" alt="SIEM" src="https://github.com/user-attachments/assets/48bcef0b-0107-4b4e-8987-382362da97aa" />


### Important caveat

None of these rules detected the credential theft itself. What fired was the delivery context, the execution path, and the binary's PE characteristics. The LSASS memory walk, the minidump assembly, and the credential exfiltration over TCP produced no dedicated alert.

An attacker delivering a signed binary with a valid IMPHASH from a less-monitored path would evade all four rules. The operation would remain invisible to both ASR and these behavioral detections.

This is the core finding: the technique is detectable — but only if the environment is instrumented for it, and only at the wrapper level. The credential material itself left the host without triggering a single dedicated alert.


## Open Questions

- **Microsoft Defender for Endpoint (MDE):** This test was conducted against vanilla Defender with ASR enabled. MDE's kernel-mode EDR sensor operates at a different layer and may detect this technique where ASR does not. This has not been tested and represents a significant open variable. Organizations relying on MDE rather than standalone Defender may have different visibility into this technique.
- **ASR detection mechanism:** Whether rule 9e6c4e1f pattern-matches specific API calls (MiniDumpWriteDump, dbghelp.dll) or uses a broader behavioral heuristic is not confirmed. The practical result is identical — no telemetry — but the underlying reason has implications for what variations of this technique would or would not trigger detection.
- **Higher patch levels:** Patch level context: Testing was conducted at the current highest UBR (26100.32690) as of 2026-05-07. Whether earlier patch levels exhibit different ASR behaviour is an open question but outside the scope of this test.

## Scope

Lab infrastructure, owned and operated by the researcher.

## References

- [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)

- ASR rule documentation: [Block credential stealing from the Windows local security authority subsystem](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)

- SpecterOps Credential Guard research: October 2025 https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/


<img width="1878" height="778" alt="AttackWithASRRUleCENSORED" src="https://github.com/user-attachments/assets/bbd5f7be-a95c-4796-b0bd-4454d06262d2" />

<img width="1009" height="423" alt="Dumps" src="https://github.com/user-attachments/assets/c179bad9-ba63-4d08-be98-471ed70889a5" />

<img width="1152" height="490" alt="CredsKVCFORENSICCENSORED" src="https://github.com/user-attachments/assets/ee0e16e4-c93c-4e0f-b8b0-e556c8a521bb" />

<img width="1205" height="717" alt="FROMWINDOWSMACHINE" src="https://github.com/user-attachments/assets/47127551-b555-44d4-b254-9cab1e1650a7" />

<img width="999" height="539" alt="DUMPDIRECTFROMWINDOWSMACHINE" src="https://github.com/user-attachments/assets/b198efa5-c588-4623-a5b1-2adbece8ce11" />

<img width="1850" height="649" alt="UBRRTPASR" src="https://github.com/user-attachments/assets/e0691b5c-80ef-4cd4-a489-dcde1e68d41a" />









