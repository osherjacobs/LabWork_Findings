# KslKatz — Comparative Defender ETW Analysis
## Falsifying a Defender Signature Update Hypothesis

**Lab:** lab2019.local / badsuccessor.local  
**Date:** June 3, 2026  
**Tool:** [KslKatz](https://github.com/S1lky/KslKatz) — BYOVD credential extractor using Microsoft Defender's KslD.sys  
**Tracer:** PerfView (Microsoft-Antimalware-Engine ETW provider)

---

## Background

During KslKatz lab validation across multiple Windows Server versions and patch levels (documented in the main KslKatz writeup), a post-run Defender signature update (1.449.x → 1.451.245.0) coincided with a credential extraction failure on WIN-ATTACK (Server 2022, Build 20348, UBR 587).

The failure mode was specific: the BYOVD primitive executed cleanly, the driver loaded, LSA encryption keys were found — but `LogonSessionList not found` terminated the chain before credential extraction.

The initial hypothesis was that the signature update had caused the failure. This writeup documents the ETW trace analysis, the falsification methodology used to test that hypothesis, and the subsequent source-level investigation that identified the actual root cause.

---

## Test Configuration

| Host | OS | Build | UBR | Sig Version | Binary | Outcome |
|------|----|-------|-----|-------------|--------|---------|
| WIN-ATTACK | Server 2022 Standard Eval | 20348 | 587 | 1.451.245.0 | flot.exe (MorphKatz-mutated) | ❌ LogonSessionList not found |
| WIN-JOCP945SK51 | Server 2019 Standard Eval | 17763 | 8755 | 1.451.245.0 | pkd2.exe | ✅ 5 MSV1_0 credentials extracted |

Both runs captured with identical PerfView collection parameters:

```
PerfView collect <output>.etl /NoGui /KernelEvents=Default /ClrEvents:None
  /Providers="Microsoft-Antimalware-Engine,Microsoft-Windows-Kernel-General"
  /CircularMB:256
```

---

## Falsification Methodology

The initial attribution — sig update caused extraction failure — was challenged on two grounds before running the control.

**Ground 1: Sig updates don't modify lsasrv.dll**

KslKatz uses a GhostKatz-style pattern scan against lsasrv.dll on disk to locate `LogonSessionList` via RIP-relative displacement. The binary layout of lsasrv.dll is determined by OS patch level (UBR), not Defender signature version. A sig update has no mechanism to alter lsasrv.dll struct offsets.

**Ground 2: A Defender detection would be expected to produce observable enforcement**

A detection event — quarantine, interruption, or detection telemetry — would be expected rather than a silent mid-chain `LogonSessionList not found` failure after driver load and key discovery. The observed failure mode is structurally inconsistent with a detection event, which would have produced EID 1116/1117 and process termination before the chain progressed.

**Falsification test:** Run pkd2.exe on WIN-JOCP945SK51 (Server 2019, UBR 8755) at sig version 1.451.245.0. If the sig update is the causal variable, extraction should fail there too. If extraction succeeds, the sig update is not the cause.

**Result:** Extraction succeeded on Server 2019 at identical sig version.

The sig update hypothesis was testable, tested, and rejected.

---

## ETW Trace Analysis — Comparative

### Execution Timeline (both hosts)

Both traces show an identical Defender decision sequence:

| Event | WIN-ATTACK (ms) | WIN-JOCP945SK51 (ms) |
|-------|----------------|----------------------|
| BmProcessCreate (binary) | 21,972 | 18,245 |
| processmemoryscan Start | 22,467 | 18,745 |
| processmemoryscan Stop | 22,481 (13.9ms) | 18,759 (13.6ms) |
| LsassPEDrop.A!rsm fired | 22,123 | 18,289 |
| AcroDrop fired | 22,123 | 18,290 |
| PSCodeInjector.A fired | 22,682 (Result=1) | 19,135 (Result=1) |
| ServiceBinModifier.B fired | 24,139 | 20,312 |
| services.exe IsKnownFriendly | 24,139 | 20,312 |
| vKslD.sys trusted (DigitalSignature) | 24,146 | 20,317 |
| BmDriverLoad — vKslD.sys | 24,144 | 20,314 |

### Defender Behaviour: No Material Differences Observed

All behavioral signatures fired on both hosts. All returned Result=0 (no enforcement action) with the exception of `PSCodeInjector.A`, which returned Result=1 on both hosts but produced no downstream enforcement in either run.

The process memory scan completed in under 14ms on both hosts with no action. The vulnerable driver loaded on both hosts after passing a DigitalSignature trust check. `services.exe` was confirmed IsKnownFriendly on both.

No material ETW differences were observed between the two runs.

### Key Observation: vKslD.sys Trust Path

On both hosts, Defender evaluated vKslD.sys trust as:

```
IsTrusted - CI/EA: 0, ValidateTrust: 1 (1), FromCache: 0, FromSR: 0, Catalog: 0
→ trusted - DigitalSignature
```

This is the BYOVD trust path operating as designed. The driver carries a valid Microsoft digital signature, and in both observed runs Defender's trust evaluation allowed the load despite the exposed IOCTL surface.

### PSCodeInjector.A — Result=1 With No Enforcement

Both traces recorded `Behavior:Win32/PSCodeInjector.A` with Result=1, but no observable enforcement action followed in either run. Similar patterns were observed in prior ETW analysis from this series, where internal behavioral classification occurred without downstream quarantine or interruption.

---

## MOAC Cache Analysis

Following ETW comparison, the WIN-ATTACK trace was examined for MOAC (Microsoft Online Antimalware Catalog) cache events — specifically `MOACLookup`, `MOACAdd`, and `MOACRevoke` — to test whether a cache hit from a prior run had altered engine behaviour around the flot.exe execution path.

**Hypothesis under test:** A MOAC cache entry from a prior execution on WIN-ATTACK may have influenced MsMpEng's IOCTL interception path without producing a visible detection event.

**Findings:**

All flot.exe MOACLookup events returned `Result=32,770` — a cache miss, meaning no prior MOAC entry existed. Full scan proceeded normally. vKslD.sys also cache-missed (32,770), was scanned, passed, and a MOACAdd entry was written (Result=0, SigSeq `0x000017702964D645`). Defender's own KslD.sys returned `Result=32,769` (known-clean fast path), as expected.

| File | MOAC Result | Meaning |
|------|-------------|---------|
| flot.exe | 32,770 (0x8002) | Cache miss — full scan |
| vKslD.sys (deployed) | 32,770 (0x8002) | Cache miss — full scan, passed |
| KslD.sys (Defender copy) | 32,769 (0x8001) | Cache hit — known clean |

No MOACRevoke events were observed for either file in the execution window.

**Conclusion:** MOAC had no bearing on the failure. The cache layer operated normally on WIN-ATTACK — flot.exe was a clean miss, scanned without enforcement. MOAC hypothesis falsified.

---

## Continued Investigation — Source-Level Root Cause

With Defender, MOAC, and sig update all ruled out, investigation shifted to the runtime state of WIN-ATTACK itself.

### Eliminating Environmental Variables

The following were confirmed identical or ruled out as causal:

- **lsasrv.dll on disk:** SHA256 hash confirmed unchanged. File dated March 2022, version 10.0.20348.469. Not present separately in WinSxS.
- **MorphKatz mutation:** Zero code patches applied across all variants (`Applied 0 patches`). Only data-morph (EP thunk + `.morph` section). Logic in lsa.cpp untouched.
- **Hotpatch:** No `Microsoft-Windows-Hotpatch` ETW events. Hypothesis eliminated.
- **Logon state:** Type 7 (unlock) logon confirmed via Security log EID 4624 at 5:36:22 AM. MSV1_0 confirmed as active authentication package. Lock/unlock performed and confirmed before re-run. Extraction still failed.

The machine had rebooted at 3:55 AM (confirmed via System log EID 20). The successful run two days prior was on a machine that had been running continuously with active sessions.

### Instrumentation

Debug output was added to `find_logon_list` in `lsa.cpp` to print the resolved pointer and validation result before the MmCopyMemory read:

```cpp
std::cout << std::format("  [DBG] sig min_build={} pattern_match_off=0x{:x}\n",
                         sig.min_build, sig_off);
// ... after resolution:
std::cout << std::format("  [DBG] fe_rva=0x{:x} list_ptr=0x{:x} head=0x{:x} match={}\n",
                         fe_rva, list_ptr, head,
                         (head && head != list_ptr) ? "YES" : "NO");
```

### Debug Output (WIN-ATTACK, post-fix build)

```
[*] Finding LogonSessionList...
  [DBG] sig min_build=20348 pattern_match_off=0x54fe5
  [DBG] fe_rva=0x163f90 list_ptr=0x7ffdcca73f90 head=0x7ffdcca73f90 match=NO
[-] MSV1_0 phase: LogonSessionList not found
```

The pattern matched at offset `0x54fe5`. The RIP-relative displacement resolved correctly to `fe_rva=0x163f90`. The runtime VA `list_ptr=0x7ffdcca73f90` is within the lsasrv.dll mapped range (`0x7ffdcc910000`–`0x7ffdcca7d000`). Everything resolved correctly.

But `head == list_ptr` — and the validation check rejected it.

---

## Root Cause

### What LogonSessionList Actually Is

Windows keeps credentials in a data structure called `LogonSessionList` inside lsasrv.dll. Think of it as a circular chain of links — each link is one logged-on user's session. When the chain is empty (no sessions yet), the last link points back to the first, which is itself. It's a closed loop with one node.

KslKatz finds this chain by scanning lsasrv.dll on disk, reading a set of known byte patterns, and computing where the chain starts in memory. It then checks whether the chain is real by asking: *does the first link point somewhere other than itself?*

The check in `lsa.cpp`:

```cpp
uint64_t head = read_ptr(h, dtb, list_ptr);
if (head && head != list_ptr) {
    // success — walk the chain
}
```

In plain terms: "is the chain non-empty?" If yes, proceed. If the first link points back to itself, assume the scan failed and try the next pattern.

This is the bug. A self-referential list is not a failed scan — it is a correctly initialized empty list. Windows sets it up this way from boot. The check was intended to confirm the pointer is meaningful, but it accidentally rejects a valid structure that simply has no entries yet.

### Why It Worked Before

Two days prior, the machine had been running for an extended period with active logon sessions. `LogonSessionList` was populated — `head != list_ptr` was true — and the check passed.

After the reboot at 3:55 AM, lsass reinitialised `LogonSessionList` as an empty self-referential structure. Even after a lock/unlock (confirmed Type 7 logon at 5:36:22 AM), the check fired at a moment when the list appeared self-referential to the tool, or the timing of the credential write into the list versus the read was narrow enough to produce the same result.

### Why the Server 2019 DC Always Works

WIN-JOCP945SK51 is a domain controller. Domain controllers have persistent Kerberos and NTLM sessions from boot — machine account, SYSTEM, service accounts. `LogonSessionList` is never empty post-boot on a DC. The check `head != list_ptr` is always true. The bug never surfaces.

### The Fix

One character change in `lsa.cpp`:

```cpp
// Before — rejects valid empty list
if (head && head != list_ptr) {

// After — accepts any non-null pointer
if (head) {
```

The downstream credential walker handles an empty list correctly — it walks zero entries and returns nothing. The correct output for an empty list is zero credentials, not "LogonSessionList not found."

### Verification

After applying the fix, rebuilding, and running through MorphKatz with the same parameters:

```
[*] Finding LogonSessionList...
  [DBG] sig min_build=20348 pattern_match_off=0x54fe5
  [DBG] fe_rva=0x163f90 list_ptr=0x7ffdcca73f90 head=0x7ffdcca73f90 match=NO
[*] Extracting MSV1_0 credentials...
```

The `match=NO` line remains — the debug output still prints the old result — but execution now continues past it. Five credentials extracted:

```
WIN-ATTACK\Administrator   NT: 3c0***************************
LAB2019\WIN-ATTACK$        NT: e57***************************
Window Manager\DWM-1       NT: e57***************************
Font Driver Host\UMFD-0    NT: e57***************************
Font Driver Host\UMFD-1    NT: e57***************************
```

---

## Detection

The EID 13 registry IOC remains consistent and build-independent. Both hosts produced the characteristic two-event cluster on every execution:

```
HKLM\System\CurrentControlSet\Services\KslD\ImagePath
  Attack write:   System32\drivers\vKslD.sys (or KslD.sys)
  Restore write:  system32\drivers\wd\KslD.sys
```

KQL detection rule:

```kql
event.code:"13"
AND winlog.event_data.TargetObject:*KslD\ImagePath*
AND NOT winlog.event_data.Details:*drivers\\wd\\KslD.sys*
```

This rule fires on the attack write regardless of OS version, UBR, sig version, or extraction outcome. The registry modification is an operational requirement of the chain — it fires whether extraction succeeds or fails, and whether the list is empty or populated.

---

## Summary

| Hypothesis | Test | Result |
|------------|------|--------|
| Sig update (1.449 → 1.451.245.0) caused failure | Control run on Server 2019 at identical sig version | Falsified — extraction succeeded |
| Defender enforcement (silent detection) | ETW trace — no EID 1116/1117, no enforcement events | Falsified — identical decision path on both hosts |
| MOAC cache hit altered IOCTL path | MOACLookup events in execution window | Falsified — cache miss on flot.exe, normal scan path |
| Hotpatch modified lsasrv.dll in memory | Hotpatch ETW provider, file hash verification | Falsified — no hotpatch events, disk file unchanged |
| lsasrv.dll pattern coverage miss | Debug instrumentation of find_logon_list | Falsified — pattern matched, VA resolved correctly |
| Empty LIST_ENTRY rejected by head != list_ptr check | Source inspection + debug output | **Confirmed — root cause** |

The failure had nothing to do with Defender. A one-character validation check in KslKatz's `find_logon_list` function incorrectly treated a valid empty `LogonSessionList` as a pattern scan failure. The bug is latent on any freshly booted non-DC Windows host and surfaces reliably post-reboot before sustained interactive session activity populates the list.

---

## Caveats

Findings reflect a single lab environment of VMs that are powered on and off regularly — neither host maintains long-term uptime. The Server 2019 DC is switched off daily. Its consistent extraction success is therefore not an uptime artifact. The more likely explanation is structural: a domain controller running AD DS populates `LogonSessionList` with machine account and service credentials during the boot sequence itself, before any interactive logon occurs. `LogonSessionList` is never self-referential by the time a tool could run against it. The bug surfaces on member servers and workstations where no such boot-time credential population occurs and the list remains empty until an interactive session is established.

The fix (`head && head != list_ptr` → `head`) should be validated across additional builds and session states before treating it as universally correct. The downstream credential walker must handle a self-referential list without looping — the existing `seen` set guard in `extract_creds` covers this.
