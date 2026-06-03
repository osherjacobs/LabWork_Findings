<img width="1907" height="932" alt="nameditdidnothing2022" src="https://github.com/user-attachments/assets/af9da242-99fd-4233-954a-3b1769fc788c" />


# KslKatz — Defender ETW Telemetry Analysis
## Microsoft-Antimalware-Engine Provider: Two-Host Comparative

**Lab:** lab2019.local / badsuccessor.local  
**Date:** June 3, 2026  
**Tool:** [KslKatz](https://github.com/S1lky/KslKatz) — BYOVD credential extractor using Microsoft Defender's KslD.sys  
**Tracer:** PerfView (Microsoft-Antimalware-Engine ETW provider)

---

## Background

Following the OS matrix validation documented in the main KslKatz writeup, the focus here shifts to Defender's internal telemetry — what does the engine actually observe and decide when KslKatz executes, and does that picture differ across OS versions?

Two hosts were traced: WIN-ATTACK (Server 2022, UBR 587) and WIN-JOCP945SK51 (Server 2019, UBR 8755). Both ran at identical Defender signature versions. The Microsoft-Antimalware-Engine ETW provider was used via PerfView to capture the engine decision stream — behavioral classification events, MOAC cache lookups, driver trust evaluation, and process memory scan activity.

During this analysis an anomaly emerged: the same binary that had previously extracted credentials on WIN-ATTACK stopped working. A Defender sig update had occurred between runs, making it an obvious initial hypothesis. That hypothesis was tested and falsified. A subsequent source-level investigation identified a latent tool bug as a contributing factor — but the underlying trigger for why it surfaced on this specific run remains uncharacterised. Both the telemetry story and the anomaly are documented here, in that order.

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

### No Material Differences Observed

All behavioral signatures fired on both hosts. All returned Result=0 (no enforcement action) with the exception of `PSCodeInjector.A`, which returned Result=1 on both hosts but produced no downstream enforcement in either run.

The process memory scan completed in under 14ms on both hosts with no action. The vulnerable driver loaded on both hosts after passing a DigitalSignature trust check. `services.exe` was confirmed IsKnownFriendly on both.

From a Defender telemetry perspective, these two runs are indistinguishable. No material differences were observable in the Defender ETW decision stream. Same classifications, same trust evaluation, same outcome — no enforcement on either host.

### vKslD.sys Trust Path

On both hosts, Defender evaluated vKslD.sys trust as:

```
IsTrusted - CI/EA: 0, ValidateTrust: 1 (1), FromCache: 0, FromSR: 0, Catalog: 0
→ trusted - DigitalSignature
```

The driver carries a valid Microsoft digital signature. In both runs Defender's trust evaluation allowed the load without friction despite the exposed IOCTL surface. This is the BYOVD trust path working as the attacker intends — the signature is the bypass.

### PSCodeInjector.A — Classification Without Enforcement

Both traces recorded `Behavior:Win32/PSCodeInjector.A` with Result=1. No enforcement followed on either host. This is consistent with prior ETW analysis in this series — internal behavioral classification does not reliably map to user-visible enforcement. Result=1 here appears to indicate the rule fired but enforcement was gated by a downstream policy or confidence threshold that was not met.

---

## MOAC Cache Analysis

The WIN-ATTACK trace was examined for MOAC (Microsoft Online Antimalware Catalog) cache events — `MOACLookup`, `MOACAdd`, and `MOACRevoke` — to determine whether prior execution history on this host had influenced the engine's handling of flot.exe.

**Findings:**

All flot.exe MOACLookup events returned `Result=32,770` — a cache miss. No prior MOAC entry existed for this binary. Full scan proceeded normally. vKslD.sys also cache-missed, was scanned, passed, and a MOACAdd entry was written (SigSeq `0x000017702964D645`). Defender's own KslD.sys returned `Result=32,769` (known-clean fast path).

| File | MOAC Result | Meaning |
|------|-------------|---------|
| flot.exe | 32,770 (0x8002) | Cache miss — full scan |
| vKslD.sys (deployed) | 32,770 (0x8002) | Cache miss — full scan, passed |
| KslD.sys (Defender copy) | 32,769 (0x8001) | Cache hit — known clean |

No MOACRevoke events were observed for either file in the execution window. The cache layer had no influence on this run.

---

## The Anomaly — WIN-ATTACK Extraction Failure

With the telemetry picture established, the extraction failure on WIN-ATTACK is addressed separately. It is not a Defender story.

### Initial Hypothesis: Sig Update

A Defender signature update (1.449.x → 1.451.245.0) had occurred between the successful run two days prior and this run. The coincidence made it an obvious first candidate.

Two grounds for scepticism before running the control:

**Ground 1:** KslKatz resolves `LogonSessionList` by scanning lsasrv.dll on disk. The binary layout of lsasrv.dll is UBR-determined, not sig-determined. A sig update has no mechanism to alter struct offsets in lsasrv.dll.

**Ground 2:** A Defender detection would produce EID 1116/1117 and process termination — not a silent `LogonSessionList not found` after driver load and key extraction had already succeeded.

**Control test:** Run pkd2.exe on WIN-JOCP945SK51 at the same sig version 1.451.245.0. Extraction succeeded. Sig update hypothesis falsified.

### Subsequent Investigation

With Defender ruled out, the following were checked and eliminated:

- **lsasrv.dll on disk:** SHA256 confirmed unchanged. File dated March 2022, version 10.0.20348.469.
- **MorphKatz mutation:** Zero code patches applied. Only data-morph (EP thunk + `.morph` section). Logic untouched across all five variants.
- **Hotpatch:** No `Microsoft-Windows-Hotpatch` ETW events. File unchanged on disk.
- **Logon state:** Machine had rebooted at 3:55 AM. Type 7 unlock logon confirmed via EID 4624 at 5:36:22 AM. MSV1_0 confirmed as active authentication package. Extraction still failed after confirmed unlock.

Debug instrumentation was added to `find_logon_list` in `lsa.cpp` to print the resolved pointer and validation result:

```
[*] Finding LogonSessionList...
  [DBG] sig min_build=20348 pattern_match_off=0x54fe5
  [DBG] fe_rva=0x163f90 list_ptr=0x7ffdcca73f90 head=0x7ffdcca73f90 match=NO
[-] MSV1_0 phase: LogonSessionList not found
```

The pattern matched. The RIP-relative displacement resolved correctly. The runtime VA `0x7ffdcca73f90` falls within the lsasrv.dll mapped range (`0x7ffdcc910000`–`0x7ffdcca7d000`). Everything resolved correctly.

But `head == list_ptr` — and the validation check rejected it.

### The Tool Bug

`find_logon_list` validates the resolved pointer with:

```cpp
if (head && head != list_ptr) {
    // walk the chain
}
```

`LogonSessionList` is a Windows LIST_ENTRY — a circular doubly-linked list. When empty, the head points back to itself. This is valid initialised state, not a failed scan. The check incorrectly treats a self-referential list as a pattern match failure and moves to the next signature. All signatures fail the same check. The function throws `LogonSessionList not found`.

The fix is one character:

```cpp
// Before
if (head && head != list_ptr) {

// After
if (head) {
```

After applying the fix, rebuilding, and running through MorphKatz:

```
[+] 5 credential(s):
  WIN-ATTACK\Administrator   NT: 3c0***************************
  LAB2019\WIN-ATTACK$        NT: e57***************************
  Window Manager\DWM-1       NT: e57***************************
  Font Driver Host\UMFD-0    NT: e57***************************
  Font Driver Host\UMFD-1    NT: e57***************************
```

### What Remains Unresolved

The bug explains the mechanism. It does not explain the trigger.

The same binary, the same machine, the same tool code — worked two days prior, failed on this run. The `head != list_ptr` check had always been there. Something in the runtime state of WIN-ATTACK made `LogonSessionList` self-referential at the moment of the scan when it had not been before.

The most likely candidate is lsass session state post-reboot: on a freshly booted non-DC machine, `LogonSessionList` may remain self-referential for longer than expected after interactive logon, particularly in a VM context where session initialisation timing differs from physical hardware. But this was not confirmed with controlled timing tests. The trigger is uncharacterised.

The Server 2019 DC is unaffected structurally — AD DS populates `LogonSessionList` with machine account and service credentials during the boot sequence itself, before any tool could run against it. The list is never self-referential post-boot on a domain controller regardless of uptime or VM power cycle frequency.

---

## Detection

The EID 13 registry IOC is consistent and build-independent. Both hosts produced the characteristic two-event cluster on every execution:

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

Fires on the attack write regardless of OS version, UBR, sig version, or extraction outcome. The registry modification is an operational requirement of the chain — it fires whether the extraction succeeds or fails, and whether the list is populated or empty.

---

## Summary

The primary finding from the ETW analysis is that Defender's internal decision path is identical across Server 2019 and Server 2022 at identical sig versions — same behavioral classifications, same trust evaluation, same non-enforcement. The telemetry does not differentiate between a successful and failed extraction run. From the engine's perspective, both runs look the same.

The anomaly that emerged during this analysis — extraction failing on a machine where it had previously worked — turned out to have nothing to do with Defender. A latent tool bug in `find_logon_list` incorrectly rejected a self-referential LIST_ENTRY state consistent with an empty or unpopulated `LogonSessionList`. The bug was fixed. The trigger for why it surfaced on this specific run remains uncharacterised.

| Variable | Finding |
|----------|---------|
| Defender sig version (1.449 → 1.451.245.0) | No effect — falsified by Server 2019 control |
| Defender engine behavior | Identical across both hosts — no material ETW differences |
| MOAC cache | Cache miss on both attack binaries — no influence |
| lsasrv.dll on disk | Unchanged — hash confirmed |
| Tool bug (`head != list_ptr`) | Confirmed as mechanism — trigger uncharacterised |

---

## Caveats

Both hosts are VMs powered on and off regularly. The Server 2019 DC is switched off daily. Uptime is not the explanatory variable for the DC's consistent success — boot-time credential population by AD DS is.

The `head` fix should be validated across additional builds and session states. The downstream credential walker handles a self-referential list without looping — the existing `seen` set guard in `extract_creds` covers this.

Findings reflect a single lab environment. Defender behaviour observed here is against Windows Defender only — MDE with advanced hunting or third-party EDR was not assessed.

Selected screenshots:

Perfview

<img width="1907" height="932" alt="2022Defenderscannoaction" src="https://github.com/user-attachments/assets/91fa3d66-8ce1-4b39-830a-27b8628997ad" />

<img width="1907" height="932" alt="nameditdidnothing2022" src="https://github.com/user-attachments/assets/e06b6433-23aa-418d-996c-e11540aa9843" />

<img width="1907" height="932" alt="genericmessagetask2022" src="https://github.com/user-attachments/assets/43cd45dd-9fe4-467c-a514-705519c71d26" />

Driver load:

<img width="1907" height="932" alt="driverload2022" src="https://github.com/user-attachments/assets/fecb6605-887a-4e45-acac-e02255ca232f" />

Working on 01-06-2026

<img width="1593" height="937" alt="2022MORPHKATZEDGOTCREDSDEFENDERCAUGHTITBEFORE" src="https://github.com/user-attachments/assets/a1ed9c71-d3fe-4fd5-9e56-e7f9aa4a50af" />

Failing on 03-06-2026

<img width="1907" height="932" alt="flotexethatworked2daysagoonthismachneweird" src="https://github.com/user-attachments/assets/1b395927-8d46-45f8-9c67-709c68987b13" />

Code fix in lsa.cpp

<img width="1894" height="938" alt="codefixinlsacpp" src="https://github.com/user-attachments/assets/1a622710-29d3-48b7-86cf-7f466086befd" />

Succesful run 03-06-2026

<img width="1907" height="932" alt="succesfulrun03062026" src="https://github.com/user-attachments/assets/17eb4d7b-a5fd-4e72-9f78-676fdb5712f9" />









