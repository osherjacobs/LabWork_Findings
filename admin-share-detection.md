# Admin Share Access Detection — Purple Team Lab
**EID 5145 | Winlogbeat | Elastic SIEM | Kali → DC01**

> Assume breach. Admin creds in hand. One SMB connection to C$. Does your stack see it?

---

## Lab Topology

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker | 192.168.1.218 |
| Windows Server 2019 (DC01) | Target / Domain Controller | 192.168.1.4 |
| Ubuntu 22.04 (Dell) | ELK Stack | 192.168.1.250 |

**Domain:** `lab2019.local`  
**Stack:** Elasticsearch + Kibana + Winlogbeat `8.19.12`  
**Sysmon:** v15.15 (olafhartong modular config)

---

## Attack

Simulated post-compromise admin share access using known credentials.

```bash
smbclient //192.168.1.4/C$ -U 'lab2019.local\Administrator%<password>'
```

```
smb: \> ls
smb: \> exit
```

No exploit. No lateral movement tool. Just SMB with valid creds — the most common post-compromise primitive that gets missed.

---

## Detection Prerequisites

### 1. Windows Audit Policy (DC)

```powershell
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
```

Both must show `Success and Failure`.

> Note: EID 5140/5145 are fired by the SMB subsystem — no SACL on C:\ required.

### 2. Winlogbeat Config (DC)

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 5140, 5145
  - name: System
    event_id: 7045
  - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["https://<ELK-IP>:9200"]
  username: "elastic"
  password: "<password>"
  ssl.verification_mode: none

setup.ilm.enabled: false
```

```powershell
cd "C:\Program Files\Winlogbeat"
.\winlogbeat.exe setup --index-management -e
Start-Service winlogbeat
```

### 3. Sysmon (DC)

v15.15 with olafhartong modular config. Relevant coverage for this scenario:

- **EID 3** — Network connection on port 445
- **EID 11** — File create under C:\
- **PipeEvent** — `\paexec`, `\psexecsvc`, `\csexecsvc` pipe names (psexec detection)

---

## IOCs Captured

### EID 5145 — Detailed File Share (share connect)

| Field | Value |
|---|---|
| `event.code` | `5145` |
| `winlog.event_data.ShareName` | `\\*\C$` |
| `winlog.event_data.ShareLocalPath` | `\\??\C:\` |
| `winlog.event_data.IpAddress` | `192.168.1.218` (Kali) |
| `winlog.event_data.IpPort` | `37512` |
| `winlog.event_data.SubjectUserName` | `Administrator` |
| `winlog.event_data.SubjectDomainName` | `LAB2019` |
| `winlog.event_data.AccessMask` | `0x80` (ReadAttributes — share connect) |
| `winlog.event_data.SubjectUserSid` | `S-1-5-21-3984567624-304424726-3877085034-500` |
| `winlog.keywords` | `Audit Success` |
| `host.name` | `DC01.lab2019.local` |

### EID 5145 — Detailed File Share (directory listing)

| Field | Value |
|---|---|
| `winlog.event_data.AccessMask` | `0x81` (ReadData + ReadAttributes — `ls`) |
| `winlog.event_data.RelativeTargetName` | `\` (root of C$) |

Two events per `smbclient` session:
- `0x80` = initial share connection
- `0x81` = directory listing (`ls`)

---

## Detection Rule (Kibana SIEM)

**Type:** Custom Query  
**Language:** KQL  
**Index:** `winlogbeat-*`

```kql
event.code: "5145" and winlog.event_data.ShareName: "\\\\*\\C$"
```

**Rule settings:**

| Setting | Value |
|---|---|
| Name | `Admin Share Access - C$ via SMB` |
| Severity | High |
| Risk Score | 73 |
| Runs every | 5 minutes |
| Look-back | 1 minute |

---

## Alert Output

```
Rule:     Admin Share Access - C$ via SMB
Severity: High
Score:    73
Host:     DC01.lab2019.local
Source:   192.168.1.218
Time:     Mar 19, 2026 @ 18:21:00
```

2 alerts fired — one per EID 5145 event (connect + list).

---

## Rooms Model Mapping

| Room | Asset |
|---|---|
| Foothold | Kali with valid admin creds |
| Rights over target | Administrator → C$ share (built-in admin share, no explicit permission needed) |
| What target provides | Full filesystem read access on DC |
| Credential utilization | NTLM auth over SMB (Type 3 logon — EID 4624) |

---

## Correlated Event Chain

```
EID 4624 (Type 3)     — Network logon from 192.168.1.218
EID 5140              — Share object accessed (C$)
EID 5145 (0x80)       — Share connect: ReadAttributes
EID 5145 (0x81)       — Directory listing: ReadData + ReadAttributes
```

Full correlation: logon + share access + access mask escalation from single source IP within seconds = high-confidence admin share access.

---

## Detection Gaps / Tuning Notes

- **False positives:** Legitimate admin tools, backup agents, and monitoring software also hit C$. Tune by excluding known-good source IPs or adding `winlog.event_data.SubjectUserName` whitelist.
- **Blind spot:** This rule fires on *any* C$ access — add `winlog.event_data.IpAddress` not in known admin subnets to reduce noise in production.
- **Extend to ADMIN$:** Add `winlog.event_data.ShareName: "\\\\*\\ADMIN$"` to the query to also catch psexec-style service binary drops.
- **Next layer:** Correlate EID 5145 → EID 4697 (service install) within 60 seconds from same source IP for psexec detection.

---

## References

- [Microsoft EID 5145](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)
- [Microsoft EID 5140](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140)
- [Elastic Winlogbeat docs](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)

---

*Lab environment. All testing performed on owned infrastructure.*
