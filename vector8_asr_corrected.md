# Vector 8 — LSASS Dump Against ASR Rule 9e6c4e1f on Server 2025

## Background

This vector extends the LSASS dump series (Vectors 5–7b) by testing the behaviour of ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` — "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" — against the same custom C# tool documented in the earlier vectors.

**Technique:** Pure NTAPI memory walk. Minidump assembled in memory. No MiniDumpWriteDump. No dbghelp.dll. No comsvcs. Streamed over TCP to attacker machine. Nothing written to disk.

---

## Environment

- **Target:** WIN-52H4TKKPD9C
- **OS:** Windows Server 2025 Datacenter
- **Version:** 24H2 (Build 26100.32690)
- **Defender Signatures:** 1.449.490.0 (updated 2026-05-07)
- **RTP:** Enabled
- **Domain:** WORKGROUP (standalone server, not domain-joined)
- **Virtualization-based Security:** Running — VBS active, Credential Guard not configured
- **Configuration:** VMware VM, 2x Intel Core, 4GB RAM

---

## Part 1 — Mistaken Finding (Documented for Transparency)

### What happened

During initial testing, the ASR rule was configured using an incorrect GUID:

```
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0  ← incorrect (b0)
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2  ← correct (b2)
```

Windows accepted the invalid GUID silently. Get-MpPreference reported it as active with action=1 (Block mode). No error was returned.

```powershell
AttackSurfaceReductionRules_Ids        AttackSurfaceReductionRules_Actions
-------------------------------        -----------------------------------
{9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0} {1}
```

Because the GUID did not correspond to a real rule, no enforcement occurred. The dump succeeded and full credential extraction was achieved. This was initially misread as an ASR bypass.

### Lesson

Windows does not validate ASR GUIDs on input. An invalid GUID is silently accepted and reported as configured. This is worth noting for anyone scripting ASR rule deployment — there is no native enforcement that the GUID corresponds to a real rule.

---

## Part 2 — Correct Testing

### ASR Rule Active (Correct GUID)

```powershell
AttackSurfaceReductionRules_Ids        AttackSurfaceReductionRules_Actions
-------------------------------        -----------------------------------
{9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2} {1}
```

### Result — Rule Blocks

With the correct GUID in Block mode, both local and remote execution produced a dump of **152 bytes** — an empty minidump shell with no LSASS memory content. Full credential extraction failed.

EID 1121 fired on both execution attempts:

```
Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.
ID: 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2
Path: C:\Windows\Tasks\curpipe.exe
Process Name: C:\Windows\System32\lsass.exe
```

**The rule works as documented.**

---

## Part 3 — ASR Folder Exclusion Bypass

### Technique

Same attack dependency as Vector 6 (Defender folder exclusion). With admin/SYSTEM access:

```powershell
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Windows\Tasks\curpipe.exe"
```

### Result — Full Dump Reinstated

Local execution (119ms):
- Regions walked: 670 — 59,236,352 bytes in 25ms
- Built: 59,262,792 bytes in 53ms
- Sent: 41ms
- **Total: 119ms**

Remote execution via scheduled task (~236ms):
- Full dump received on attacker machine
- NT hash, SHA1, DPAPI material — full extraction confirmed via KvcForensic

### ASR Telemetry

EID 5007 logged the exclusion addition:

```
Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event 
you should review the settings as this may be the result of malware.

New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\
ASR\ASROnlyExclusions\C:\Windows\Tasks\curpipe.exe = 0x0
```

EID 1121 block events also present from the pre-exclusion test runs, confirming the correct rule was active before the exclusion was added.

The signal exists. EID 5007 with `ASROnlyExclusions` in the registry path is an actionable detection primitive. Whether this event can be ingested and alerted on via a SIEM pipeline (Winlogbeat → ELK or equivalent) warrants further testing — it has not yet been validated end to end in this lab. If ingestible, a rule alerting on `ASROnlyExclusions` modifications would provide early warning of this bypass pattern.

---

---

## Part 3b — Impact Validation: Pass-the-Hash Against Domain Controller

The NT hash extracted from WIN-52H4TKKPD9C was validated via pass-the-hash 
against DC02 (192.168.1.4, badsuccessor.local) using nxc:


<img width="1875" height="547" alt="PTH" src="https://github.com/user-attachments/assets/4d7ef435-0b7a-40b6-be3f-99e50a0492ae" />


## Part 4 — ELK/Sysmon Telemetry

A pre-instrumented Sysmon/ELK stack was running throughout. With the outbound network connection rule suppressed (to reduce noise), two alerts fired against WIN-52H4TKKPD9C:

- **Sysmon - Binary Execution from Windows Tasks** — HIGH (risk score 73)
- **Sysmon - Unsigned Binary with Zeroed IMPHASH** — MEDIUM (risk score 50)

### Important caveat

Neither rule detected the credential theft itself. What fired was the execution path and the binary's PE characteristics — location and identity, not behaviour. The LSASS memory walk, minidump assembly, and TCP exfiltration produced no dedicated alert.

An attacker delivering a signed binary with a valid IMPHASH from a less-monitored path would evade both rules. The credential material would leave the host without triggering a single dedicated alert.

The unfiltered alert count for the full session was 321 HIGH severity alerts — dominated by outbound network connection events from a binary in C:\Windows\Tasks. This signal is real but noisy. A tuned analyst view suppressing that rule leaves only the execution-context signals above.

This illustrates a broader point: instrumentation matters, but so does what you instrument for and how you tune it.

---

## Detection Recommendations

- **Alert on EID 5007** — specifically targeting `ASROnlyExclusions` registry path modifications. The event text includes an explicit malware warning. Validate whether this event is captured by your SIEM pipeline.
- **Alert on EID 1121** — ASR block events against lsass.exe. If firing, something is attempting LSASS access and being blocked. Worth correlating with subsequent EID 5007 exclusion additions.
- **Correlate EID 5007 exclusion additions with subsequent LSASS access events** — the sequence is the attack chain.
- **Sysmon EID 10** — LSASS process access with GrantedAccess 0x1410 or 0x1010 remains a primary detection primitive regardless of ASR state.
- **Network anomaly** — outbound TCP from a binary in C:\Windows\Tasks with high data-to-time ratio (~60MB in under 200ms) is a clear outlier worth flagging.

---

## Credential Guard Note

Credential Guard, where enabled and correctly configured, provides meaningful mitigation against LSASS credential extraction for the material it protects.

Three caveats:

1. **Coverage is not universal.** DPAPI master keys and certain Kerberos artifacts may remain accessible depending on configuration.
2. **Documented bypass paths exist.** SpecterOps research (October 2025) demonstrated Credential Guard can be circumvented under specific conditions.
3. **Deployment friction is real.** Compatibility issues with smartcard drivers, PAM solutions, and backup agents mean some environments cannot enable it without breaking legitimate tooling.

Enabling Credential Guard raises the bar meaningfully. It is not a reason to skip it. But it is not an unconditional boundary.

**Note:** The target in this test is a standalone WORKGROUP machine. 
Credential Guard's primary protection — isolating domain credential material 
in the Virtual Secure Mode — does not apply in this configuration. 
The Credential Guard discussion in this writeup is included for completeness 
and applies to domain-joined environments where this technique would 
more typically be deployed.

---

## Open Questions

- **EID 5007 SIEM ingestion:** Whether EID 5007 ASR exclusion events are captured by standard Winlogbeat pipelines and alertable via ELK has not been validated in this lab. This is the next test.
- **Object access auditing (EID 4656/4663):** Not monitored during this test. If enabled, Windows security auditing may log LSASS handle access independently of ASR telemetry.
- **Microsoft Defender for Endpoint (MDE):** This test was conducted against vanilla Defender. MDE's kernel-mode EDR sensor operates at a different layer and may detect this technique where ASR does not. Not yet tested.
- **Tamper Protection:** If enabled, modification of ASR rules and exclusions via PowerShell is blocked. This test was conducted without Tamper Protection active.

---

## On Source and Tooling

This document is a detection and telemetry record. No source code, compiled tooling, or operational instructions are published. The technique is documented to the degree necessary to understand the detection surface — not to enable reproduction. Screenshots are provided as evidence. The binary will not be shared.

## Tooling Credit

Credential parsing in this vector was performed using **KvcForensic**, a memory forensics tool for parsing LSASS minidumps. KvcForensic successfully extracted NT hashes, SHA1, and DPAPI master keys from dumps produced in this lab environment where pypykatz failed due to struct offset mismatches introduced at higher Server 2025 UBR levels (documented in Vector 7b).

KvcForensic is the work of [wesmar](https://github.com/wesmar). Repository: [https://github.com/wesmar/KvcForensic](https://github.com/wesmar/KvcForensic).

---

## Scope

Lab infrastructure, owned and operated by the researcher.

---

## References

- [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)
- [ASR rule reference — Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [SpecterOps Credential Guard research — October 2025](https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/)

SCREENSHOTS

LOCAL EXECUTION WITH ASR FOLDER EXECUTION
<img width="1520" height="853" alt="LOCALWITHFOLDEREXCLUSIONRULE" src="https://github.com/user-attachments/assets/c0086987-d0ee-4a12-80bc-4a96ed80019d" />

REMOTE
<img width="1874" height="1013" alt="REMOTEWITHASREXCLUSION" src="https://github.com/user-attachments/assets/d4472baf-88c0-4b16-97f2-beb0cb05ce53" />

CREDENTIAL MATERIAL (Extracted with KvC Forensic)

<img width="1121" height="555" alt="KvcForesnsicCREDS" src="https://github.com/user-attachments/assets/cc50a489-d5be-4445-9b33-7be1d20d5fe6" />

PTH

<img width="1875" height="547" alt="PTH" src="https://github.com/user-attachments/assets/6a1e2d5c-0464-49dd-b17a-413d95c50731" />


LOCAL TELEMETRY

<img width="1867" height="948" alt="LocalTelemetry" src="https://github.com/user-attachments/assets/b29d6b4b-060e-414e-9fc8-c2026400ea0e" />

<img width="1867" height="940" alt="LocalTelemetry2" src="https://github.com/user-attachments/assets/d8871edd-895a-406e-a277-176e2d4307a7" />

SIEM ALERTS:

<img width="1877" height="962" alt="SIEMALERTS" src="https://github.com/user-attachments/assets/6a92e321-53b5-4106-b939-13f7d9e23250" />


