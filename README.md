# Active Directory Security Research

> Controlled offensive security research in enterprise-modeled lab environments.  
> Attack path realism, defensive visibility, and control failure analysis — **not** tool tutorials.  
> Documented chains with raw telemetry, detection gaps, and KQL.

**All testing performed exclusively on my own personal lab systems.**

**Lab stack:** Windows Server 2019/2022/2025 · Kali · Sysmon 15.20 (SwiftOnSecurity) · Winlogbeat → Elasticsearch 8.x  
**All credentials and sensitive details sanitized.**

---

### **Research Scope & Disclaimer**

This repository focuses on **detection engineering** and Microsoft Defender telemetry behavior.  
All techniques use publicly documented Windows APIs. No custom tooling or binaries are provided.

---

## Credential Access — LSASS Vector Series

| Vector   | Target                  | Technique                                      | Status          | Writeup |
|----------|-------------------------|------------------------------------------------|-----------------|---------|
| vector4  | Server 2022             | MiniDumpWriteDump via dbghelp.dll              | ✅ Published    | [vector4-lsass-dump-detection.md](vector4-lsass-dump-detection.md) |
| vector5  | Server 2022             | LSASS + goexec/nxc delivery chain              | ✅ Published    | [vector5-lsass-goexec-pta.md](vector5-lsass-goexec-pta.md) |
| vector6  | Server 2022             | Exclusion path analysis (EID 5007)             | ✅ Published    | [vector6-lsass-exclusion-window.md](vector6-lsass-exclusion-window.md) |
| vector7  | Server 2025 (UBR 1)     | MiniDumpWriteDump, default config              | ✅ Published    | [vector7-lsass-dump-detection-boundary.md](vector7-lsass-dump-detection-boundary.md) |
| vector7b | Server 2025 (UBR 1742)  | Patch boundary — last build with reliable extraction | ✅ Published | [vector7b-lsass-server2025.md](vector7b-lsass-server2025.md) |
| vector7c | Server 2025             | PPL (RunAsPPL=2) boundary analysis             | 🔄 In progress  | — |

**Series Finding:**  
EID 5007 (Defender exclusion add/remove) is the highest-fidelity intervention point. Technique-level detection (including EID 10) is unreliable under live runtime enforcement.

---

## Credential Access — Replication Path

| Writeup              | Target                        | Technique                                              | Status       | Link |
|----------------------|-------------------------------|--------------------------------------------------------|--------------|------|
| DCSync / secretsdump | Server 2025 (fully patched)   | impacket-secretsdump (DRSUAPI) — no LSASS interaction | ✅ Published | [ADCSync_Writeup.md](ADCSync_Writeup.md) / [derrida-dcsync.md](derrida-dcsync.md) |

**Key Finding:** Memory protections are irrelevant to the replication protocol path.

---

## ADCS Abuse

| Writeup | Technique | Link |
|---------|-----------|------|
| ESC1    | SAN abuse → certificate request → PKINIT → NT hash | [ESC1_Lab_Setup.md](ESC1_Lab_Setup.md) + [adcs-esc-reference-guide.md](adcs-esc-reference-guide.md) |
| ESC4    | Template misconfiguration → ESC1 pivot | [esc4-dual-eku-gotcha.md](esc4-dual-eku-gotcha.md) |
| ESC8    | NTLM relay → certsrv → certificate theft | [esc8-ntlm-relay.md](esc8-ntlm-relay.md) |
| Kerberos CNAME → ESC8 → ESC1 | CVE-2026-20929 chain | [kerberos-cname-relay-lab.md](kerberos-cname-relay-lab.md) |

---

## Kerberos & Delegation

- [kerberos-attack-chains-sanitized.md](kerberos-attack-chains-sanitized.md)
- [adcs-attack-paths-sanitized.md](adcs-attack-paths-sanitized.md)
- [adcs-esc-reference-guide.md](adcs-esc-reference-guide.md)

---

## Lab Infrastructure & Setup Guides

| Document | Purpose | Link |
|----------|---------|------|
| Sysmon Setup Guide | SwiftOnSecurity config + deployment | [Sysmon_Setup_Guide.md](Sysmon_Setup_Guide.md) |
| AD + ADCS Lab Build | Domain + CA setup | [AD_ADCS_Setup_Guide.md](AD_ADCS_Setup_Guide.md) / [ad-lab-setup.md](ad-lab-setup.md) |
| ESC1 Lab Setup | Certificate template config | [ESC1_Lab_Setup.md](ESC1_Lab_Setup.md) |
| ESC8 Lab Setup | NTLM relay environment | [ESC8_Lab_Setup.md](ESC8_Lab_Setup.md) |

---

## Detection Engineering — Recurring High-Value Signals

| Event                        | Source              | Relevance |
|-----------------------------|---------------------|---------|
| **EID 5007**                | Windows Security    | Defender exclusion add/remove (strongest upstream signal) |
| EID 5136                    | Directory Service   | Attribute writes (Shadow Credentials, DACLs) |
| EID 4768 (PreAuthType 16)   | Kerberos            | PKINIT authentication |
| EID 10                      | Sysmon              | LSASS handle access (high confidence *when* it fires) |
| RemoteRegistry service start| System              | Replication / DCSync abuse |

> **Core Thesis:** The control surface is not aligned with the risk surface.

---

**Ongoing purple team research.** New vectors added periodically.

**LinkedIn:** [Osher Jacobs](https://linkedin.com/in/osher-jacobs/)
