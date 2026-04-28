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
All research was conducted exclusively on personal lab systems.

---

## Credential Access — LSASS Vector Series

| Vector   | Target                  | Technique                                      | Status              |
|----------|-------------------------|------------------------------------------------|---------------------|
| vector4  | Server 2022             | MiniDumpWriteDump via dbghelp.dll              | ✅ Published        |
| vector5  | Server 2022             | LSASS + goexec/nxc delivery chain              | ✅ Published        |
| vector6  | Server 2022             | Exclusion path analysis (EID 5007)             | ✅ Published        |
| vector7  | Server 2025 (UBR 1)     | MiniDumpWriteDump, default config              | ✅ Published        |
| vector7b | Server 2025 (UBR 1742)  | Patch boundary testing                         | 🔄 In progress      |

**Series Finding:**  
EID 5007 (Defender exclusion add/remove) is the highest-fidelity intervention point. Technique-level detection (including EID 10) is unreliable under live runtime enforcement.

---

## Credential Access — Replication Path

| Writeup              | Target                        | Technique                                              | Status       |
|----------------------|-------------------------------|--------------------------------------------------------|--------------|
| DCSync / secretsdump | Server 2025 (fully patched)   | impacket-secretsdump (DRSUAPI) — no LSASS interaction | ✅ Published |

**Key Finding:** Memory protections are irrelevant to the replication protocol path.

---

## ADCS Abuse

- ESC1 – SAN abuse + PKINIT
- ESC4 – Template misconfiguration
- ESC8 – NTLM relay + certificate theft
- Kerberos CNAME Relay → ESC8 → ESC1

---

## Kerberos & Delegation

- Unconstrained / Constrained / RBCD abuse chains
- Full ADCS + Kerberos attack path references

---

## Lab Infrastructure & Setup Guides

- Sysmon Configuration (SwiftOnSecurity + custom)
- AD + ADCS Lab Build Guide
- ESC1 / ESC8 Lab Setup Guides

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
> Defender often interacts with credential access — but the signal frequently does not follow the risk.

---

**Ongoing purple team research.** New vectors added periodically.

**LinkedIn:** [Osher Jacobs](https://www.linkedin.com/in/osher-jacobs/)
