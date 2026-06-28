# Security Research

> **Observed system behavior → adversarial chaining → telemetry reality → defensive implication.**

Controlled offensive security research in enterprise-modeled lab environments.  
Attack path realism, defensive visibility, and control failure analysis — **not** tool tutorials.  
Documented chains with raw telemetry, detection gaps, and KQL.

**All testing performed exclusively on my own personal lab systems.**  
**Lab stack:** Windows Server 2019/2022/2025 · Kali · Sysmon 15.20 (SwiftOnSecurity) · Winlogbeat → Elasticsearch 8.x  
**All credentials and sensitive details sanitized.**

---

### Recent / Notable Findings (2026)

- **kslkatz ETW Analysis & Validation** — Deep dive into kslkatz behavior, ETW telemetry, and detection opportunities.
- **ETW Provider Blindness** (`etw_ps_blind.md`) — PowerShell ETW evasion vectors and visibility gaps.
- **Defender Reconciliation Loop** — Analysis of Defender’s internal state reconciliation behavior under attack.
- Ongoing LSASS boundary testing on Server 2025 (vector7b + pypykatz).
- Expanded ADCS, Kerberos CNAME relay, and DACL/Shadow Credentials research.

---

### Research Philosophy

This research strives to operate at the **no-patch boundary** — where Microsoft has made a deliberate architectural or compatibility decision that leaves an exploitable gap, and where no direct vendor remediation is expected under the current boundary classification.

Three classes of finding are in scope:

| Class                        | Description                                                                 | Detection Posture                          |
|-----------------------------|-----------------------------------------------------------------------------|--------------------------------------------|
| **Won't fix**               | Behavior is intentional. Breaking it would break enterprise workflows.     | Detection + architectural controls         |
| **Can't reasonably fix**    | Legacy protocols, enterprise dependency chains, backward compatibility.    | Exposure mapping + compensating controls   |
| **Will fix, not yet prioritized** | Timing, not philosophy. Patch is coming.                              | Detection for the pre-patch window         |

The research model is **operational assumption analysis**: identifying where the operational interpretation of a security control exceeds its actual guarantees.

> *"The operational interpretation of the protection exceeded the actual guarantees — and that gap is where the trust assumption became an attack surface."*

---

### Research Scope & Disclaimer

This repository focuses on **detection engineering** and Microsoft Defender / ETW telemetry behavior.  
All techniques use publicly documented Windows APIs. No custom tooling or binaries are provided.

---

## Credential Access — LSASS Vector Series

| Vector   | Target                  | Technique                                      | Status              |
|----------|-------------------------|------------------------------------------------|---------------------|
| vector4  | Server 2022             | MiniDumpWriteDump via dbghelp.dll              | ✅ Published        |
| vector5  | Server 2022             | LSASS + goexec/nxc delivery chain              | ✅ Published        |
| vector6  | Server 2022             | Exclusion path analysis (EID 5007)             | ✅ Published        |
| vector7  | Server 2025 (UBR 1)     | MiniDumpWriteDump, default config              | ✅ Published        |
| vector7b | Server 2025 (UBR 1742)  | Patch boundary + kslkatz / pypykatz testing    | ✅ Published        |

**Series Finding:** EID 5007 remains the highest-fidelity intervention point.

---

## Credential Access — Replication Path

- **DCSync / secretsdump** on fully patched Server 2025 (no LSASS interaction)
- **Derrida-DCSync** analysis

**Key Finding:** Memory protections are irrelevant to the replication protocol path.

---

## Credential Guard / Remote Credential Guard

- Vector 8 — CG/RCG abuse chains (ESC3 → DA → RCG abuse)

**Class:** Won't fix (within vendor design scope).

---

## ADCS Abuse

- ESC1, ESC3, ESC4, ESC8 chains
- ADCSync homelab analysis + tooling
- Sanitized attack paths and reference guides

---

## Kerberos & Delegation

- Unconstrained / Constrained / RBCD
- Kerberos CNAME Relay + EPA bypass
- Golden DMSA, SPN jacking, and related vectors

---

## Detection Engineering — Recurring High-Value Signals

| Event                        | Source                | Relevance |
|-----------------------------|-----------------------|---------|
| **EID 5007**                | Windows Security      | Defender exclusion changes (highest fidelity) |
| EID 5136                    | Directory Service     | Attribute / DACL / Shadow Credentials writes |
| EID 5145                    | Windows Security      | Admin share access |
| EID 4768 (PreAuthType 16)   | Kerberos              | PKINIT authentication |
| EID 10                      | Sysmon                | LSASS handle access |
| RemoteRegistry service start| System                | DCSync / replication abuse |
| Various ETW provider events | Microsoft-Windows-*   | PowerShell / process injection visibility |

---

## Lab Infrastructure & Setup Guides

- Full AD + ADCS + ELK lab build guides
- Sysmon configuration
- ESC1 / ESC8 specific setups

---

**Ongoing research.** New vectors and findings added as they are validated in telemetry.

**LinkedIn:** [Osher Jacobs](https://www.linkedin.com/in/osher-jacobs/)
