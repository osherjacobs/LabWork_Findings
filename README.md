# Active Directory Security Research

> **Observed system behavior → adversarial chaining → telemetry reality → defensive implication.**

Controlled offensive security research in enterprise-modeled lab environments.  
Attack path realism, defensive visibility, and control failure analysis — **not** tool tutorials.  
Documented chains with raw telemetry, detection gaps, and KQL.

**All testing performed exclusively on my own personal lab systems.**  
**Lab stack:** Windows Server 2019/2022/2025 · Kali · Sysmon 15.20 (SwiftOnSecurity) · Winlogbeat → Elasticsearch 8.x  
**All credentials and sensitive details sanitized.**

---

### Research Philosophy

This research strives to operate at the **no-patch boundary** — where Microsoft has made a deliberate architectural or compatibility decision that leaves an exploitable gap, and where no direct vendor remediation is expected under the current boundary classification.

Three classes of finding are in scope:

| Class | Description | Detection Posture |
|---|---|---|
| **Won't fix** | Behavior is intentional. Breaking it would break enterprise workflows. Vendor may explicitly state "no security boundary violation." | Detection and architectural compensating controls are the primary mitigation path. No direct vendor remediation expected. |
| **Can't reasonably fix** | Legacy protocols, enterprise dependency chains, backward compatibility constraints. | Exposure mapping + compensating controls + detection in the residual gap. |
| **Will fix, not yet prioritized** | Timing, not philosophy. Patch is coming. | Detection logic that covers the window before the patch lands. |

The research model is **operational assumption analysis**: identifying where the operational interpretation of a security control exceeds its actual guarantees, and where trust assumptions quietly become attack surfaces.

Three surfaces are always in scope simultaneously:

- **Control surface** — what the vendor exposes, documents, and designs the protection to cover
- **Risk surface** — what an attacker can operationally construct from observed system behavior
- **Telemetry surface** — what defenders actually observe when the chain runs

The gap between these three surfaces is where the findings live. The goal is not to prove that controls are useless — it is to document precisely where they hold and where they don't, and to extract concrete detection logic from that delta.

> *"The operational interpretation of the protection exceeded the actual guarantees — and that gap is where the trust assumption became an attack surface."*

---

### Research Scope & Disclaimer

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
| vector7b | Server 2025 (UBR 1742)  | Patch boundary testing                         | ✅ Published        |

**Series Finding:**  
EID 5007 (Defender exclusion add/remove) is the highest-fidelity intervention point. Technique-level detection (including EID 10) is unreliable under live runtime enforcement.

---

## Credential Access — Replication Path

| Writeup              | Target                        | Technique                                              | Status       |
|----------------------|-------------------------------|--------------------------------------------------------|--------------|
| DCSync / secretsdump | Server 2025 (fully patched)   | impacket-secretsdump (DRSUAPI) — no LSASS interaction | ✅ Published |

**Key Finding:** Memory protections are irrelevant to the replication protocol path.

---

## Credential Guard / Remote Credential Guard

| Writeup | Target | Technique | Status |
|---|---|---|---|
| Vector 8 — CG/RCG abuse | Server 2022 + Win11 CG client | ESC3 → DA → DumpGuard RCG abuse → NTLMv1 → PTH | ✅ Published |

**Key Finding:** Credential Guard protects LSASS memory access from VTL0. It does not protect against authentication flow abuse via the Remote Credential Guard protocol — an independent RDP credential delegation mechanism that can leverage CG functionality where present. Zero LSASS alerts fired. Behavior confirmed within vendor design scope; no security boundary violation acknowledged.  
**Class:** Won't fix.

---

## ADCS Abuse

- ESC1 – SAN abuse + PKINIT
- ESC3 – Enrollment Agent abuse → DA certificate on behalf of Administrator
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
|-----------------------------|---------------------|-----------|
| **EID 5007**                | Windows Security    | Defender exclusion add/remove (strongest upstream signal) |
| EID 5136                    | Directory Service   | Attribute writes (Shadow Credentials, DACLs) |
| EID 5145                    | Windows Security    | Admin share access — file delivery/retrieval indicator |
| EID 4768 (PreAuthType 16)   | Kerberos            | PKINIT authentication |
| EID 10                      | Sysmon              | LSASS handle access (high confidence *when* it fires) |
| RemoteRegistry service start| System              | Replication / DCSync abuse |

> **Core Thesis:** The control surface is not aligned with the risk surface — and the telemetry surface frequently covers neither completely.  
> The signal often does not follow the risk. That gap is the research subject.

---

**Ongoing research.** New vectors added when findings are confirmed in telemetry.  
**LinkedIn:** [Osher Jacobs](https://www.linkedin.com/in/osher-jacobs/)
