# Active Directory Security Research

> Controlled offensive security research in enterprise-modeled lab environments.
> Attack path realism, defensive visibility, and control failure analysis — not tool tutorials.
> Documented chains with raw telemetry, detection gaps, and KQL.

**Lab stack:** Windows Server 2019 / 2022 / 2025 · Kali · Sysmon 15.20 (SwiftOnSecurity) · Winlogbeat → Elasticsearch 8.x

> All credentials and network details sanitized for public documentation.

---

## Credential Access — LSASS Vector Series

| Vector | Target | Technique | Status |
|--------|--------|-----------|--------|
| vector4 | Server 2022 | MiniDumpWriteDump via dbghelp.dll | ✅ Published |
| vector5 | Server 2022 | LSASS + goexec/nxc delivery chain | ✅ Published |
| vector6 | Server 2022 | Exclusion path analysis (EID 5007) | ✅ Published |
| vector7 | Server 2025 (UBR 1) | MiniDumpWriteDump, default config | ✅ Published |
| vector7b | Server 2025 (UBR 1742) | Patch boundary — last build with reliable pypykatz extraction | ✅ Published |
| vector7c | Server 2025 | PPL (RunAsPPL=2) boundary analysis | 🔄 In progress |

**Series finding:** EID 5007 (Defender exclusion add/remove) is the highest-fidelity intervention point across all variants.
Technique-level detection is unreliable under live runtime enforcement. Absence of EID 10 is not evidence of absence.

---

## Credential Access — Replication Path

| Writeup | Target | Technique |
|---------|--------|-----------|
| ADCSYNC / DCSync | Server 2025 (fully patched, Defender on) | impacket-secretsdump DRSUAPI — no LSASS interaction |

**Finding:** Memory protections are irrelevant to the replication protocol path.
The patch that disrupts LSASS dump parsing does not affect DCSync.
Detection boundary: **RemoteRegistry service start** on the DC — not LSASS handle access.

---

## ADCS Abuse

| Writeup | Technique |
|---------|-----------|
| ESC1 | SAN abuse → certificate request → PKINIT → NT hash |
| ESC4 | Template misconfiguration → ESC1 pivot |
| ESC8 | NTLM relay → certsrv → certificate theft |
| Kerberos CNAME → ESC8 → ESC1 | CVE-2026-20929: ARP spoof → mitm6-cname → krbrelayx → DA |

---

## Kerberos & Delegation

- Kerberos attack chains (sanitized reference)
- ADCS attack paths reference guide
- ESC8 NTLM relay chain documentation

---

## Lab Infrastructure

| Document | Purpose |
|----------|---------|
| Sysmon Setup Guide | SwiftOnSecurity config, deployment notes |
| AD/ADCS Setup Guide | Domain + CA build for lab replication |
| ESC1 Lab Setup | Certificate template configuration |
| ESC8 Lab Setup | NTLM relay environment configuration |

---

## Detection Engineering — Recurring Signals

Across all vectors, technique-level detection is unreliable. The highest-confidence signals sit **upstream** of the technique itself — operator behavior, environmental dependencies, and service state changes.

| Event | Source | Relevance |
|-------|--------|-----------|
| EID 5007 | Windows Security | Defender exclusion add/remove — universal upstream signal across credential access vectors |
| EID 5136 | AD Audit | Attribute writes — Shadow Credentials, DACL modifications |
| EID 4768 PreAuthType 16 | Kerberos | PKINIT authentication — certificate-based logon |
| EID 10 | Sysmon | LSASS handle access — high confidence when present, non-deterministic under live enforcement |
| RemoteRegistry start | Windows Security | Earliest signal for replication path abuse |

> **Core thesis:** The control surface is not aligned to the risk surface.
> Defender interacts with credential access operations — and sometimes says nothing.
> Build detection on operator behavior, not technique invocation.

---

## Series Context

All research follows an **assumed breach** model:
remote shell → privilege escalation → credential extraction → lateral movement → domain compromise.

Each vector documents the full chain: execution path, Defender behavior, Sysmon telemetry, Kibana detection rules, and KQL.

---

*Ongoing purple team research series. New vectors published periodically.*
*LinkedIn writeups: [Osher Jacobs](https://www.linkedin.com/in/osher-jacobs/)*
