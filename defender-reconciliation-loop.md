# Defender Has a Mind of Its Own
## Registry Reconciliation and the Limits of Documented Controls
### Windows Server 2019 — Purple Team Lab Observation

**Platform:** Windows Server 2019 (DC01.lab2019.local)  
**Defender version:** 4.18.26020.6-0  
**SIEM:** ELK + Sysmon + Winlogbeat  
**Context:** Purple team research into Defender sample submission behavior

---

## Background

During research into Defender's sample submission controls, a registry key governing submission policy was modified via an elevated process. The change appeared to succeed — the value was confirmed via query. The documented behavior for that value was expected to take effect.

It did not.

Further investigation via Sysmon EID 13 telemetry revealed why.

---

## Observed Behavior

After each write to the submission policy registry value, `MsMpEng.exe` — the Defender engine process — wrote its own value to the same key within seconds. In multiple cases, this write differed from the value that had just been set.

The sequence repeated consistently across multiple write attempts within the same session. The pattern is not random. It is a reconciliation loop.

**What the telemetry shows:**

| Time | Process | Value Written |
|---|---|---|
| 14:16:12 | reg.exe (SYSTEM) | 0x3 |
| 14:16:23 | MsMpEng.exe | 0x0 |
| 14:16:40 | reg.exe (SYSTEM) | 0x0 |
| 14:16:44 | MsMpEng.exe | 0x1 |
| 14:16:47 | reg.exe (SYSTEM) | 0x0 |
| 14:16:51 | MsMpEng.exe | 0x0 |

MsMpEng is not simply blocking writes — it is making its own writes, to its own value, from its own internal state. The registry is a surface it reads and corrects. It is not the authoritative configuration store.

---

## What This Means

Microsoft's documentation states that Tamper Protection is not active on Windows Server 2019 without Microsoft Defender for Endpoint integration and a management plane (Intune or ConfigMgr). That is technically accurate — the formal Tamper Protection feature is absent.

What is present is something else: an internal policy reconciliation mechanism inside MsMpEng that operates independently of the documented control surface. It does not appear in the Tamper Protection documentation because it is not Tamper Protection. It predates it, or sits alongside it, or is something different entirely.

The practical effect is similar. Registry writes to specific Defender policy values do not produce stable behavioral changes. The engine evaluates its own internal state and corrects the registry to match — not the other way around.

**The registry is a signal. MsMpEng is the source of truth.**

---

## Detection Implications

This behavior is fully visible in Sysmon EID 13 telemetry. Every write — by both the external process and MsMpEng — is logged with timestamp, process image, and value written.

A detection rule filtering EID 13 on the relevant Defender registry key path, excluding `MsMpEng.exe` as the writing process, produces a high-fidelity alert. MsMpEng writing that key is expected baseline behavior. Anything else writing it is not.

The telemetry gap is not in visibility — Sysmon captures it cleanly, tagged with the appropriate MITRE technique identifier by the Sysmon configuration. The gap is in alerting: without a rule consuming that telemetry, the write goes unnoticed.

**KQL for the detection rule:**

```kql
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "13" AND
winlog.event_data.TargetObject: *Windows\ Defender*Spynet* AND
NOT winlog.event_data.Image: *MsMpEng*
```

This fires on any external process modifying Defender's SpyNet policy values. In normal operations, nothing external writes there. The signal-to-noise ratio is high.

---

## Lab Practitioner Note

If you are maintaining a research environment on Windows Server 2019 and finding that Defender configuration changes do not produce stable behavioral changes — this is likely why. The documented control surface is not the complete picture.

The engine has internal state. The registry reflects part of it. Writing the registry changes the reflection, not necessarily the state.

This has practical implications for lab stability: configuration changes that appear to succeed may not persist in terms of behavioral effect. Verify behavior, not just registry values.

---

## What Remains Open

- Whether this reconciliation behavior is version-specific to the Defender platform version tested (4.18.26020.6-0)
- Whether the internal state can be influenced through a management plane rather than direct registry writes
- Whether the same behavior is present on Windows 10/11 endpoints or is specific to the Server SKU

These are questions for further research. The observation is documented. The telemetry supports it.

---

## Remaining Detection Gap

The rule above closes the alerting gap for external writes. It does not close the upstream gap: an attacker who reaches the point of modifying Defender policy already has SYSTEM on a domain controller. That is the problem the detection is built on top of.

Fix the credential problem first. The detection is the safety net, not the solution.

---

*Lab environment. Windows Server 2019, no MDE, no Intune, standalone domain.*  
*Sysmon + Winlogbeat + ELK. All findings based on observed telemetry.*
