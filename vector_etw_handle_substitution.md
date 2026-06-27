# ETW Handle Substitution — ScriptBlock Logging Suppression via Throwaway Provider

**Series:** Operational Assumption Analysis
**Environment:** Windows Server 2019 (17763.x) · Windows Server 2025 (26100.32690)
**Access:** Administrator session · low-privileged domain user with WinRM access (`Remote Management Users`)
**Defender RTP:** Enabled · **ScriptBlock logging:** Enabled (registry/GPO)
**Test date:** May 2026

# AD-Lab-Research Wiki

> Controlled offensive security research in enterprise-modeled Active Directory environments.  
> Focus: attack path realism, defensive telemetry, and control failure analysis — not tool tutorials.

---

## Table of Contents

1. [Lab Architecture](#lab-architecture)
2. [Research Methodology](#research-methodology)
3. [ADCS Exploitation (ESC Series)](#adcs-exploitation-esc-series)
4. [Kerberos Attack Chains](#kerberos-attack-chains)
5. [Windows Evasion](#windows-evasion)
6. [Detection Engineering](#detection-engineering)
7. [Setup Guides](#setup-guides)
8. [Files Reference](#files-reference)

---

## Lab Architecture

Two isolated AD lab environments built on VMware Workstation Pro (Ubuntu host, LUKS FDE):

### lab2019.local
| Host | Role | IP |
|---|---|---|
| DC01 | Domain Controller – Server 2019 | 192.168.1.x |
| WIN-ATTACK | Attacker workstation – Server 2022 | 192.168.1.x |
| ELK Stack | Log aggregation + Kibana | 192.168.1.250 |

---


## AMSI / ETW Divergence

A notable asymmetry emerged when comparing AMSI and ScriptBlock logging behavior.

Without separate AMSI evasion, AMSI blocked PowerShell content and Defender generated detection telemetry — but 4104 content visibility was already absent after ETW substitution.

This creates two distinct defender-facing conditions:

**Condition A:** AMSI fires. The detection exists. The ScriptBlock context that would normally accompany it does not.

**Condition B:** AMSI is subsequently bypassed. Post-substitution PowerShell content no longer appears in ScriptBlock logging.

In both conditions, `ActionSuccess: True` in Defender telemetry does not indicate chain disruption — it reflects the outcome of that specific detection event.

---

## Detection Surface

The technique is not silent. The setup chain remained observable in 4104 before telemetry loss occurred.

In tested sessions, 4104 captured reflection activity against ETW provider internals — provider discovery, reflective field access, and handle manipulation. Certain reflection operations surfaced at warning-level severity during AMSI scanning.

**What disappears after substitution:**
EID 4104 (ScriptBlock content), EID 4103 (module logging), post-substitution PowerShell content visibility.

**What does not disappear:**
Authentication telemetry (4624, 4776), process ancestry, network activity, LDAP activity, Sysmon process and network events.

This is not process invisibility, network invisibility, or a persistence mechanism.

---

## Operational Tradeoff

The technique introduced a detectable forensic artifact. The throwaway provider registration persisted in ETW provider enumeration and appeared anomalous absent explicit cleanup.

Operational tradeoff: reduced ScriptBlock content visibility in exchange for an anomalous provider-registration artifact.

---

## Scope

- Validated on Windows Server 2019 and Windows Server 2025 only
- ScriptBlock logging required explicit enablement (not default on tested builds)
- Tested against Defender AV; broader platform behavior may differ
- Reflective access constraints (WDAC, CLM, JEA) may alter feasibility
- No claim is made regarding PowerShell 7, MDE behavioral detections, alternate ETW consumers, or broader Windows build parity
- Claims are bounded to observed lab behavior

---

## Conclusion

The finding is not that ScriptBlock logging can be disabled.

The narrower observation is that a policy-enabled telemetry control may remain configured yet become operationally unreliable within a session boundary under tested conditions.

The defensive question is therefore not simply whether a control is configured, but whether telemetry continuity can be trusted at runtime and assumed to hold throughout uptime.
