# ETW Handle Substitution — ScriptBlock Logging Suppression via Throwaway Provider

**Series:** Operational Assumption Analysis
**Environment:** Windows Server 2019 (17763.x) · Windows Server 2025 (26100.32690)
**Access:** Administrator session · low-privileged domain user with WinRM access (`Remote Management Users`)
**Defender RTP:** Enabled · **ScriptBlock logging:** Enabled (registry/GPO)
**Test date:** May 2026

**Acknowledgment:** A public discussion with Adrian Cepero Corcho following earlier ETW provider-interference testing prompted exploration of handle substitution as a related direction. The testing, characterization, and telemetry analysis presented here reflect independent lab work under the conditions described.

---

## Finding

In tested environments, PowerShell ScriptBlock telemetry (EID 4104) ceased arriving after runtime handle substitution without disabling policy, modifying registry keys, nulling the ETW handle, or requiring elevated privileges.

The mechanism substitutes PowerShell's internal ETW provider registration handle with a valid handle belonging to a throwaway provider GUID that has no subscribed consumers.

The defensive gap is therefore not registry state — it is trust in runtime telemetry continuity.

This is not a telemetry invisibility primitive. Authentication, process, and network telemetry remained observable throughout.

---

## Operational Implication

Many environments treat ScriptBlock logging as binary:

> Policy enabled = PowerShell content visibility.

The tested environments demonstrated a weaker guarantee:

> Policy enabled ≠ telemetry integrity guaranteed throughout session lifetime.

The registry state remained unchanged. The logging policy remained enabled. No obvious runtime failure surfaced in-session. In tested sessions, post-substitution ScriptBlock content was not observed.

---

## Assumptions Tested

Two operational assumptions were evaluated. In tested environments, both proved weaker than commonly assumed.

1. ScriptBlock logging remains active for the duration of a policy-enabled session
2. AMSI blocking implies content visibility through 4104

---

## Mechanism

PowerShell's ETW pipeline routes through an internal provider object in `System.Management.Automation`. The tested approach operates entirely within managed .NET — no native calls, no kernel interaction, no registry writes.

The chain proceeds roughly as:

```
1. Locate the loaded SMA assembly        → filter by FullName
2. Resolve PSEtwLogProvider type         → GetType(...)
3. Reflect into etwProvider static field → GetField('etwProvider', NonPublic|Static)
4. Obtain the live provider object       → GetValue($null)
5. Locate the kernel handle field        → GetField('m_regHandle', NonPublic|Instance)
6. Capture original handle value         → [for reference]
7. Instantiate throwaway EventProvider   → New-Object ... (random GUID)
8. Extract throwaway handle              → GetField('m_regHandle'...).GetValue(...)
9. Overwrite PS provider handle          → SetValue($providerObject, $newHandle)
```

After step 9, the PowerShell ETW provider continues to report itself active. Events emit against a kernel-valid handle. No consumer receives them.

The substituted handle is non-zero and indistinguishable from a legitimate registration by handle-value inspection alone.

Implementation specifics are intentionally withheld. The detection implications are communicable without publishing an operational chain.

---

## Results

**Baseline:** EID 4104 fired normally for arbitrary strings, `Invoke-Expression`, and tooling execution.

**Post-substitution:** 4104 ceased arriving for subsequent PowerShell content. `Invoke-Expression` activity was not logged. Tooling execution was not logged. The loss of ScriptBlock telemetry persisted for session duration.

The effect persisted following forced garbage collection, indicating the substituted kernel registration outlived the managed wrapper object.

**Access context:** Validated in administrator and low-privileged WinRM sessions. Results were consistent across both.

### Environment Comparison

| Condition | Server 2019 (17763.x) | Server 2025 (26100.32690) |
|---|---|---|
| ScriptBlock logging default | Off | Off |
| Post-substitution 4104 telemetry loss | Confirmed | Confirmed |
| Setup chain visible pre-substitution | Confirmed | Confirmed |
| Warning-level events in setup chain | Confirmed | Confirmed |
| AMSI detection (no bypass) | Confirmed | Confirmed |
| Post-substitution content visibility | None observed | None observed |
| GC survival of substitution | Confirmed | Confirmed |

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
