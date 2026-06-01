<img width="1914" height="958" alt="EIDACCROSSHOSTS13" src="https://github.com/user-attachments/assets/cc7c9722-af34-402d-9e92-0a8a9719d52d" />


# KslKatz Lab Validation — Operational Assumption Analysis

**Tool:** [KslKatz](https://github.com/S1lky/KslKatz) — BYOVD credential extractor using Microsoft Defender's KslD.sys  
**Lab:** lab2019.local / badsuccessor.local  
**Date:** June 2026

---

**Primary finding:** KslKatz seems UBR-dependent rather than build-dependent. Identical OS builds at different patch levels produced different outcomes perhaps due to variant pattern signatures in lsasrv.dll. The tool's published support matrix lists build numbers only — UBR is not mentioned, which may be the underlying variable.

| Claim | Lab outcome |
|-------|-------------|
| PPL bypass | Confirmed |
| Credential extraction | Partially confirmed |
| Build-based support matrix | Contradicted |
| UBR sensitivity | Observed |
| Defender evasion | Inconsistent across builds |
| Registry IOC (EID 13) | Consistent across all hosts |

---

## Inspiration

This validation was prompted by the Weekly Purple Team video [Herding Katz to Steal Creds](https://www.youtube.com/watch?v=m2KTm7UYMuc) (May 30, 2026), which walks through the MorphKatz + KslKatz workflow from both red and blue team perspectives. The video demonstrates the technique working cleanly and pairs it with Elastic detection rules.

My testing covers a range of OS versions, patch levels, and build configurations. The results are mixed. UBR sensitivity, evasion consistency, and credential extraction reliability all vary in ways that a single successful demonstration won't surface.


**Tools used:**
- [KslKatz](https://github.com/S1lky/KslKatz) — BYOVD credential extractor using Microsoft Defender's KslD.sys (GPL-3.0)
- [MorphKatz](https://github.com/0xMohammedHassan/morphkatz) — polymorphic machine-code rewriter for Windows x64 binaries, used here for PE mutation and data-section encoding to evade ML-based Defender detections (AGPL-3.0)


---

## What the tool does

KslKatz combines two techniques into a standalone executable:

- **KslD.sys BYOVD** — switches the SCM `ImagePath` for the KslD service from the patched `drivers\wd\KslD.sys` to the vulnerable `drivers\KslD.sys` (or deploys an embedded copy as `vKslD.sys`), exploiting an unrestricted `MmCopyMemory()` wrapper exposed via IOCTL to usermode
- **GhostKatz-style local signature scanning** — reads lsasrv.dll and wdigest.dll from disk (no `LoadLibrary`, no ETW event), pattern-scans for `LogonSessionList` and `l_LogSessList` references, and resolves their addresses via RIP-relative displacement

The read primitive bypasses PPL entirely — `MmCopyMemory()` operates below the process protection layer and doesn't care which process owns the physical pages it reads.

The support matrix in the README lists Server 2022 (20348) and Windows 11 24H2/25H2 (26100) as **tested and working**.

---

## What actually happened

### Build environment pain

KslKatz targets `v143` platform toolset. The lab dev machine runs Visual Studio 2026 (18.6.0) with two MSVC toolsets installed side by side: `14.44.35207` (v143) and `14.51.36231` (v145). The default CMake generator picked `14.44`, vcpkg picked `14.51`, and the resulting link produced six `LNK2001` unresolved externals against vectorized STL intrinsics (`__std_rotate`, `__std_max_element_8u`, etc.) that exist in one toolset's STL but not the other.

Fix: retarget the solution to `v145` so both vcpkg and MSBuild use the same toolset. Ten minutes of actual work, about two hours of toolchain archaeology (Thanks Claude....).

### Hash output bug

Once the tool ran successfully on Server 2019, the NT hashes came out malformed — leading zero-padded, last four bytes truncated:

```
LAB2019\administrator
  NT:   000000003cINCORRECTVALUE   ← wrong
```

The correct hash (confirmed via secretsdump DRSUAPI) is `REDACTED`.

Root cause: `walk_primary()` in `lsa.cpp` gates credential extraction on `!dec[0x40]` (isIso) and `dec[0x41]`/`dec[0x42]` (isNtOwf). A hex dump of the decrypted blob on build 17763 showed these offsets don't contain flags on this build — they're part of the credential data itself. The actual NT hash starts at `0x4a`, not `0x46` or `0x48` as the code assumed. Fixed by probing the decrypted buffer directly and hardcoding the correct offsets for this struct layout.

---

## Tested OS matrix

| Host | OS | Build | UBR | Defender evasion | MSV1_0 | WDigest | Credential Guard | Notes |
|------|----|-------|-----|-----------------|--------|---------|-----------------|-------|
| WIN-JOCP945SK51 | Windows Server 2019 | 17763 | 8755 | rename only | ✅ | ❌ | Off | WDigest disabled by default |
| WIN-ATTACK | Windows Server 2022 | 20348 | 587 | rename + morphkatz | ✅ | ❌ | Off | WDigest disabled by default |
| WIN-1KS84GNPAUM | Windows Server 2022 | 20348 | 5020 | n/a | ❌ | ❌ | Off | LogonSessionList signature miss. Unable to reproduce expected results |
| DC02 | Windows Server 2025 | 26100 | 32690 | rename only | ❌ | ❌ | Off (VBS not enabled) | LogonSessionList + WDigest signature miss. Unable to reproduce expected results. Native vulnerable driver present. App Control for Business enforced |

---

## Windows Versions / coverage treated in this testing round

The support matrix lists build numbers but not UBRs. The actual coverage boundary seems UBR-dependent.

Two machines running identical build 20348 produced opposite results — one extracted credentials cleanly, one failed at `LogonSessionList not found`. The difference was UBR 587 vs UBR 5020. The pattern table entry `msv_pat3` matches the lsasrv.dll at lower patch levels but the pattern seems to have changed somewhere between those two UBRs.

The same issue applies to the 26100 entry. DC02 at 26100.32690 failed on both MSV1_0 and WDigest signatures.

The reality is a seeming sliding window of pattern coverage that degrades silently as patch level increases. There's no error indicating a stale signature — just `LogonSessionList not found`, which could equally mean a genuine protection mechanism is blocking access.

---

## Evasion

As with any credential dumping workflow, local administrator context is a prerequisite. KslKatz requires it to interact with the SCM, modify the KslD service configuration, and open the driver device handle. This is not a limitation specific to this tool — it is the baseline access requirement for this class of technique.

Defender detection behavior varied across machines and was not purely signature-based.

On Server 2019 (17763 / UBR 8755), a simple filename rename was sufficient — the binary ran clean with no Defender intervention. No morphing required.

On Server 2022 (20348 / UBR 587), the renamed binary was quarantined as `Trojan:Win32/Sabsik.TE.A!ml` — an ML-based detection, not a static signature. The `!ml` suffix is the tell. Static string obfuscation via morphkatz's `--data-morph` pass (XOR-encoding known KslKatz strings with a runtime decoder stub, stripping the Authenticode signature, randomizing the Rich header) was sufficient to bring the ML score below the detection threshold on this build. Five morphed variants were generated; one passed.

The ML model on the higher-UBR Server 2022 machine (20348 / UBR 5020) was not tested for evasion since credential extraction failed at the signature level regardless.

One observation worth noting on the morphkatz workflow: the `--target-defender` bisection mode — which uses MpCmdRun to identify detected byte regions and focuses rewrites on those anchors — requires Defender to actually flag the binary on the machine where morphkatz runs. To enable this without Defender deleting the working binaries, a folder exclusion was added on the dev machine. This allowed Defender to scan and report detections via MpCmdRun while leaving files in place — the intended workflow for this kind of iterative evasion development.

In practice, the dev machine's Defender did not flag KslKatz even with real-time protection enabled and signatures updated, so bisection produced no anchors and the code rewriter generated zero candidate rewrites regardless. The data-morph pass — driven by a manually written YARA rule targeting known KslKatz strings — was the only effective component. This is consistent with an ML detection that scores on aggregate PE features rather than discrete byte sequences, and confirms that bisection-based feedback loops only work when the scanning engine on the dev machine matches the detection posture of the target environment.

---

## Detection

The attack is structurally detectable in environments collecting Sysmon EID 13 or equivalent registry telemetry because the `KslD` `ImagePath` modification is an operational requirement of execution.

**Detection rule (KQL):**

```
event.code:"13" AND winlog.event_data.TargetObject:*KslD\ImagePath* AND NOT winlog.event_data.Details:*drivers\\wd\\KslD.sys*
```

Across all four machines, the query returned 22 events total — multiple runs on Server 2019 accounted for the higher count. The timeline shows event clusters at each execution timestamp, all landing on the same `TargetObject`.

Every execution produced exactly two EID 13 events with a ~3 second gap:

1. Attack write: `ImagePath` → `System32\drivers\vKslD.sys` or `System32\drivers\KslD.sys`
2. Restore write: `ImagePath` → `system32\drivers\wd\KslD.sys`

The restore write confirms execution completed. The attack write is the primary IOC. Any `ImagePath` value pointing outside `drivers\wd\` is malicious — the legitimate state is always the patched driver path.

Expected false-positive rate is extremely low: the legitimate KslD service path always resolves to `drivers\wd\KslD.sys`, and any deviation is highly suspicious. This is not a heuristic — it is a structural requirement of the attack chain.

No detailed telemetry analysis was performed beyond confirming event presence and field values. A thorough analysis — covering process ancestry, handle telemetry, driver load events, and behavioral clustering — would be a significant undertaking beyond the scope of this validation. The audience is invited to extend that work. Telemetry screenshots from this lab are included for reference.

---

## Framing

Lab validation confirmed the kernel read primitive, PPL bypass behavior, and LSA key extraction path on supported builds. In observed failures, the limiting factor was signature coverage rather than access to protected memory.

This would need stricter testing and observation but it seems the tool degrades silently at higher patch levels. UBR is probably the variable that matters. Extending coverage to a new UBR requires extracting lsasrv.dll from the target, finding the `LogonSessionList` reference in a disassembler, and adding the pattern to the signature table. Repeatable but manual.

The Server 2025 failure (not listed as supported in the matrix) is best explained by a signature-table miss rather than VBS or isolation-based protection, which were architecturally absent on this host. `App Control for Business policy: Enforced` was present but did not prevent execution of the renamed binary.

DRSUAPI remains unaffected by any of this — protocol-layer replication doesn't touch lsasrv.dll struct layouts, PPL, or local memory at all.

---

## Caveats

These findings reflect a single lab environment and should not be treated as definitive or universally reproducible results. Specific VMware configurations, domain setup, Defender signature versions at time of testing, and UBR values at the time of each run all influence outcomes. It is entirely possible that environmental quirks in this lab account for some of the failures observed — particularly on the higher-UBR Server 2022 machine, where the gap between expected and actual behavior is large enough to warrant independent replication before drawing any conclusions.

KslKatz is clearly a well-engineered tool and the underlying technique is sound. I was not able to reliably reproduce the expected results across the full claimed support matrix — but that is a reflection of my environment and the UBR sensitivity of the pattern matching, not necessarily a fundamental flaw in the approach. The UBR dependency hypothesis is the most parsimonious explanation for the observed outcomes, but confirming it would require systematic testing across multiple UBRs on the same base build — something outside the scope of this lab session.

Independent replication across additional UBRs — particularly Server 2022 between UBR 588–5019 — would help validate or falsify the UBR sensitivity hypothesis. Testing on Server 2025 is outside the tool's claimed support matrix but may be of interest to researchers.


