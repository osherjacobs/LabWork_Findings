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

Server 2019 UBR 8755

<img width="1875" height="870" alt="2019" src="https://github.com/user-attachments/assets/8a588b83-b801-4940-b5e6-7806424fb64b" />

2022 UBR 587

<img width="1172" height="220" alt="2022MORPHKATZEDGOTCREDSDEFENDERCAUGHTITBEFORE_UBR" src="https://github.com/user-attachments/assets/805169d6-3b7f-43cb-b61b-54b6cc2b4004" />

<img width="1593" height="937" alt="2022MORPHKATZEDGOTCREDSDEFENDERCAUGHTITBEFORE" src="https://github.com/user-attachments/assets/0a281531-0fa1-4001-a89d-e6b0ea573a29" />

2022 UBR 5020

<img width="1890" height="941" alt="2022HIGHUBR" src="https://github.com/user-attachments/assets/822ab409-8ebb-4978-ae2a-ba98d7d64552" />

Server 2025 UBR 32690

<img width="1027" height="884" alt="2025NOCREDS" src="https://github.com/user-attachments/assets/ece0959b-9e6d-40f6-80b8-566281876723" />

<img width="1535" height="865" alt="2025NOCREDSUBR" src="https://github.com/user-attachments/assets/768fe520-c21f-466f-b600-ff470d2f60b0" />


ELK JSON 

"WIN-ATTACK"

{
  "_index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
  "_id": "ReTKhJ4BW3PCqUwNj6kz",
  "_version": 1,
  "_source": {
    "@timestamp": "2026-06-01T20:05:21.952Z",
    "agent": {
      "ephemeral_id": "bb727259-ce37-43c5-917c-7dd56ef33f6c",
      "id": "3d29cd4b-344b-43dc-a6cd-fbda0a2d60f8",
      "name": "WIN-ATTACK",
      "type": "winlogbeat",
      "version": "8.19.12"
    },
    "winlog": {
      "computer_name": "WIN-ATTACK.lab2019.local",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      },
      "version": 2,
      "event_data": {
        "UtcTime": "2026-06-01 20:05:21.952",
        "EventType": "SetValue",
        "ProcessGuid": "{b5c63fd8-e41c-6a1d-0b00-000000002400}",
        "ProcessId": "708",
        "Details": "system32\\drivers\\wd\\KslD.sys",
        "Image": "C:\\Windows\\system32\\services.exe",
        "User": "NT AUTHORITY\\SYSTEM",
        "RuleName": "T1031,T1050",
        "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
      },
      "record_id": 5844,
      "task": "Registry value set (rule: RegistryEvent)",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "provider_name": "Microsoft-Windows-Sysmon",
      "api": "wineventlog",
      "event_id": "13",
      "opcode": "Info",
      "process": {
        "pid": 2772,
        "thread": {
          "id": 4608
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational"
    },
    "event": {
      "provider": "Microsoft-Windows-Sysmon",
      "action": "Registry value set (rule: RegistryEvent)",
      "created": "2026-06-01T20:05:23.768Z",
      "code": "13",
      "kind": "event"
    },
    "log": {
      "level": "information"
    },
    "message": "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 20:05:21.952\nProcessGuid: {b5c63fd8-e41c-6a1d-0b00-000000002400}\nProcessId: 708\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM",
    "host": {
      "name": "WIN-ATTACK.lab2019.local"
    },
    "ecs": {
      "version": "8.0.0"
    }
  },
  "fields": {
    "winlog.process.thread.id": [
      4608
    ],
    "winlog.event_data.ProcessGuid": [
      "{b5c63fd8-e41c-6a1d-0b00-000000002400}"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.computer_name": [
      "WIN-ATTACK.lab2019.local"
    ],
    "winlog.process.pid": [
      2772
    ],
    "winlog.user.type": [
      "User"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.record_id": [
      "5844"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "WIN-ATTACK"
    ],
    "host.name": [
      "WIN-ATTACK.lab2019.local"
    ],
    "winlog.event_data.UtcTime": [
      "2026-06-01 20:05:21.952"
    ],
    "winlog.event_data.Details": [
      "system32\\drivers\\wd\\KslD.sys"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.event_data.ProcessId": [
      "708"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.version": [
      2
    ],
    "winlog.task": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "winlog.event_data.RuleName": [
      "T1031,T1050"
    ],
    "winlog.event_data.TargetObject": [
      "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
    ],
    "winlog.event_data.User": [
      "NT AUTHORITY\\SYSTEM"
    ],
    "agent.hostname": [
      "WIN-ATTACK"
    ],
    "message": [
      "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 20:05:21.952\nProcessGuid: {b5c63fd8-e41c-6a1d-0b00-000000002400}\nProcessId: 708\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM"
    ],
    "winlog.event_id": [
      "13"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "winlog.event_data.Image": [
      "C:\\Windows\\system32\\services.exe"
    ],
    "event.action": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "@timestamp": [
      "2026-06-01T20:05:21.952Z"
    ],
    "event.code": [
      "13"
    ],
    "agent.id": [
      "3d29cd4b-344b-43dc-a6cd-fbda0a2d60f8"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "winlog.event_data.EventType": [
      "SetValue"
    ],
    "event.created": [
      "2026-06-01T20:05:23.768Z"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "bb727259-ce37-43c5-917c-7dd56ef33f6c"
    ],
    "agent.version": [
      "8.19.12"
    ]
  }
}

DC02:

{
  "_index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
  "_id": "vuTChJ4BW3PCqUwNap4t",
  "_version": 1,
  "_source": {
    "@timestamp": "2026-06-01T19:56:23.021Z",
    "event": {
      "created": "2026-06-01T19:56:24.605Z",
      "code": "13",
      "kind": "event",
      "provider": "Microsoft-Windows-Sysmon",
      "action": "Process Create (rule: ProcessCreate)"
    },
    "log": {
      "level": "information"
    },
    "message": "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:56:23.020\nProcessGuid: {65f03206-9d40-6a1d-0b00-000000002100}\nProcessId: 788\nImage: C:\\WINDOWS\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM",
    "host": {
      "name": "DC02.badsuccessor.local"
    },
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "version": "8.19.12",
      "ephemeral_id": "ee78f402-ae21-429b-adcf-98798c958a90",
      "id": "d03fb57b-7222-4253-b677-4d8eba92e648",
      "name": "DC02",
      "type": "winlogbeat"
    },
    "winlog": {
      "task": "Process Create (rule: ProcessCreate)",
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "api": "wineventlog",
      "event_id": "13",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      },
      "process": {
        "pid": 2256,
        "thread": {
          "id": 3932
        }
      },
      "computer_name": "DC02.badsuccessor.local",
      "opcode": "Info",
      "version": 2,
      "event_data": {
        "RuleName": "T1031,T1050",
        "ProcessGuid": "{65f03206-9d40-6a1d-0b00-000000002100}",
        "ProcessId": "788",
        "Image": "C:\\WINDOWS\\system32\\services.exe",
        "EventType": "SetValue",
        "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath",
        "Details": "system32\\drivers\\wd\\KslD.sys",
        "UtcTime": "2026-06-01 19:56:23.020",
        "User": "NT AUTHORITY\\SYSTEM"
      },
      "record_id": 34568,
      "provider_name": "Microsoft-Windows-Sysmon"
    }
  },
  "fields": {
    "winlog.process.thread.id": [
      3932
    ],
    "winlog.event_data.ProcessGuid": [
      "{65f03206-9d40-6a1d-0b00-000000002100}"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.computer_name": [
      "DC02.badsuccessor.local"
    ],
    "winlog.process.pid": [
      2256
    ],
    "winlog.user.type": [
      "User"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.record_id": [
      "34568"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "DC02"
    ],
    "host.name": [
      "DC02.badsuccessor.local"
    ],
    "winlog.event_data.UtcTime": [
      "2026-06-01 19:56:23.020"
    ],
    "winlog.event_data.Details": [
      "system32\\drivers\\wd\\KslD.sys"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.event_data.ProcessId": [
      "788"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.version": [
      2
    ],
    "winlog.task": [
      "Process Create (rule: ProcessCreate)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "winlog.event_data.RuleName": [
      "T1031,T1050"
    ],
    "winlog.event_data.TargetObject": [
      "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
    ],
    "winlog.event_data.User": [
      "NT AUTHORITY\\SYSTEM"
    ],
    "agent.hostname": [
      "DC02"
    ],
    "message": [
      "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:56:23.020\nProcessGuid: {65f03206-9d40-6a1d-0b00-000000002100}\nProcessId: 788\nImage: C:\\WINDOWS\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM"
    ],
    "winlog.event_id": [
      "13"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "winlog.event_data.Image": [
      "C:\\WINDOWS\\system32\\services.exe"
    ],
    "event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "@timestamp": [
      "2026-06-01T19:56:23.021Z"
    ],
    "event.code": [
      "13"
    ],
    "agent.id": [
      "d03fb57b-7222-4253-b677-4d8eba92e648"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "winlog.event_data.EventType": [
      "SetValue"
    ],
    "event.created": [
      "2026-06-01T19:56:24.605Z"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "ee78f402-ae21-429b-adcf-98798c958a90"
    ],
    "agent.version": [
      "8.19.12"
    ]
  }
}

WIN-1KS84GNPAUM.lab2019.local

{
  "_index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
  "_id": "IuTBhJ4BW3PCqUwNQ57y",
  "_version": 1,
  "_source": {
    "@timestamp": "2026-06-01T19:55:12.889Z",
    "host": {
      "name": "WIN-1KS84GNPAUM.lab2019.local"
    },
    "winlog": {
      "process": {
        "pid": 2124,
        "thread": {
          "id": 4968
        }
      },
      "provider_name": "Microsoft-Windows-Sysmon",
      "record_id": 27872,
      "api": "wineventlog",
      "opcode": "Info",
      "event_data": {
        "RuleName": "T1031,T1050",
        "EventType": "SetValue",
        "UtcTime": "2026-06-01 19:55:12.888",
        "ProcessGuid": "{8ac51e87-d71b-6a1d-0b00-000000001a00}",
        "Image": "C:\\Windows\\system32\\services.exe",
        "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath",
        "Details": "system32\\drivers\\wd\\KslD.sys",
        "ProcessId": "736",
        "User": "NT AUTHORITY\\SYSTEM"
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      },
      "task": "Registry value set (rule: RegistryEvent)",
      "computer_name": "WIN-1KS84GNPAUM.lab2019.local",
      "version": 2,
      "event_id": "13",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    },
    "event": {
      "provider": "Microsoft-Windows-Sysmon",
      "action": "Registry value set (rule: RegistryEvent)",
      "created": "2026-06-01T19:55:14.337Z",
      "code": "13",
      "kind": "event"
    },
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "id": "04c179b6-32f0-4f95-8ecb-30ede9282c39",
      "name": "WIN-1KS84GNPAUM",
      "type": "winlogbeat",
      "version": "8.19.12",
      "ephemeral_id": "1f95c2f3-7a1d-4ffd-8a10-9b34b1e8741d"
    },
    "log": {
      "level": "information"
    },
    "message": "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:55:12.888\nProcessGuid: {8ac51e87-d71b-6a1d-0b00-000000001a00}\nProcessId: 736\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM"
  },
  "fields": {
    "winlog.process.thread.id": [
      4968
    ],
    "winlog.event_data.ProcessGuid": [
      "{8ac51e87-d71b-6a1d-0b00-000000001a00}"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.computer_name": [
      "WIN-1KS84GNPAUM.lab2019.local"
    ],
    "winlog.process.pid": [
      2124
    ],
    "winlog.user.type": [
      "User"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.record_id": [
      "27872"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "WIN-1KS84GNPAUM"
    ],
    "host.name": [
      "WIN-1KS84GNPAUM.lab2019.local"
    ],
    "winlog.event_data.UtcTime": [
      "2026-06-01 19:55:12.888"
    ],
    "winlog.event_data.Details": [
      "system32\\drivers\\wd\\KslD.sys"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.event_data.ProcessId": [
      "736"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.version": [
      2
    ],
    "winlog.task": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "winlog.event_data.RuleName": [
      "T1031,T1050"
    ],
    "winlog.event_data.TargetObject": [
      "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
    ],
    "winlog.event_data.User": [
      "NT AUTHORITY\\SYSTEM"
    ],
    "agent.hostname": [
      "WIN-1KS84GNPAUM"
    ],
    "message": [
      "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:55:12.888\nProcessGuid: {8ac51e87-d71b-6a1d-0b00-000000001a00}\nProcessId: 736\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: system32\\drivers\\wd\\KslD.sys\nUser: NT AUTHORITY\\SYSTEM"
    ],
    "winlog.event_id": [
      "13"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "winlog.event_data.Image": [
      "C:\\Windows\\system32\\services.exe"
    ],
    "event.action": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "@timestamp": [
      "2026-06-01T19:55:12.889Z"
    ],
    "event.code": [
      "13"
    ],
    "agent.id": [
      "04c179b6-32f0-4f95-8ecb-30ede9282c39"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "winlog.event_data.EventType": [
      "SetValue"
    ],
    "event.created": [
      "2026-06-01T19:55:14.337Z"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "1f95c2f3-7a1d-4ffd-8a10-9b34b1e8741d"
    ],
    "agent.version": [
      "8.19.12"
    ]
  }
}

WIN-JOCP945SK51

{
  "_index": ".ds-winlogbeat-8.19.14-2026.05.13-000002",
  "_id": "BeS_hJ4BW3PCqUwN354h",
  "_version": 1,
  "_source": {
    "@timestamp": "2026-06-01T19:53:37.612Z",
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "id": "aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6",
      "name": "WIN-JOCP945SK51",
      "type": "winlogbeat",
      "version": "8.19.14",
      "ephemeral_id": "82295209-cc3e-4275-8f94-e4db72e6816e"
    },
    "winlog": {
      "version": 2,
      "record_id": 20164,
      "task": "Registry value set (rule: RegistryEvent)",
      "opcode": "Info",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      },
      "event_id": "13",
      "computer_name": "WIN-JOCP945SK51.lab2019.local",
      "process": {
        "pid": 3432,
        "thread": {
          "id": 4312
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "event_data": {
        "ProcessGuid": "{6e4a868b-da32-6a1d-0b00-000000002700}",
        "Details": "System32\\drivers\\vKslD.sys",
        "User": "NT AUTHORITY\\SYSTEM",
        "EventType": "SetValue",
        "UtcTime": "2026-06-01 19:53:37.611",
        "RuleName": "T1031,T1050",
        "ProcessId": "684",
        "Image": "C:\\Windows\\system32\\services.exe",
        "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
      },
      "provider_name": "Microsoft-Windows-Sysmon",
      "api": "wineventlog"
    },
    "event": {
      "created": "2026-06-01T19:53:39.334Z",
      "code": "13",
      "kind": "event",
      "provider": "Microsoft-Windows-Sysmon",
      "action": "Registry value set (rule: RegistryEvent)"
    },
    "log": {
      "level": "information"
    },
    "message": "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:53:37.611\nProcessGuid: {6e4a868b-da32-6a1d-0b00-000000002700}\nProcessId: 684\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: System32\\drivers\\vKslD.sys\nUser: NT AUTHORITY\\SYSTEM",
    "host": {
      "name": "WIN-JOCP945SK51.lab2019.local"
    }
  },
  "fields": {
    "winlog.process.thread.id": [
      4312
    ],
    "winlog.event_data.ProcessGuid": [
      "{6e4a868b-da32-6a1d-0b00-000000002700}"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.computer_name": [
      "WIN-JOCP945SK51.lab2019.local"
    ],
    "winlog.process.pid": [
      3432
    ],
    "winlog.user.type": [
      "User"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.record_id": [
      "20164"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "WIN-JOCP945SK51"
    ],
    "host.name": [
      "WIN-JOCP945SK51.lab2019.local"
    ],
    "winlog.event_data.UtcTime": [
      "2026-06-01 19:53:37.611"
    ],
    "winlog.event_data.Details": [
      "System32\\drivers\\vKslD.sys"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.event_data.ProcessId": [
      "684"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.version": [
      2
    ],
    "winlog.task": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "winlog.event_data.RuleName": [
      "T1031,T1050"
    ],
    "winlog.event_data.TargetObject": [
      "HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath"
    ],
    "winlog.event_data.User": [
      "NT AUTHORITY\\SYSTEM"
    ],
    "agent.hostname": [
      "WIN-JOCP945SK51"
    ],
    "message": [
      "Registry value set:\nRuleName: T1031,T1050\nEventType: SetValue\nUtcTime: 2026-06-01 19:53:37.611\nProcessGuid: {6e4a868b-da32-6a1d-0b00-000000002700}\nProcessId: 684\nImage: C:\\Windows\\system32\\services.exe\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\KslD\\ImagePath\nDetails: System32\\drivers\\vKslD.sys\nUser: NT AUTHORITY\\SYSTEM"
    ],
    "winlog.event_id": [
      "13"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "winlog.event_data.Image": [
      "C:\\Windows\\system32\\services.exe"
    ],
    "event.action": [
      "Registry value set (rule: RegistryEvent)"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "@timestamp": [
      "2026-06-01T19:53:37.612Z"
    ],
    "event.code": [
      "13"
    ],
    "agent.id": [
      "aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "winlog.event_data.EventType": [
      "SetValue"
    ],
    "event.created": [
      "2026-06-01T19:53:39.334Z"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "82295209-cc3e-4275-8f94-e4db72e6816e"
    ],
    "agent.version": [
      "8.19.14"
    ]
  }
}

