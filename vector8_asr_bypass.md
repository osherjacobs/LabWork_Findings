# Vector 8 — ASR Rule 9e6c4e1f Bypass via Pure NTAPI LSASS Dump

## Environment

- **Target:** WIN-52H4TKKPD9C (Windows Server 2025, 24H2)
- **Build:** 26100.32690
- **Defender Signatures:** 1.449.490.0 (updated 2026-05-07)
- **RTP:** Enabled
- **ASR Rule:** `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` — Block mode (action=1)

## Technique

Custom C# tool. Pure NTAPI memory walk. Minidump assembled in memory. No MiniDumpWriteDump. No dbghelp.dll. No comsvcs. Streamed over TCP to attacker machine. Nothing written to disk.

## Execution Contexts Tested

### Remote
Execution via scheduled task (goexec/tsch) from attacker machine.  
Total operation time: ~200ms.  
Nothing written to disk on target.

### Local
Same tool executed directly on target machine (curpipe.exe from C:\Windows\Tasks).

**Execution output:**
- SeDebugPrivilege: enabled
- LSASS PID: 900
- Handle: 0x744
- Regions walked: 665 — 59,252,736 bytes in 23ms
- Dump built: 59,279,096 bytes in 47ms
- Sent to attacker: 45ms
- **Total: 115ms**

ASR rule confirmed active immediately prior to execution via Get-MpPreference (action=1).

## Result

Full LSASS credential extraction succeeded in both execution contexts.

- NT hash: extracted
- SHA1: extracted
- DPAPI master key: extracted
- Kerberos material: extracted

## ASR Telemetry

Post-execution query against Microsoft-Windows-Windows Defender/Operational:

- EID 1121 (block): none
- EID 1122 (audit): none
- EID 1131: none
- EID 1132: none

Rule confirmed active via Get-MpPreference immediately after execution in both cases.

## Observations

Both remote and local execution contexts bypass ASR rule `9e6c4e1f` without triggering any telemetry. The bypass does not appear to be execution-context dependent.

This is a single test against a single technique in a controlled lab environment. No conclusions are drawn about the general effectiveness of ASR rules or Defender.

The finding is narrow: this specific technique, in this configuration, at this patch level, produced no ASR telemetry and was not blocked in either execution context.

Whether this reflects a gap in rule coverage, a detection logic limitation, or a configuration dependency is not yet determined. Further research is indicated.

## Scope

No tooling published. No source code. Screenshots only. Lab infrastructure, owned and operated by the researcher.

## References

- [osherjacobs/AD-Lab-Research](https://github.com/osherjacobs/AD-Lab-Research)
- ASR rule documentation: [Block credential stealing from the Windows local security authority subsystem](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)

<img width="1878" height="778" alt="AttackWithASRRUleCENSORED" src="https://github.com/user-attachments/assets/bbd5f7be-a95c-4796-b0bd-4454d06262d2" />

<img width="1009" height="423" alt="Dumps" src="https://github.com/user-attachments/assets/c179bad9-ba63-4d08-be98-471ed70889a5" />

<img width="1152" height="490" alt="CredsKVCFORENSICCENSORED" src="https://github.com/user-attachments/assets/ee0e16e4-c93c-4e0f-b8b0-e556c8a521bb" />

<img width="1205" height="717" alt="FROMWINDOWSMACHINE" src="https://github.com/user-attachments/assets/47127551-b555-44d4-b254-9cab1e1650a7" />

<img width="999" height="539" alt="DUMPDIRECTFROMWINDOWSMACHINE" src="https://github.com/user-attachments/assets/b198efa5-c588-4623-a5b1-2adbece8ce11" />

<img width="1850" height="649" alt="UBRRTPASR" src="https://github.com/user-attachments/assets/e0691b5c-80ef-4cd4-a489-dcde1e68d41a" />









