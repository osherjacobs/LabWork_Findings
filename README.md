Active Directory Security Research
Controlled offensive security research conducted in enterprise-modeled lab environments.
Emphasis on attack path realism, defensive visibility, and control failure analysis. Not tool tutorials — documented chains with raw telemetry, detection gaps, and KQL.
Lab: Windows Server 2019/2022/2025 | Kali | Sysmon 15.20 + SwiftOnSecurity config | Winlogbeat → Elasticsearch 8.x
All credentials and network details sanitized.

Credential Access — LSASS Vector Series
VectorTargetTechniqueStatusvector4Server 2022MiniDumpWriteDump via dbghelp.dllPublishedvector5Server 2022LSASS + goexec/nxc deliveryPublishedvector6Server 2022Exclusion path analysis (EID 5007)Publishedvector7Server 2025 (UBR 1)MiniDumpWriteDump, default configPublishedvector7bServer 2025 (UBR 1742)Patch boundary — pypykatz compatibilityPublishedvector7cServer 2025PPL boundary analysisIn progress
Key finding across series: EID 5007 (Defender exclusion add/remove) is the highest-fidelity intervention point. Technique-level detection is unreliable under live runtime enforcement.

Credential Access — Replication Path
WriteupTargetTechniqueADCSYNCServer 2025 (fully patched)secretsdump DRSUAPI — no LSASS interaction
Key finding: Memory protections are irrelevant to the replication protocol path. Detection boundary is RemoteRegistry service start, not LSASS.

ADCS Abuse
WriteupTechniqueESC1SAN abuse → certificate request → PKINITESC4Template misconfiguration → ESC1 pivotESC8NTLM relay → certsrv → certificate theftKerberos CNAME → ESC8 → ESC1 chainCVE-2026-20929 — ARP spoof → mitm6 → krbrelayx → DA

Kerberos & Delegation

Kerberos attack chains (sanitized)
ADCS attack paths reference guide


Lab Setup & Infrastructure

Sysmon setup guide (SwiftOnSecurity config)
AD/ADCS environment setup
ESC1/ESC8 lab configuration


Detection Engineering Notes
Across all vectors, the consistent finding is that technique-level detection is unreliable. The highest-confidence signals are upstream of the technique itself — operator behavior, environmental dependencies, and service state changes.
Recurring intervention points:

EID 5007 — Defender exclusion modification
EID 5136 — AD attribute writes (Shadow Credentials, DACL changes)
RemoteRegistry service start — replication path abuse
EID 4768 PreAuthType 16 — PKINIT authentication


Part of an ongoing purple team research series. New vectors published periodically.
GitHub traffic and LinkedIn writeups: Osher Jacobs
