**
# ELK Security Monitoring Lab — Adversarial Detection Engineering
**
Windows Server 2019 AD + Kali + ELK Stack (Elasticsearch, Kibana, Winlogbeat)

This lab was built to reproduce common post-compromise behavior in Active Directory and observe how it appears in native Windows telemetry.

The focus is not deployment, but visibility:

what actions generate signal

what looks benign but isn’t

where default logging and detection logic fail

Tested scenario:
Admin share access (SMB → C$) using valid credentials, mapped to Event ID 5145 and correlated logon activity.

---

## Lab Topology

| Host | Role | IP | OS |
|---|---|---|---|
| Dell desktop | ELK stack (bare metal) | 192.168.1.250 | Ubuntu 22.04 LTS |
| i5-14500 VMware host | DC VM + Kali VM | 192.168.1.x | Ubuntu 24.04 |
| Windows Server 2019 VM | Domain Controller (DC01) | 192.168.1.4 | WS2019 Eval |
| Kali Linux VM | Attacker | 192.168.1.218 | Kali rolling |

**Domain:** `lab2019.local`  
**Access to Kibana:** SSH tunnel from Kali or i5 host → port 5601

---

## Part 1 — Ubuntu Host Preparation (Dell)

### Static IP via Netplan

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    enp3s0:
      dhcp4: no
      addresses: [192.168.1.250/24]
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

```bash
sudo netplan apply
```

### SSH hardening

```bash
sudo apt install openssh-server -y
```

Generate ed25519 keypair on your client machine and copy the public key:

```bash
# On client (i5 or Kali)
ssh-keygen -t ed25519 -C "elk-lab"
ssh-copy-id elastic@192.168.1.250
```

Harden the SSH config on the Dell:

```bash
sudo nano /etc/ssh/sshd_config
```

Set:
```
PasswordAuthentication no
PermitRootLogin no
```

```bash
sudo systemctl restart ssh
```

### Firewall (UFW)

```bash
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw allow from 192.168.1.0/24 to any port 9200
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw enable
sudo ufw status
```

Only your local subnet can reach SSH, Elasticsearch, and Kibana. Nothing else.

### Prevent sleep/suspend (headless machine)

```bash
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```

Edit `/etc/systemd/logind.conf`:

```
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
IdleAction=ignore
```

```bash
sudo systemctl restart systemd-logind
```

### Timezone and NTP

```bash
sudo timedatectl set-timezone Asia/Jerusalem
timedatectl status
```

Confirm NTP is active (`NTP service: active`).

---

## Part 2 — Elasticsearch

### Add Elastic APT repo and install

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch -y
```

**Save the auto-generated `elastic` password from the install output immediately.** It is only shown once.

### Tune JVM heap

Elasticsearch defaults to auto-sizing which can overcommit on a 16GB machine. Pin it:

```bash
sudo mkdir -p /etc/elasticsearch/jvm.options.d/
echo "-Xms4g" | sudo tee /etc/elasticsearch/jvm.options.d/heap.options
echo "-Xmx4g" | sudo tee -a /etc/elasticsearch/jvm.options.d/heap.options
```

### Bind to network interface

By default Elasticsearch only listens on localhost. Check for existing entries first:

```bash
sudo grep -n "network.host" /etc/elasticsearch/elasticsearch.yml
```

If a line exists, delete it by line number:

```bash
sudo sed -i '<LINE_NUMBER>d' /etc/elasticsearch/elasticsearch.yml
```

Then append:

```bash
echo "network.host: 0.0.0.0" | sudo tee -a /etc/elasticsearch/elasticsearch.yml
```

Verify exactly one entry:

```bash
sudo grep -n "network.host" /etc/elasticsearch/elasticsearch.yml
```

### Start and enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### Verify

```bash
curl -k -u elastic:<YOUR_PASSWORD> https://localhost:9200
```

Expected: JSON with `"number": "8.19.12"`.

---

## Part 3 — Kibana

### Install

```bash
sudo apt install kibana -y
```

### Bind to network interface

Same issue as Elasticsearch. Check first:

```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
```

If a line exists with `"localhost"`, delete it by line number:

```bash
sudo sed -i '<LINE_NUMBER>d' /etc/kibana/kibana.yml
```

Append the correct value:

```bash
echo "server.host: 0.0.0.0" | sudo tee -a /etc/kibana/kibana.yml
```

Verify exactly one entry:

```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
```

### Add encryption keys

Required for the SIEM/Security detection engine. Without these, the detection engine refuses to initialize.

Generate the keys:

```bash
sudo /usr/share/kibana/bin/kibana-encryption-keys generate
```

Copy the three output lines and append them to the config:

```bash
sudo tee -a /etc/kibana/kibana.yml << 'KEYS'
xpack.encryptedSavedObjects.encryptionKey: "<KEY1>"
xpack.reporting.encryptionKey: "<KEY2>"
xpack.security.encryptionKey: "<KEY3>"
KEYS
```

### Start and enable

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

Wait for Kibana to fully initialize (60-90 seconds):

```bash
sudo journalctl -u kibana -f
```

Wait for: `Kibana is now available`. Then Ctrl+C.

### Initialize the detection engine

```bash
curl -u elastic:<YOUR_PASSWORD> -X POST "http://localhost:5601/api/detection_engine/index" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true"
```

Expected: `{"acknowledged":true}`

> Kibana runs HTTP locally. Use `http://localhost:5601` for local API calls.  
> Elasticsearch uses HTTPS. Use `https://localhost:9200` for Elasticsearch API calls.

### Access Kibana

Kibana is not exposed to the internet. Access it via SSH tunnel from your client:

```bash
ssh -L 5601:localhost:5601 elastic@192.168.1.250 -N
```

Then open `http://localhost:5601` in your browser. Login: `elastic` / `<YOUR_PASSWORD>`.

---

## Part 4 — Windows Audit Policy (DC)

Run in elevated PowerShell on the DC:

```powershell
# Share access — fires EID 5140 and 5145
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Logon events — fires EID 4624, 4625, 4648
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
auditpol /get /subcategory:"Logon"
```

All must return `Success and Failure`.

> EID 5145 is fired by the SMB subsystem — no SACL on C:\ is required.

---

## Part 5 — Sysmon (DC)

Sysmon provides process, network, file, and pipe telemetry beyond what the Security log captures.

```powershell
# Download Sysmon and olafhartong modular config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\sysmon.zip"
Expand-Archive C:\sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"

# Install
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify
Get-Service Sysmon64
```

Key event IDs for this lab:

| EID | Description |
|---|---|
| 3 | Network connection (port 445 = SMB) |
| 11 | File created under C:\ |
| 17/18 | Pipe created/connected (psexec detection) |

---

## Part 6 — Winlogbeat (DC)

### Download and extract

Version must match Elasticsearch exactly:

```powershell
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.12-windows-x86_64.zip" -OutFile "C:\winlogbeat.zip"
Expand-Archive C:\winlogbeat.zip -DestinationPath "C:\Program Files\"
Rename-Item "C:\Program Files\winlogbeat-8.19.12-windows-x86_64" "C:\Program Files\Winlogbeat"
```

### Configure

Overwrite the default config entirely:

```powershell
@"
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 5140, 5145
  - name: System
    event_id: 7045
  - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["https://<ELK-IP>:9200"]
  username: "elastic"
  password: "<YOUR_PASSWORD>"
  ssl.verification_mode: none

setup.kibana:
  host: "http://<ELK-IP>:5601"

setup.ilm.enabled: false
"@ | Set-Content "C:\Program Files\Winlogbeat\winlogbeat.yml" -Encoding UTF8
```

### Install, setup, and start

```powershell
cd "C:\Program Files\Winlogbeat"
powershell -ep bypass .\install-service-winlogbeat.ps1
.\winlogbeat.exe setup --index-management -e
Start-Service winlogbeat
Get-Service winlogbeat
```

The `setup` command pushes the index template to Elasticsearch. It must succeed before starting the service. If it fails with a connection error, fix connectivity first then re-run it.

### Verify logs landing

From the Dell:

```bash
curl -k -u elastic:<YOUR_PASSWORD> "https://localhost:9200/winlogbeat-*/_count"
```

Expected: `{"count": <number greater than 0>, ...}`

---

## Part 7 — Kibana Data View and Detection Rule

### Create data view

Hamburger → Stack Management → Data Views → Create data view

- Name: `winlogbeat`
- Index pattern: `winlogbeat-*`
- Timestamp field: `@timestamp`

### Verify data in Discover

Hamburger → Analytics → Discover → select `winlogbeat` data view → Last 24 hours.

Events should be flowing from DC01.

### Create detection rule

Hamburger → Security → Rules → Detection rules (SIEM) → Create new rule

**Step 1 — Define rule:**
- Type: Custom query
- Index patterns: `winlogbeat-*`
- Query:

```kql
event.code: "5145" and winlog.event_data.ShareName: "\\\\*\\C$"
```

**Step 2 — About rule:**
- Name: `Admin Share Access - C$ via SMB`
- Description: `Detects network access to C$ admin share via SMB - EID 5145`
- Severity: `High`
- Risk score: `73`

**Step 3 — Schedule:**
- Runs every: `5 minutes`
- Additional look-back time: `1 minute`

**Step 4:** Create and enable rule.

---

## Part 8 — Run the Attack (Kali)

```bash
smbclient //<DC-IP>/C$ -U '<DOMAIN>\Administrator%<PASSWORD>'
```

At the prompt:
```
smb: \> ls
smb: \> exit
```

Wait up to 5 minutes, then check Security → Alerts in Kibana.

---

## Troubleshooting

### Elasticsearch connection refused from Windows

**Symptom:** Winlogbeat setup fails — `connectex: A connection attempt failed`  
**Cause:** Elasticsearch bound to localhost, or UFW blocking port 9200  
**Fix:** Add `network.host: 0.0.0.0` to `/etc/elasticsearch/elasticsearch.yml` and run `sudo ufw allow from 192.168.1.0/24 to any port 9200`

### Kibana fails to start — duplicate mapping key

**Symptom:** `FATAL CLI ERROR YAMLException: duplicated mapping key`  
**Cause:** A key like `server.host` defined twice — once in the default config and once appended  
**Fix:** Always grep for existing keys before appending:
```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
sudo sed -i '<LINE_NUMBER>d' /etc/kibana/kibana.yml
```

### Detection engine permissions error

**Symptom:** `Detection engine permissions required` in Security → Alerts  
**Cause:** Encryption keys missing or detection engine index not initialized  
**Fix:** Add encryption keys, restart Kibana, then POST to the detection engine endpoint:
```bash
curl -u elastic:<PASSWORD> -X POST "http://localhost:5601/api/detection_engine/index" \
  -H "Content-Type: application/json" -H "kbn-xsrf: true"
```

### Kibana SSL error on local curl

**Symptom:** `curl: (35) error:0A00010B:SSL routines::wrong version number`  
**Cause:** Kibana uses HTTP locally — only Elasticsearch uses HTTPS  
**Fix:** Use `http://localhost:5601` for Kibana, `https://localhost:9200` for Elasticsearch

### Winlogbeat setup fails after firewall fix

**Symptom:** Setup command still fails even after fixing UFW  
**Cause:** Elasticsearch not yet bound to the network interface  
**Fix:** Add `network.host: 0.0.0.0` to `/etc/elasticsearch/elasticsearch.yml` and restart Elasticsearch, then re-run `.\winlogbeat.exe setup --index-management -e`

---

## Key Event IDs Reference

| EID | Log | Fires when |
|---|---|---|
| 5140 | Security | Network share object accessed |
| 5145 | Security | Network share object checked for access (detailed) |
| 4624 | Security | Successful logon (Type 3 = network) |
| 4625 | Security | Failed logon |
| 4648 | Security | Logon with explicit credentials |
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| Sysmon 3 | Sysmon | Network connection (port 445) |
| Sysmon 11 | Sysmon | File created |
| Sysmon 17/18 | Sysmon | Named pipe (psexec) |

---

*Part of the AD-Lab-Research detection engineering series.*  
*Tested: Elasticsearch/Kibana/Winlogbeat 8.19.12 — Ubuntu 22.04 — Windows Server 2019 — Kali rolling*
