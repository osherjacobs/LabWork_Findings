# ELK Stack Setup for Windows Security Monitoring
**Elasticsearch + Kibana + Winlogbeat — Ubuntu + Windows Server 2019**

---

## Prerequisites

| Component | Host | Spec |
|---|---|---|
| Elasticsearch + Kibana | Ubuntu (bare metal or VM) | 16GB RAM minimum |
| Winlogbeat + Sysmon | Windows Server / Client | Domain-joined preferred |
| Attacker | Kali Linux | Same subnet |

All three on the same `/24` subnet. No cloud. No agent framework.

---

## Part 1 — Elasticsearch (Ubuntu)

### Install

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch -y
```

Note the auto-generated `elastic` password from the install output — save it immediately.

### Bind to network interface

By default Elasticsearch only listens on localhost. Fix this before starting:

```bash
echo "network.host: 0.0.0.0" | sudo tee -a /etc/elasticsearch/elasticsearch.yml
```

Verify only one `network.host` entry exists:

```bash
sudo grep -n "network.host" /etc/elasticsearch/elasticsearch.yml
```

If you see two entries, remove the first one:

```bash
sudo sed -i '<LINE_NUMBER>d' /etc/elasticsearch/elasticsearch.yml
```

### Start and enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### Open firewall (restrict to your subnet)

```bash
sudo ufw allow from 192.168.1.0/24 to any port 9200
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw reload
```

### Verify

```bash
curl -k -u elastic:<YOUR_PASSWORD> https://localhost:9200
```

Expected: JSON response with `"number": "8.x.x"`.

---

## Part 2 — Kibana (Ubuntu)

### Install

```bash
sudo apt install kibana -y
```

### Bind to network interface

Same issue as Elasticsearch — defaults to localhost only:

```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
```

If line exists with value `"localhost"`, delete that line number first:

```bash
sudo sed -i '<LINE_NUMBER>d' /etc/kibana/kibana.yml
```

Then append the correct value:

```bash
echo "server.host: 0.0.0.0" | sudo tee -a /etc/kibana/kibana.yml
```

Verify exactly one entry:

```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
```

### Add encryption keys (required for Security/SIEM features)

Without these, the detection engine will refuse to initialize:

```bash
sudo /usr/share/kibana/bin/kibana-encryption-keys generate
```

Copy the three output lines and append them:

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

### Verify Kibana is up

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

Expected response: `{"acknowledged":true}`

> Note: Kibana runs HTTP locally, not HTTPS. Use `http://localhost:5601` for local curl calls.

---

## Part 3 — Windows Audit Policy (DC / Target)

Run in elevated PowerShell:

```powershell
# Share access events — fires EID 5140 and 5145
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Logon events — fires EID 4624, 4625, 4648
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
```

Both must return `Success and Failure`.

> EID 5145 is fired by the SMB subsystem — no SACL on C:\ is required.

---

## Part 4 — Winlogbeat (Windows)

### Download and extract

Match the version exactly to your Elasticsearch version:

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

### Install as service and push index template

```powershell
cd "C:\Program Files\Winlogbeat"
powershell -ep bypass .\install-service-winlogbeat.ps1
.\winlogbeat.exe setup --index-management -e
```

The setup command connects to Elasticsearch and pushes the index template. It must complete without error before starting the service.

### Start

```powershell
Start-Service winlogbeat
Get-Service winlogbeat
```

Expected: `Running`.

### Verify logs landing in Elasticsearch

From the Ubuntu host:

```bash
curl -k -u elastic:<YOUR_PASSWORD> "https://localhost:9200/winlogbeat-*/_count"
```

Expected: `{"count": <number greater than 0>, ...}`

---

## Part 5 — Kibana Data View and Detection Rule

### Create data view

Hamburger → Stack Management → Data Views → Create data view

- Name: `winlogbeat`
- Index pattern: `winlogbeat-*`
- Timestamp: `@timestamp`

### Create detection rule

Hamburger → Security → Rules → Detection rules (SIEM) → Create new rule

- Type: **Custom query**
- Index: `winlogbeat-*`
- Query:

```kql
event.code: "5145" and winlog.event_data.ShareName: "\\\\*\\C$"
```

- Name: `Admin Share Access - C$ via SMB`
- Severity: `High`
- Risk score: `73`
- Schedule: every 5 minutes, 1 minute look-back

---

## Troubleshooting

### Elasticsearch connection refused from Windows

**Symptom:** Winlogbeat setup fails with `connectex: A connection attempt failed`  
**Cause:** Elasticsearch bound to localhost only, or firewall blocking port 9200  
**Fix:** Add `network.host: 0.0.0.0` to `/etc/elasticsearch/elasticsearch.yml` and open UFW port 9200

### Kibana fails to start — YAML duplicate key error

**Symptom:** `FATAL CLI ERROR YAMLException: duplicated mapping key`  
**Cause:** `server.host` defined twice in `kibana.yml` — once in the default config and once appended  
**Fix:**
```bash
sudo grep -n "server.host" /etc/kibana/kibana.yml
sudo sed -i '<FIRST_LINE_NUMBER>d' /etc/kibana/kibana.yml
```
Always check for existing keys before appending to any yml file.

### Detection engine permissions error in Kibana

**Symptom:** `Detection engine permissions required` in Security → Alerts  
**Cause:** Detection engine index not initialized, or missing encryption keys  
**Fix:** Add encryption keys first, restart Kibana, then POST to the detection engine index endpoint:
```bash
curl -u elastic:<PASSWORD> -X POST "http://localhost:5601/api/detection_engine/index" \
  -H "Content-Type: application/json" -H "kbn-xsrf: true"
```

### Kibana curl returns SSL error locally

**Symptom:** `curl: (35) error:0A00010B:SSL routines::wrong version number`  
**Cause:** Kibana runs HTTP locally; only Elasticsearch uses HTTPS  
**Fix:** Use `http://localhost:5601` for Kibana API calls, `https://localhost:9200` for Elasticsearch

### Winlogbeat index template push fails

**Symptom:** Setup exits with Elasticsearch connection error  
**Cause:** Elasticsearch not yet reachable when setup ran (firewall or binding issue)  
**Fix:** Resolve connectivity first, then re-run `.\winlogbeat.exe setup --index-management -e` before starting the service

---

*Part of the AD-Lab-Research detection engineering series.*  
*Tested on Elasticsearch/Kibana/Winlogbeat 8.19.12 — Ubuntu 22.04 — Windows Server 2019*
