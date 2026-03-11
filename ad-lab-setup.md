# AD Lab Setup — PtH / PtT / Golden Ticket

## Requirements

| Component | Spec |
|-----------|------|
| Host RAM | 16GB minimum, 32GB recommended |
| Hypervisor | VMware Workstation / VirtualBox / Hyper-V |
| DC ISO | Windows Server 2019 or 2022 Evaluation (free from Microsoft) |
| Workstation ISO | Windows 11 Evaluation (free from Microsoft) |
| Attacker | Kali Linux (latest) |

ISO downloads: https://www.microsoft.com/en-us/evalcenter/

---

## VM Specs

| VM | OS | RAM | Disk | IP |
|----|----|-----|------|----|
| DC01 | Windows Server 2019/2022 | 4GB | 60GB | 192.168.56.10 |
| WS01 | Windows 11 | 4GB | 60GB | 192.168.56.20 |
| Kali | Kali Linux | 4GB | 80GB | 192.168.56.30 |

Set all VMs to **Host-Only** network adapter (same subnet, no internet required). Do not use NAT — Host-Only ensures the vulnerable lab is isolated from your home network.

---

## Step 1 — Install Windows Server on DC01

1. Install Windows Server — select **Desktop Experience**
2. Set Administrator password: `P@ssw0rd123!`
3. Set static IP:
   - IP: `192.168.56.10`
   - Subnet: `255.255.255.0`
   - DNS: `127.0.0.1`

---

## Step 2 — Promote DC01 to Domain Controller

Open PowerShell as Administrator:

```powershell
# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC — creates new forest
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Force
```

Server will reboot automatically. After reboot, login as `LAB\Administrator`.

---

## Step 3 — Create Domain Users

```powershell
# Create standard user
New-ADUser -Name "Alice" `
  -SamAccountName "alice" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true

# Create Domain Admin
New-ADUser -Name "Bob" `
  -SamAccountName "bob" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members "bob"
```

---

## Step 4 — Join WS01 to Domain

On WS01, set static IP and DNS pointing to DC:
- IP: `192.168.56.20`
- DNS: `192.168.56.10`

```powershell
# Join domain
Add-Computer -DomainName "lab.local" `
  -Credential (Get-Credential) `
  -Restart
```

Login with `LAB\alice` or `LAB\bob` to verify domain join.

---

## Step 5 — Disable Defender on WS01 (lab only)

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

> **Note:** Do this on VMs only. Never on your host machine.

---

## Verify Connectivity from Kali

```bash
ping 192.168.56.10   # DC01
ping 192.168.56.20   # WS01
nmap -sV 192.168.56.10
```

## Step 6 — Snapshot Everything

Before starting any attack practice, take a snapshot of all three VMs. AD environments break easily — locked accounts, corrupted databases, misconfigured DNS. Snapshots let you restore to a clean state without rebuilding from scratch.

---

## Recommended Kali Tooling

For attack practice, it is recommended to install the following tools on Kali:

- **Impacket** — Python toolkit for network protocol interaction and AD attacks
- **BloodHound** — AD enumeration and attack path visualization
- **Neo4j** — Required backend database for BloodHound

Environment is ready for domain attack practice. Certain administrator UAC settings / SMB signing settings on the DC may need altering but that is not covered in this guide.
