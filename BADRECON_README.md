# BadRecon

**Active Directory & AD CS Enumeration Framework**

https://github.com/osherjacobs/AD-Lab-Research/blob/main/badrecon.py

BadRecon is a Python-based Active Directory and AD CS enumeration framework focused on identity graph extraction and detection engineering signal generation in modern hardened Windows environments.

It was built as a byproduct of lab work reproducing Bad Successor (CVE-2025-53779) and Golden dMSA attack chains on Windows Server 2025. The immediate problem: every existing Python LDAP library failed the bind against LDAP-signing-enforced Server 2025. BadRecon solves that using impacket's NTLM backend.

The goal is not enumeration for its own sake. It is structured visibility into identity relationships, delegation boundaries, certificate issuance risk surfaces — and the detection signal each one generates.

Built with assistance from Anthropic's Claude LLM. Each module builds on existing research and tooling; the implementation, assembly, and detection framing are original contributions.

---

## Important Warning / Disclaimer

**This tool is provided for authorized security research, defensive analysis, and authorized penetration testing only.**

- Use of this tool against systems you do not own or do not have explicit written permission to test may violate applicable laws.
- The author assumes **no liability** for any misuse, damage, or legal consequences resulting from the use of this software.
- **Use entirely at your own risk.**

By using BadRecon, you acknowledge that you are responsible for ensuring full compliance with all relevant laws, regulations, and organizational policies.

---

## License

BadRecon — Active Directory enumeration and attack surface mapping  
Copyright (c) 2026 Osher Jacobs  
https://github.com/osherjacobs/AD-Lab-Research

**MIT License**

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the "Software"), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,  
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER  
DEALINGS IN THE SOFTWARE.

---

## Development Note

Portions of this codebase were developed with assistance from Anthropic's Claude.  
The overall architecture, integration, detection engineering logic, and final implementation are original work by the author.  
No proprietary or closed-source code was used.

---

## Design Goals

Modern Active Directory environments require tooling that reflects three realities:
- Legacy LDAP tooling assumptions no longer hold in hardened domains — LDAP signing enforcement breaks most Python LDAP stacks against Server 2022/2025
- Identity compromise paths are graph-based, not object-based
- Detection engineering requires relationship-aware telemetry, not flat enumeration

BadRecon focuses on:
- Reproducible LDAP access under hardened configurations (NTLM + signing, port 389)
- Relationship-first data modeling — identity and permission graph extraction
- Detection-oriented normalization of AD and AD CS artifacts

---

## Requirements
```bash
pip3 install impacket ldap3
```

Python 3.10+. Tested against Windows Server 2022 and 2025 with LDAP signing enforced. LDAPS not required.

---

## Usage
```bash
python3 badrecon.py -d <DC_IP> -u <user@domain.local> -p '<password>' [--module <module>]
```

### Arguments

| Argument       | Description                                      |
|----------------|--------------------------------------------------|
| `-d`, `--dc`   | DC IP or hostname                                |
| `-u`, `--user` | Username in `user@domain.local` format           |
| `-p`, `--password` | Password                                     |
| `--module`     | Module to run (default: `all`)                   |
| `--group-dn`   | DN for recursive group membership lookup         |
| `--filter`     | Raw LDAP filter — passthrough query              |
| `--base`       | Custom search base DN (default: domain base)     |

---

## Capabilities

### Identity & Directory Enumeration
- All users with adminCount, password policy flags, disabled accounts
- Kerberoastable accounts (`--module kerberoast`)
- AS-REP roastable accounts (`--module asrep`)
- Computer objects, groups, recursive membership

### Delegation Surface
Unconstrained, Constrained, S4U2Self, RBCD targets

### ACL Edge Enumeration (`--module acledges`)
BloodHound-style directed edges from `nTSecurityDescriptor` (opt-in only)

### Managed Service Accounts (`--module msa`)
gMSA + dMSA with KDS root key GUID extraction

### AD CS Enumeration (`--module adcs`)
CA + template enumeration with ESC1–ESC9 classification

### Other Modules
GPO, OU, DNS, DFS, raw filter passthrough, etc.

---

## Research Foundations & Credits

| Component                        | Source                              | License / Type       |
|----------------------------------|-------------------------------------|----------------------|
| LDAP filter set                  | PowerView (Harmj0y)                 | MIT                  |
| LDAP transport                   | impacket (Fortra)                   | Apache 2.0           |
| Filter escaping                  | ldap3 (Giovanni Cannata)            | LGPL                 |
| Golden dMSA research             | Adi Malyanker, Semperis             | Published research   |
| AD CS ESC framework              | SpecterOps                          | Published research   |
| LLM assistance                   | Claude (Anthropic)                  | Tooling aid          |
| Implementation & Detection       | Osher Jacobs                        | Original work        |

---

## NOTICE

BadRecon is an independent implementation and does not include or redistribute proprietary code from referenced research or tooling projects.

---

## Final Disclaimer

This tool is intended for **authorized security testing, research, and defensive analysis only**.  
Users are fully responsible for compliance with all applicable laws and policies.
