#!/usr/bin/env python3
# BadRecon — Active Directory enumeration and attack surface mapping
# Copyright (c) 2026 Osher Jacobs
# https://github.com/osherjacobs/AD-Lab-Research
#
# MIT License
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
"""
BadRecon - Active Directory enumeration and attack surface mapping
Author: Osher Jacobs — research use / detection engineering
Usage:  python3 badrecon.py -d <DC_IP> -u <user@domain.local> -p '<password>'
"""
import argparse
import json
import uuid
from impacket.ldap import ldap as impacket_ldap, ldapasn1
from impacket.ldap.ldapasn1 import SDFlagsControl
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.utils.conv import escape_filter_chars

# ── UAC bit flags ─────────────────────────────────────────────────────────────

UAC = {
    'ACCOUNTDISABLE':                     0x00000002,
    'HOMEDIR_REQUIRED':                   0x00000008,
    'LOCKOUT':                            0x00000010,
    'PASSWD_NOTREQD':                     0x00000020,
    'PASSWD_CANT_CHANGE':                 0x00000040,
    'ENCRYPTED_TEXT_PWD_ALLOWED':         0x00000080,
    'NORMAL_ACCOUNT':                     0x00000200,
    'INTERDOMAIN_TRUST_ACCOUNT':          0x00000800,
    'WORKSTATION_TRUST_ACCOUNT':          0x00001000,
    'SERVER_TRUST_ACCOUNT':               0x00002000,
    'DONT_EXPIRE_PASSWORD':               0x00010000,
    'SMARTCARD_REQUIRED':                 0x00040000,
    'TRUSTED_FOR_DELEGATION':             0x00080000,
    'NOT_DELEGATED':                      0x00100000,
    'USE_DES_KEY_ONLY':                   0x00200000,
    'DONT_REQ_PREAUTH':                   0x00400000,
    'PASSWORD_EXPIRED':                   0x00800000,
    'TRUSTED_TO_AUTH_FOR_DELEGATION':     0x01000000,
}

def uac_flag(name):
    return f"(userAccountControl:1.2.840.113556.1.4.803:={UAC[name]})"

def uac_not_flag(name):
    return f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC[name]}))"


# ── Security descriptor helpers ───────────────────────────────────────────────

BINARY_ATTRS = {
    'msDS-ManagedPasswordId',
    'msDS-GroupMSAMembership',
    'objectGUID',
    'objectSid',
    'nTSecurityDescriptor',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
}

def parse_msa_principals(raw_bytes):
    """Extract SIDs from msDS-GroupMSAMembership security descriptor."""
    sids = []
    try:
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw_bytes)
        dacl = sd['Dacl']
        if dacl:
            for ace in dacl['Data']:
                try:
                    sids.append(ace['Ace']['Sid'].formatCanonical())
                except Exception:
                    pass
    except Exception as e:
        sids.append(f"[SD parse error: {e}]")
    return sids

def parse_kds_guid(hex_blob):
    """Extract KDS root key GUID from msDS-ManagedPasswordId blob."""
    try:
        raw = bytes.fromhex(hex_blob)
        if len(raw) < 40:
            return None
        return str(uuid.UUID(bytes_le=raw[24:40]))
    except Exception:
        return None


def parse_pwd_age(val):
    """Convert Windows FILETIME interval to days."""
    try:
        v = int(val)
        if v == 0:
            return "0 (no expiry)"
        days = abs(v) // 864000000000
        return f"{days} days"
    except Exception:
        return val

def parse_pwd_properties(val):
    """Decode pwdProperties bitmask."""
    try:
        v = int(val)
        flags = []
        if v & 1:  flags.append("Complexity required")
        if v & 2:  flags.append("Reversible encryption")
        if v & 8:  flags.append("Lockout admins")
        if v & 16: flags.append("No anon change")
        if v & 32: flags.append("No clear change")
        return flags if flags else ["No restrictions"]
    except Exception:
        return val

def parse_lockout_duration(val):
    """Convert Windows FILETIME interval to minutes."""
    try:
        v = int(val)
        if v == 0:
            return "0 (manual unlock required)"
        mins = abs(v) // 600000000
        return f"{mins} minutes"
    except Exception:
        return val


# ── ACL / DACL edge parser ────────────────────────────────────────────────────

EXTENDED_RIGHTS = {
    '00299570-246d-11d0-a768-00aa006e0529': 'ForceChangePassword',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
    '9b026da6-0d3c-465c-8bee-5199d7165cba': 'DS-Validated-Write-Computer',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated-SPN',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'Validated-DNS-Host-Name',
}

WRITE_PROPERTY_GUIDS = {
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'WriteMember',
    '00fbf30c-91fe-11d1-aebc-0000f80367c1': 'WriteAllowedToAct',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'WriteKeyCredentialLink',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'WriteAccountRestrictions',
}

def _guid_from_bytes(b):
    try:
        return str(uuid.UUID(bytes_le=bytes(b)))
    except Exception:
        return None

def parse_dacl_edges(raw_sd, object_dn, domain_sid=None):
    """Parse nTSecurityDescriptor binary and return BloodHound-style edges."""
    edges = []
    try:
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw_sd)
        dacl = sd['Dacl']
        if not dacl:
            return edges

        for ace in dacl['Data']:
            ace_type = ace['AceType']
            if ace_type not in (0x00, 0x05):
                continue
            try:
                sid_raw = ace['Ace']['Sid'].formatCanonical()
                sid  = resolve_sid(sid_raw, domain_sid)
                mask = int(ace['Ace']['Mask']['Mask'])
            except Exception:
                continue

            if sid in ('S-1-1-0', 'S-1-5-11', 'S-1-5-10', 'S-1-3-0'):
                continue

            if mask & 0x10000000 or (mask & 0x000f01ff) == 0x000f01ff:
                edges.append({'from': sid, 'to': object_dn, 'edge': 'GenericAll'})
                continue

            if mask & 0x00040000:
                edges.append({'from': sid, 'to': object_dn, 'edge': 'WriteDacl'})
            if mask & 0x00080000:
                edges.append({'from': sid, 'to': object_dn, 'edge': 'WriteOwner'})
            if ace_type == 0x00 and mask & 0x00000020:
                edges.append({'from': sid, 'to': object_dn, 'edge': 'GenericWrite'})

            if ace_type == 0x05:
                try:
                    flags    = int(ace['Ace']['Flags'])
                    obj_guid = None
                    if flags & 0x01:
                        obj_guid = _guid_from_bytes(ace['Ace']['ObjectType'])
                    if mask & 0x00000100 and obj_guid:
                        right = EXTENDED_RIGHTS.get(obj_guid, f'ExtendedRight:{obj_guid}')
                        edges.append({'from': sid, 'to': object_dn, 'edge': right})
                    if mask & 0x00000020 and obj_guid:
                        prop = WRITE_PROPERTY_GUIDS.get(obj_guid)
                        if prop:
                            edges.append({'from': sid, 'to': object_dn, 'edge': prop})
                except Exception:
                    pass

    except Exception as e:
        edges.append({'error': str(e), 'object': object_dn})
    return edges


# ── SID resolution ────────────────────────────────────────────────────────────

WELL_KNOWN_SIDS = {
    'S-1-1-0':    'Everyone',
    'S-1-3-0':    'Creator Owner',
    'S-1-3-1':    'Creator Group',
    'S-1-5-7':    'Anonymous',
    'S-1-5-9':    'Enterprise Domain Controllers',
    'S-1-5-10':   'Self',
    'S-1-5-11':   'Authenticated Users',
    'S-1-5-18':   'SYSTEM',
    'S-1-5-19':   'LOCAL SERVICE',
    'S-1-5-20':   'NETWORK SERVICE',
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-546': 'BUILTIN\\Guests',
    'S-1-5-32-547': 'BUILTIN\\Power Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-550': 'BUILTIN\\Print Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
    'S-1-5-32-552': 'BUILTIN\\Replicators',
    'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
    'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
    'S-1-5-32-568': 'BUILTIN\\IIS_IUSRS',
    'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
    'S-1-5-32-582': 'BUILTIN\\Storage Replica Administrators',
    'S-1-5-32-583': 'BUILTIN\\OpenSSH Users',
}

DOMAIN_RIDS = {
    '500': 'Administrator',
    '501': 'Guest',
    '502': 'krbtgt',
    '512': 'Domain Admins',
    '513': 'Domain Users',
    '514': 'Domain Guests',
    '515': 'Domain Computers',
    '516': 'Domain Controllers',
    '517': 'Cert Publishers',
    '518': 'Schema Admins',
    '519': 'Enterprise Admins',
    '520': 'Group Policy Creator Owners',
    '521': 'Read-only Domain Controllers',
    '522': 'Cloneable Domain Controllers',
    '525': 'Protected Users',
    '526': 'Key Admins',
    '527': 'Enterprise Key Admins',
    '553': 'RAS and IAS Servers',
    '571': 'Allowed RODC Password Replication Group',
    '572': 'Denied RODC Password Replication Group',
}

def resolve_sid(sid, domain_sid=None):
    """Resolve SID to name. Falls back to raw SID for unknown accounts."""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    if domain_sid and sid.startswith(domain_sid + '-'):
        rid = sid.split('-')[-1]
        if rid in DOMAIN_RIDS:
            return DOMAIN_RIDS[rid]
    return sid


# ── ADCS ESC detection constants ─────────────────────────────────────────────

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT          = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_NO_SECURITY_EXTENSION              = 0x00080000

CLIENT_AUTH_OIDS = {
    '1.3.6.1.5.5.7.3.2',
    '1.3.6.1.5.2.3.4',
    '1.3.6.1.4.1.311.20.2.2',
    '2.5.29.37.0',
}

CERT_REQUEST_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'

LOW_PRIV_SIDS = {
    'Everyone', 'Authenticated Users', 'Domain Users',
    'Domain Computers', 'BUILTIN\\Users'
}

HIGH_PRIV_SIDS = {
    'Domain Admins', 'Enterprise Admins', 'SYSTEM',
    'BUILTIN\\Administrators', 'Administrator',
    'Schema Admins', 'Group Policy Creator Owners',
    'Domain Controllers', 'Enterprise Domain Controllers',
}

EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

def _esc_enrollees(sd_raw, domain_sid):
    """Extract SIDs with enroll/autoenroll rights from template SD."""
    ENROLL_GUID     = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    AUTOENROLL_GUID = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    sids = set()
    try:
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_raw)
        dacl = sd['Dacl']
        if not dacl:
            return sids
        for ace in dacl['Data']:
            if ace['AceType'] not in (0x00, 0x05):
                continue
            try:
                sid_raw = ace['Ace']['Sid'].formatCanonical()
                sid     = resolve_sid(sid_raw, domain_sid)
                mask    = int(ace['Ace']['Mask']['Mask'])
                if mask & 0x10000000 or (mask & 0x000f01ff) == 0x000f01ff:
                    sids.add(sid)
                    continue
                if ace['AceType'] == 0x05:
                    flags = int(ace['Ace']['Flags'])
                    if flags & 0x01:
                        g = _guid_from_bytes(ace['Ace']['ObjectType'])
                        if g in (ENROLL_GUID, AUTOENROLL_GUID) and mask & 0x100:
                            sids.add(sid)
                elif mask & 0x100:
                    sids.add(sid)
            except Exception:
                pass
    except Exception:
        pass
    return sids


# ── Output helpers ────────────────────────────────────────────────────────────

def entry_to_dict(entry, fields=None):
    """Convert impacket SearchResultEntry to a flat dict."""
    result = {}
    for attr in entry['attributes']:
        name = str(attr['type'])
        if fields and name not in fields:
            continue
        vals = []
        for v in attr['vals']:
            raw = v.asOctets()
            if name == 'msDS-GroupMSAMembership':
                sids = parse_msa_principals(raw)
                vals = sids if sids else ['[empty SD]']
                break
            elif name in BINARY_ATTRS:
                vals.append(raw.hex())
            else:
                try:
                    vals.append(str(v))
                except Exception:
                    vals.append(raw.hex())
        if vals:
            result[name] = vals[0] if len(vals) == 1 else vals
    return result

def print_entries(label, entries, fields=None):
    print(f"\n{'='*60}")
    print(f"  {label} ({len(entries)} results)")
    print(f"{'='*60}")
    for e in entries:
        row = entry_to_dict(e, fields)
        if row:
            print(json.dumps(row, indent=2))


# ── Core class ────────────────────────────────────────────────────────────────

class BadRecon:
    def __init__(self, dc, user, password):
        if '@' in user:
            uname  = user.split('@')[0]
            domain = user.split('@')[1]
        else:
            raise ValueError("User must be user@domain.local format")

        self.base   = 'DC=' + ',DC='.join(domain.split('.'))
        self.config = f"CN=Configuration,{self.base}"
        self.schema = f"CN=Schema,CN=Configuration,{self.base}"

        self._conn = impacket_ldap.LDAPConnection(f'ldap://{dc}', baseDN=self.base)
        self._conn.login(uname, password, domain=domain)
        self.domain_sid = self._get_domain_sid()
        print(f"[+] Bound as: {uname}@{domain}")
        print(f"[+] Base DN:  {self.base}")
        if self.domain_sid:
            print(f"[+] Domain SID: {self.domain_sid}")

    def _get_domain_sid(self):
        try:
            entries = self._search_raw('(objectClass=domain)',
                                       attributes=['objectSid'], base=self.base)
            for e in entries:
                for attr in e['attributes']:
                    if str(attr['type']) == 'objectSid':
                        raw = attr['vals'][0].asOctets()
                        rev = raw[0]
                        sub_count = raw[1]
                        auth = int.from_bytes(raw[2:8], 'big')
                        subs = []
                        for i in range(sub_count):
                            sub = int.from_bytes(raw[8+i*4:12+i*4], 'little')
                            subs.append(str(sub))
                        return f"S-{rev}-{auth}-{'-'.join(subs)}"
        except Exception:
            pass
        return None

    def _search_config(self, ldap_filter, attributes=None, base=None):
        """Search configuration partition with SD flags control."""
        target = base or self.config
        attrs  = [] if (attributes is None or attributes == ['*']) else attributes
        sc     = impacket_ldap.SimplePagedResultsControl(size=200)
        sd_ctl = SDFlagsControl(criticality=True, flags=7)
        results = []
        try:
            resp = self._conn.search(
                searchBase=target,
                searchFilter=ldap_filter,
                attributes=attrs,
                sizeLimit=0,
                searchControls=[sc, sd_ctl]
            )
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    results.append(item)
        except Exception as e:
            print(f"[-] Config search error: {e}")
        return results

    def _search_raw(self, ldap_filter, attributes=None, base=None):
        target = base or self.base
        attrs  = [] if (attributes is None or attributes == ['*']) else attributes
        sc     = impacket_ldap.SimplePagedResultsControl(size=200)
        results = []
        try:
            resp = self._conn.search(
                searchBase=target,
                searchFilter=ldap_filter,
                attributes=attrs,
                sizeLimit=0,
                searchControls=[sc]
            )
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    results.append(item)
        except Exception:
            pass
        return results

    def _search(self, ldap_filter, attributes=None, base=None):
        target = base or self.base
        attrs  = [] if (attributes is None or attributes == ['*']) else attributes
        sc     = impacket_ldap.SimplePagedResultsControl(size=200)
        results = []
        try:
            resp = self._conn.search(
                searchBase=target,
                searchFilter=ldap_filter,
                attributes=attrs,
                sizeLimit=0,
                searchControls=[sc]
            )
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    results.append(item)
        except Exception as e:
            print(f"[-] Search error ({ldap_filter}): {e}")
        return results


    def get_password_policy(self):
        """Retrieve domain password and lockout policy."""
        return self._search(
            "(objectClass=domain)",
            attributes=[
                'minPwdLength', 'maxPwdAge', 'minPwdAge',
                'pwdHistoryLength', 'pwdProperties',
                'lockoutThreshold', 'lockoutDuration',
                'lockOutObservationWindow'
            ]
        )

    # ── Users ─────────────────────────────────────────────────────

    def get_users(self, extra=''):
        return self._search(f"(&(samAccountType=805306368){extra})")

    def get_enabled_users(self):
        return self.get_users(uac_not_flag('ACCOUNTDISABLE'))

    def get_disabled_users(self):
        return self.get_users(uac_flag('ACCOUNTDISABLE'))

    def get_admincount(self):
        return self.get_users("(admincount=1)")

    def get_asreproastable(self):
        return self.get_users(uac_flag('DONT_REQ_PREAUTH'))

    def get_kerberoastable(self):
        return self.get_users("(servicePrincipalName=*)")

    def get_no_password_required(self):
        return self.get_users(uac_flag('PASSWD_NOTREQD'))

    def get_password_never_expires(self):
        return self.get_users(uac_flag('DONT_EXPIRE_PASSWORD'))

    def get_des_only(self):
        return self.get_users(uac_flag('USE_DES_KEY_ONLY'))

    def get_smartcard_required(self):
        return self.get_users(uac_flag('SMARTCARD_REQUIRED'))

    # ── Delegation ────────────────────────────────────────────────

    def get_unconstrained_users(self):
        return self.get_users(uac_flag('TRUSTED_FOR_DELEGATION'))

    def get_unconstrained_computers(self):
        return self._search(
            f"(&(samAccountType=805306369){uac_flag('TRUSTED_FOR_DELEGATION')})"
        )

    def get_constrained_users(self):
        return self.get_users("(msds-allowedtodelegateto=*)")

    def get_constrained_computers(self):
        return self._search(
            "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))"
        )

    def get_s4u2self(self):
        return self.get_users(uac_flag('TRUSTED_TO_AUTH_FOR_DELEGATION'))

    def get_rbcd_targets(self):
        return self._search(
            "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            attributes=['cn', 'distinguishedName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
        )

    # ── Computers ─────────────────────────────────────────────────

    def get_computers(self, extra=''):
        return self._search(f"(&(samAccountType=805306369){extra})")

    def get_dcs(self):
        return self.get_computers(uac_flag('SERVER_TRUST_ACCOUNT'))

    def get_computers_by_os(self, os_string):
        safe = escape_filter_chars(os_string).replace(r'\2a', '*')
        return self.get_computers(f"(operatingsystem={safe})")

    # ── Managed Service Accounts ──────────────────────────────────

    def get_gmsa(self):
        return self._search(
            "(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=[
                'sAMAccountName', 'distinguishedName',
                'msDS-GroupMSAMembership',
                'msDS-ManagedPasswordInterval',
                'msDS-ManagedPasswordId',
                'PrincipalsAllowedToRetrieveManagedPassword',
                'servicePrincipalName', 'whenCreated', 'whenChanged'
            ]
        )

    def get_dmsa(self):
        return self._search(
            "(objectClass=msDS-DelegatedManagedServiceAccount)",
            attributes=[
                'sAMAccountName', 'distinguishedName',
                'msDS-GroupMSAMembership',
                'msDS-ManagedPasswordInterval',
                'msDS-ManagedPasswordId',
                'msDS-DelegatedMSAState',
                'msDS-SupersededServiceAccountDN',
                'PrincipalsAllowedToRetrieveManagedPassword',
                'servicePrincipalName', 'whenCreated', 'whenChanged'
            ]
        )

    def get_all_managed_accounts(self):
        """All gMSA and dMSA - Golden dMSA target surface."""
        return self._search(
            "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-DelegatedManagedServiceAccount))",
            attributes=[
                'sAMAccountName', 'distinguishedName', 'objectClass',
                'msDS-ManagedPasswordInterval',
                'msDS-ManagedPasswordId',
                'msDS-GroupMSAMembership',
                'msDS-DelegatedMSAState',
                'msDS-SupersededServiceAccountDN',
                'PrincipalsAllowedToRetrieveManagedPassword',
                'servicePrincipalName', 'memberOf',
                'whenCreated', 'whenChanged'
            ]
        )

    # ── Groups ────────────────────────────────────────────────────

    def get_groups(self, extra=''):
        return self._search(f"(&(objectCategory=group){extra})")

    def get_group_members_recursive(self, group_dn):
        safe = escape_filter_chars(group_dn)
        return self._search(
            f"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={safe}))"
        )

    # ── GPO / OU / Sites / Subnets ────────────────────────────────

    def get_gpos(self):
        return self._search("(&(objectCategory=groupPolicyContainer))",
                            attributes=['displayName', 'gPCFileSysPath',
                                        'distinguishedName', 'whenChanged'])

    def get_ous(self):
        return self._search("(&(objectCategory=organizationalUnit))",
                            attributes=['name', 'distinguishedName',
                                        'gpLink', 'description'])

    def get_sites(self):
        return self._search("(&(objectCategory=site))", base=self.config)

    def get_subnets(self):
        return self._search("(&(objectCategory=subnet))", base=self.config)

    # ── Schema / ACL primitives ───────────────────────────────────

    def get_schema_guids(self):
        return self._search("(schemaIDGUID=*)",
                            attributes=['name', 'schemaIDGUID', 'adminDescription'],
                            base=self.schema)

    def get_extended_rights(self):
        return self._search("(objectClass=controlAccessRight)",
                            attributes=['name', 'rightsGuid', 'appliesTo'],
                            base=self.config)

    # ── DFS ───────────────────────────────────────────────────────

    def get_dfs_v1(self):
        return self._search("(&(objectClass=fTDfs))")

    def get_dfs_v2(self):
        return self._search("(&(objectClass=msDFS-Linkv2))")

    # ── DNS zones ─────────────────────────────────────────────────

    def get_dns_zones(self):
        return self._search("(objectClass=dnsZone)",
                            attributes=['name', 'distinguishedName'])

    def get_dns_records(self):
        return self._search("(objectClass=dnsNode)",
                            attributes=['name', 'dnsRecord', 'distinguishedName'])

    # ── Passthrough ───────────────────────────────────────────────

    def custom(self, ldap_filter, attributes=None, base=None):
        return self._search(ldap_filter, attributes=attributes, base=base)

    def get_acl_edges(self, target_filter='(objectClass=*)', target_dn=None):
        """Enumerate nTSecurityDescriptor on objects and return DACL edges."""
        base = target_dn or self.base
        entries = self._search(
            target_filter,
            attributes=['distinguishedName', 'nTSecurityDescriptor', 'sAMAccountName'],
            base=base
        )
        all_edges = []
        for entry in entries:
            dn = None
            raw_sd = None
            for attr in entry['attributes']:
                name = str(attr['type'])
                if name == 'distinguishedName':
                    try:
                        dn = str(attr['vals'][0])
                    except Exception:
                        pass
                elif name == 'nTSecurityDescriptor':
                    try:
                        raw_sd = attr['vals'][0].asOctets()
                    except Exception:
                        pass
            if dn and raw_sd:
                edges = parse_dacl_edges(raw_sd, dn, self.domain_sid)
                all_edges.extend(edges)
        seen = set()
        deduped = []
        for e in all_edges:
            key = (e.get('from'), e.get('to'), e.get('edge'))
            if key not in seen:
                seen.add(key)
                deduped.append(e)
        return deduped

    # ── ADCS enumeration ──────────────────────────────────────────

    def get_cas(self):
        ca_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config}"
        return self._search_config(
            "(objectClass=pKIEnrollmentService)",
            attributes=['cn', 'displayName', 'dNSHostName', 'distinguishedName',
                        'certificateTemplates', 'flags', 'nTSecurityDescriptor'],
            base=ca_base
        )

    def get_cert_templates(self):
        tmpl_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config}"
        return self._search_config(
            "(objectClass=pKICertificateTemplate)",
            attributes=['cn', 'displayName', 'distinguishedName',
                        'msPKI-Certificate-Name-Flag',
                        'msPKI-Enrollment-Flag',
                        'msPKI-RA-Signature',
                        'pKIExtendedKeyUsage',
                        'msPKI-Certificate-Application-Policy',
                        'nTSecurityDescriptor',
                        'msPKI-Template-Schema-Version'],
            base=tmpl_base
        )

    def enumerate_adcs(self):
        """Full ADCS enumeration with ESC1-ESC7/ESC9 classification."""
        results = {'cas': [], 'templates': [], 'findings': []}

        for e in self.get_cas():
            ca = {}
            raw_sd = None
            for attr in e['attributes']:
                name = str(attr['type'])
                if name == 'nTSecurityDescriptor':
                    try:
                        raw_sd = attr['vals'][0].asOctets()
                    except Exception:
                        pass
                elif name in BINARY_ATTRS:
                    try:
                        ca[name] = attr['vals'][0].asOctets().hex()
                    except Exception:
                        pass
                else:
                    try:
                        vals = [str(v) for v in attr['vals']]
                        ca[name] = vals[0] if len(vals) == 1 else vals
                    except Exception:
                        ca[name] = attr['vals'][0].asOctets().hex()

            try:
                flags = int(ca.get('flags', '0'))
                if flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
                    results['findings'].append({
                        'esc': 'ESC6',
                        'ca':  ca.get('cn', '?'),
                        'detail': 'EDITF_ATTRIBUTESUBJECTALTNAME2 enabled — CA accepts SAN from request'
                    })
            except Exception:
                pass

            if raw_sd:
                ca_edges = parse_dacl_edges(raw_sd, ca.get('distinguishedName', ''), self.domain_sid)
                manage_rights = {'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite'}
                for edge in ca_edges:
                    if edge.get('edge') in manage_rights and edge.get('from') in LOW_PRIV_SIDS:
                        results['findings'].append({
                            'esc':    'ESC7',
                            'ca':     ca.get('cn', '?'),
                            'detail': f"{edge['from']} has {edge['edge']} on CA object"
                        })

            results['cas'].append(ca)

        for e in self.get_cert_templates():
            tmpl = {}
            raw_sd = None
            for attr in e['attributes']:
                name = str(attr['type'])
                if name == 'nTSecurityDescriptor':
                    try:
                        raw_sd = attr['vals'][0].asOctets()
                    except Exception:
                        pass
                elif name in BINARY_ATTRS:
                    try:
                        tmpl[name] = attr['vals'][0].asOctets().hex()
                    except Exception:
                        pass
                else:
                    try:
                        vals = [str(v) for v in attr['vals']]
                        tmpl[name] = vals[0] if len(vals) == 1 else vals
                    except Exception:
                        pass

            name_flag       = int(tmpl.get('msPKI-Certificate-Name-Flag', '0'))
            enrollment_flag = int(tmpl.get('msPKI-Enrollment-Flag', '0'))
            ra_sig          = int(tmpl.get('msPKI-RA-Signature', '0'))
            ekus            = tmpl.get('pKIExtendedKeyUsage', [])
            if isinstance(ekus, str):
                ekus = [ekus]
            app_policy      = tmpl.get('msPKI-Certificate-Application-Policy', [])
            if isinstance(app_policy, str):
                app_policy = [app_policy]
            all_ekus = set(ekus) | set(app_policy)

            enrollee_sids = set()
            if raw_sd:
                enrollee_sids = _esc_enrollees(raw_sd, self.domain_sid)

            tmpl_name  = tmpl.get('cn', tmpl.get('displayName', '?'))
            has_san    = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            has_auth   = bool(all_ekus & CLIENT_AUTH_OIDS)
            low_priv   = bool(enrollee_sids - HIGH_PRIV_SIDS)
            sd_missing = raw_sd is None

            if has_san and has_auth and (low_priv or sd_missing):
                results['findings'].append({
                    'esc':      'ESC1',
                    'template': tmpl_name,
                    'detail':   'Enrollee supplies SAN + client auth EKU + low-priv enrollment',
                    'enrollees': list(enrollee_sids - HIGH_PRIV_SIDS) if not sd_missing else ['[unverified]']
                })

            has_any = ('2.5.29.37.0' in all_ekus) or len(all_ekus) == 0
            if has_any and (low_priv or sd_missing):
                results['findings'].append({
                    'esc':      'ESC2',
                    'template': tmpl_name,
                    'detail':   'Any Purpose EKU or no EKU restriction + low-priv enrollment',
                    'enrollees': list(enrollee_sids - HIGH_PRIV_SIDS) if not sd_missing else ['[unverified]']
                })

            if CERT_REQUEST_AGENT_OID in all_ekus and (low_priv or sd_missing) and ra_sig == 0:
                results['findings'].append({
                    'esc':      'ESC3',
                    'template': tmpl_name,
                    'detail':   'Certificate Request Agent EKU + low-priv enrollment',
                    'enrollees': list(enrollee_sids - HIGH_PRIV_SIDS) if not sd_missing else ['[unverified]']
                })

            if raw_sd:
                tmpl_edges = parse_dacl_edges(raw_sd, tmpl_name, self.domain_sid)
                write_rights = {'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite'}
                for edge in tmpl_edges:
                    if edge.get('edge') in write_rights and edge.get('from') in LOW_PRIV_SIDS:
                        results['findings'].append({
                            'esc':      'ESC4',
                            'template': tmpl_name,
                            'detail':   f"{edge['from']} has {edge['edge']} on template"
                        })

            if enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION:
                results['findings'].append({
                    'esc':      'ESC9',
                    'template': tmpl_name,
                    'detail':   'CT_FLAG_NO_SECURITY_EXTENSION set — certificate lacks security extension'
                })

            results['templates'].append(tmpl)

        return results

    def disconnect(self):
        self._conn._socket.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='BadRecon - Active Directory enumeration and attack surface mapping')
    p.add_argument('-d', '--dc',       required=True,  help='DC hostname or IP')
    p.add_argument('-u', '--user',     required=True,  help='user@domain.local')
    p.add_argument('-p', '--password', required=True,  help='Password')
    p.add_argument('--module', default='all',
                   choices=['all', 'users', 'computers', 'groups', 'delegation',
                             'gpo', 'ou', 'acl', 'acledges', 'dns', 'dfs', 'kerberoast',
                             'asrep', 'unconstrained', 'rbcd', 'msa', 'adcs'],
                   help='Module to run (default: all)')
    p.add_argument('--group-dn', help='DN for recursive group membership lookup')
    p.add_argument('--filter',   help='Raw LDAP filter (custom query)')
    p.add_argument('--base',     help='Custom search base DN (default: domain base)')
    return p.parse_args()


def main():
    args = parse_args()
    r = BadRecon(args.dc, args.user, args.password)
    m = args.module

    if args.filter:
        base = args.base if args.base else None
        print_entries("Custom filter", r.custom(args.filter, base=base))
        r.disconnect()
        return

    if m in ('all', 'users'):
        # Password policy with parsed values
        pp_fields = ['minPwdLength', 'maxPwdAge', 'minPwdAge', 'pwdHistoryLength',
                     'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow']
        pp_entries = r.get_password_policy()
        print(f"\n{'='*60}")
        print(f"  Password Policy")
        print(f"{'='*60}")
        for e in pp_entries:
            row = entry_to_dict(e, pp_fields)
            parsed = {}
            for k, v in row.items():
                if k in ('maxPwdAge', 'minPwdAge'):
                    parsed[k] = parse_pwd_age(v)
                elif k == 'pwdProperties':
                    parsed[k] = parse_pwd_properties(v)
                elif k in ('lockoutDuration', 'lockOutObservationWindow'):
                    parsed[k] = parse_lockout_duration(v)
                else:
                    parsed[k] = v
            print(json.dumps(parsed, indent=2))

        print_entries("All Users",              r.get_users(),                  ['sAMAccountName', 'distinguishedName'])
        print_entries("AdminCount=1",           r.get_admincount(),             ['sAMAccountName', 'adminCount'])
        print_entries("Password Never Expires", r.get_password_never_expires(), ['sAMAccountName'])
        print_entries("No Password Required",   r.get_no_password_required(),   ['sAMAccountName'])
        print_entries("Disabled Users",         r.get_disabled_users(),         ['sAMAccountName'])

    if m in ('all', 'kerberoast'):
        print_entries("Kerberoastable", r.get_kerberoastable(), ['sAMAccountName', 'servicePrincipalName'])

    if m in ('all', 'asrep'):
        print_entries("ASREPRoastable", r.get_asreproastable(), ['sAMAccountName'])

    if m in ('all', 'computers'):
        print_entries("All Computers",      r.get_computers(), ['dNSHostName', 'operatingSystem'])
        print_entries("Domain Controllers", r.get_dcs(),       ['dNSHostName'])

    if m in ('all', 'groups'):
        print_entries("All Groups", r.get_groups(), ['sAMAccountName', 'distinguishedName'])

    if m in ('all', 'delegation', 'unconstrained'):
        print_entries("Unconstrained Users",     r.get_unconstrained_users(),     ['sAMAccountName'])
        print_entries("Unconstrained Computers", r.get_unconstrained_computers(), ['dNSHostName'])
        print_entries("Constrained Users",       r.get_constrained_users(),       ['sAMAccountName', 'msDS-AllowedToDelegateTo'])
        print_entries("Constrained Computers",   r.get_constrained_computers(),   ['dNSHostName', 'msDS-AllowedToDelegateTo'])
        print_entries("S4U2Self",                r.get_s4u2self(),                ['sAMAccountName'])

    if m in ('all', 'rbcd'):
        print_entries("RBCD Targets", r.get_rbcd_targets(), ['cn', 'distinguishedName'])

    if m in ('all', 'gpo'):
        print_entries("GPOs", r.get_gpos(), ['displayName', 'gPCFileSysPath'])

    if m in ('all', 'ou'):
        print_entries("OUs", r.get_ous(), ['name', 'distinguishedName', 'gpLink'])

    if m in ('adcs',):
        print("\n[*] Enumerating ADCS — CAs, templates, ESC1-ESC7/ESC9\n")
        data = r.enumerate_adcs()

        print(f"\n{'='*60}")
        print(f"  Certificate Authorities ({len(data['cas'])} found)")
        print(f"{'='*60}")
        for ca in data['cas']:
            print(json.dumps({k: v for k, v in ca.items()
                              if k not in ('nTSecurityDescriptor',)}, indent=2))

        print(f"\n{'='*60}")
        print(f"  Certificate Templates ({len(data['templates'])} found)")
        print(f"{'='*60}")
        for t in data['templates']:
            print(json.dumps({k: v for k, v in t.items()
                              if k not in ('nTSecurityDescriptor',)}, indent=2))

        print(f"\n{'='*60}")
        print(f"  ESC Findings ({len(data['findings'])} found)")
        print(f"{'='*60}")
        if data['findings']:
            for f in data['findings']:
                print(json.dumps(f, indent=2))
        else:
            print("  [+] No ESC vulnerabilities detected")

    if m in ('acledges',):
        print("\n[*] Enumerating ACL edges on privileged objects...")
        print("[*] This queries nTSecurityDescriptor — may be slow on large domains\n")
        filters = [
            ("Users",     "(&(samAccountType=805306368)(adminCount=1))"),
            ("Computers", "(&(samAccountType=805306369))"),
            ("Groups",    "(&(objectCategory=group))"),
            ("GPOs",      "(&(objectCategory=groupPolicyContainer))"),
            ("Domain",    "(objectClass=domain)"),
        ]
        for label, f in filters:
            edges = r.get_acl_edges(target_filter=f)
            if edges:
                print(f"\n{'='*60}")
                print(f"  ACL Edges — {label} ({len(edges)} edges)")
                print(f"{'='*60}")
                for e in edges:
                    if 'error' in e:
                        print(f"  [!] {e}")
                    else:
                        print(json.dumps(e, indent=2))

    if m in ('all', 'acl'):
        print_entries("Extended Rights", r.get_extended_rights(), ['name', 'rightsGuid'])

    if m in ('all', 'dns'):
        print_entries("DNS Zones", r.get_dns_zones(), ['name'])

    if m in ('all', 'dfs'):
        print_entries("DFS v1", r.get_dfs_v1())
        print_entries("DFS v2", r.get_dfs_v2())

    if m in ('all', 'msa'):
        gmsa_fields = ['sAMAccountName', 'distinguishedName', 'msDS-ManagedPasswordInterval',
                       'msDS-ManagedPasswordId', 'PrincipalsAllowedToRetrieveManagedPassword',
                       'whenCreated', 'whenChanged']
        dmsa_fields = ['sAMAccountName', 'distinguishedName', 'msDS-ManagedPasswordInterval',
                       'msDS-ManagedPasswordId', 'msDS-DelegatedMSAState',
                       'msDS-SupersededServiceAccountDN', 'PrincipalsAllowedToRetrieveManagedPassword',
                       'whenCreated', 'whenChanged']

        def print_msa(label, entries, fields):
            print(f"\n{'='*60}")
            print(f"  {label} ({len(entries)} results)")
            print(f"{'='*60}")
            for e in entries:
                row = entry_to_dict(e, fields)
                if row:
                    blob = row.get('msDS-ManagedPasswordId')
                    if blob:
                        guid = parse_kds_guid(blob)
                        if guid:
                            row['kds_root_key_guid'] = guid
                    print(json.dumps(row, indent=2))

        print_msa("gMSA Accounts", r.get_gmsa(), gmsa_fields)
        print_msa("dMSA Accounts", r.get_dmsa(), dmsa_fields)

    if args.group_dn:
        print_entries("Recursive Group Members",
                      r.get_group_members_recursive(args.group_dn),
                      ['sAMAccountName', 'distinguishedName'])
        r.disconnect()
        return

    r.disconnect()


if __name__ == '__main__':
    main()
