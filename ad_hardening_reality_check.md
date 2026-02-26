# Active Directory: The Hardening Reality Check

> We spend billions monitoring the front door (Authentication) while ignoring the back-office staff handing out master keys (Authorization).

Active Directory rarely fails because of zero-days. It fails because **trust fossilizes**.

---

## The 5 Key Attacks & The Controls That Kill Them

| Attack | The "Paperwork" Reality | The Kill Switch |
|---|---|---|
| **Shadow Credentials** | Adding a public key to a user object's `msDS-KeyCredentialLink` | **ACL Lockdown:** If you can't write to the attribute, you can't add the key. Lock down Write access to all privileged objects. |
| **RBCD** | Writing to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute | **MachineAccountQuota:** Set to 0. Don't let low-tier users create or control high-tier computer objects. |
| **DCSync** | An account requesting password replication via DRS API | **Replication Audit:** Only Domain Controllers should have replication rights. Revoke them from all service accounts immediately. |
| **Golden Ticket** | Forging a TGT because the `KRBTGT` hash was stolen | **Tiered Admin:** You don't "fix" a Golden Ticket — you prevent the access. Rotate the `KRBTGT` password twice after any incident. |
| **AD CS Abuse** | Using misconfigured certificates (SAN) to impersonate users | **Template Governance:** Kill `ENROLLEE_SUPPLIES_SUBJECT`. Treat certificate template permissions like Domain Admin rights. |

---

## The Three Questions That Kill the Mystique

Stop chasing "threat actors." Start answering these three governance questions:

1. **Who can modify directory objects?** *(The Writable Surface)*
2. **What real boundaries exist between tiers?** *(The Blast Radius)*
3. **Are we auditing control-plane changes?** *(ACLs, delegation, replication, templates)*

---

## The Uncomfortable Truth

Red-team tooling feels like sorcery because it automates graph traversal.

But most findings trace back to:

Delegation convenience

Legacy service accounts

Over-broad ACL inheritance

Mis-scoped certificate templates

“Temporary” exceptions that never expired

A disciplined internal audit of ACLs and delegation settings can collapse entire attack classes before a single exploit runs.

Active Directory doesn’t collapse because attackers are geniuses.

It collapses because governance drifts.

And jargon makes drift sound sophisticated.

<img width="305" height="316" alt="wwhite" src="https://github.com/user-attachments/assets/434f597e-4bcc-4b5b-beef-1d6e51f40020" />
