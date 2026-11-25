# Spook Yourself: What KeePassXC Leaves in RAM (and What It Doesn't)

Nov 26, 2026

## The premise

Everything here runs against your own machine and your own password database. Nothing is exploited or broken into — you're watching a password manager do what it has to do to work. What unsettles you is seeing a password you never touched this session show up in plaintext in a memory dump.

This is documented, known behaviour, not a vulnerability. It needs root on the box to pull off, and if your disk is encrypted, what reaches the disk stays protected at rest. The point is to see the threat model with your own eyes. Do it with a throwaway test entry — don't dump your real vault and leave plaintext cores lying around.

## What you need

- A Linux box (this run: KeePassXC 2.8.0, Debian 13, kernel 6.12.116+deb13-amd64) running KeePassXC, with a database unlocked.
- `gdb`, which provides the `gcore` command: `sudo apt install gdb`.
- `root` / `sudo`. You will see below why it is required — without it the dump is blocked.
- A disposable test entry, so you grep for a canary instead of your real secrets.

## Tested on

| Variable | Configuration |
| --- | --- |
| KeePassXC | 2.8.0 |
| OS | Debian 13 (trixie) |
| Kernel | 6.12.116+deb13-amd64 |
| Qt | run `keepassxc --version` to capture |
| `ptrace_scope` | 2 (admin-only) |
| Database format | KDBX (confirm in Database settings) |
| Swap / core volume | LVM on LUKS, encrypted at rest |

## Step 1 — Plant a canary

In your test database, create a throwaway entry with a password that is unique and easy to grep for — something that won't collide with real words already in memory:

```
CANARY_7f3a9b2e_KPXC
```

Unlock the database. That is all you need to do — you don't have to click the entry yet. The case where you *never* open it is the interesting one, and it comes later.

## Step 2 — Find the process and check ptrace

```bash
pidof keepassxc
cat /proc/sys/kernel/yama/ptrace_scope
```

`ptrace_scope` controls who is allowed to attach to another process's memory:

- `0` — any same-user process can attach
- `1` — only a parent can attach to its own children
- `2` — admin only (needs `CAP_SYS_PTRACE`, i.e. root)
- `3` — nobody, not even root, until reboot

Most desktops sit at `1` or `2`. The key point: **root bypasses all of this except level 3.** So at scope 2 your `sudo` dump works not because the protection failed, but because you *are* the admin it permits. An ordinary same-user process — malware running as you, without root — would be blocked. That's the restriction working.

## Step 3 — Dump the process memory

```bash
sudo gcore -o kpxc_dump $(pidof keepassxc)
```

This writes a core file like `kpxc_dump.150699` holding the full process memory.

Two traps that will waste your time:

- `gcore: command not found` — it ships inside `gdb`, not as its own package. `sudo apt install gdb` (there is no `gcore` package; `apt install gcore` fails).
- Don't build the PID with a `$`-prefixed literal. `pid=$150699` and `$150699` are both parsed as `${1}50699`: bash takes the empty positional `$1` and appends `50699`, so you dump PID `50699` and get `ptrace: No such process`. Pass the number bare, or use `$(pidof keepassxc)`.

## Step 4 — Search the dump (and the UTF-16 trap)

The obvious command finds nothing — and that empty result fools people into thinking the data isn't there:

```bash
strings -n 6 kpxc_dump.* | grep -a 'CANARY_7f3a9b2e'   # likely empty
```

KeePassXC is a Qt app, and Qt holds strings as **UTF-16 internally** — your canary sits in memory as `C\0A\0N\0A\0R\0Y\0...`, which plain ASCII `strings` scans straight past. Search every encoding instead:

```bash
for enc in s S l b; do
  echo "== -e $enc =="
  strings -e $enc -n 6 kpxc_dump.* | grep -a 'CANARY_7f3a9b2e'
done
```

`-e l` (16-bit little-endian) is the one that lights up. There it is, in cleartext. The blank first attempt was an encoding mistake, not a sign the secret was protected.

## Step 5 — The lock test

A single hit isn't a measurement. The useful question is whether the secret *clears* when you lock the database. Dump in three states and compare:

| State | Secret in RAM? |
| --- | --- |
| Unlocked, entry viewed | Present (UTF-16) |
| Database locked | Gone |
| Locked + 60s | Gone |

```bash
# lock the database in the KeePassXC UI, then:
sudo gcore -o kpxc_locked $(pidof keepassxc)
sleep 60; sudo gcore -o kpxc_delayed $(pidof keepassxc)
for f in kpxc_locked kpxc_delayed; do
  for enc in l b; do strings -e $enc -n6 $f.* | grep -a 'CANARY_7f3a9b2e'; done
done
```

The delayed dump matters: an immediate clear rules out live buffers, but not pages the allocator freed without zeroing. Gone after lock *and* gone a minute later is strong evidence KeePassXC clears the tested secret on lock — though a blank grep shows only that this search found nothing, not that every copy was wiped.

## Step 6 — The part that actually gets you

Pick an entry you have **not** opened, clicked, or copied since unlocking. Grep a short fragment of its password against the unlocked core:

```bash
for enc in s S l b; do strings -e $enc -n4 kpxc_dump.* | grep -a 'FRAGMENT'; done
```

You get the whole password back — not just your fragment. Two things are happening. On this build and test database, unlocking alone was enough to make that unviewed entry's password recoverable — you never had to open it. (Whether that holds across every KeePassXC version, database format, and entry setting is exactly what you'd confirm per configuration.) And `strings` emits contiguous runs of printable bytes, cut at any non-printable byte — so matching a fragment surfaces the whole printable run around it, which usually includes the rest of the password (and sometimes adjacent data too). It isn't reading application fields, just printable sequences.

You don't even need a wildcard. If you want to be explicit about capturing the unknown tail, anchor on a known prefix:

```bash
strings -e l -n4 kpxc_dump.* | grep -ao 'KNOWNPREFIX[[:print:]]*'
```

Note the limit: this only recovers what is already decrypted in the dump. `grep`/`strings` read bytes that are present — they can't brute-force or infer anything that isn't materialised, so an entry that genuinely stayed obfuscated has nothing contiguous to grab. (A literal `*` won't help either: in regex it means "zero or more of the previous char", not "any characters" — that's `.*` or `[[:print:]]*`.)

## Step 7 — Go for the master password

The entry passwords were the warm-up. The master password is the real prize — it unlocks everything and people reuse it. Test it the same way, but on a throwaway database whose master password is itself a canary, so you never grep or print your real one:

```
MASTERCANARY_9f1c_KPXC
```

```bash
# unlock the THROWAWAY db, then dump and search every encoding:
sudo gcore -o kpxc_master $(pidof keepassxc)
for enc in s S l b; do strings -e $enc -n 6 kpxc_master.* | grep -a 'MASTERCANARY_9f1c'; done
```

| State | Master password in RAM? |
| --- | --- |
| Unlocked (throwaway DB) | Not found, any encoding |

Result on this build: **not found even while unlocked.** KeePassXC 2.8.0 doesn't keep your plaintext master passphrase in recoverable form — it derives the key through the KDF and wipes the password. That is better than the original KeePass, which leaked the master password char-by-char from memory (CVE-2023-32784); the remediation guidance there was literally to switch to KeePassXC.

One distinction: "master password not in RAM" is not "can't decrypt from RAM". The *derived* key must be in memory while unlocked — that's how the database is decrypted — so the live database can still be read from memory. What this buys you is narrower but real: your *reusable passphrase* isn't exposed, so a memory compromise doesn't hand over a credential that works on your other accounts. That is the argument for a unique master password plus a keyfile or hardware key as a second factor.

## Why this isn't a vulnerability

What you just did is closely related to CVE-2024-33900 / CVE-2024-33901 (near-duplicate, both disputed) — and the KeePassXC maintainers **dispute it**, on the grounds that holding decrypted secrets in RAM while a database is unlocked is unavoidable in any realistic design. In their words, roughly: dumping plaintext from an unlocked process is normal behaviour, not a bug.

The severity hinges entirely on the precondition, and the precondition is steep:

- The CVE applies only to an attacker who **already has the victim's privileges**.
- You needed `sudo`. On Debian/Ubuntu the default `ptrace_scope` means an ordinary same-user process can't dump another's memory at all.
- An attacker already root on your unlocked session doesn't need any of this — they can keylog you, swap your clipboard, or modify the unlocked database directly.

So it is the documented cost of a password manager doing its job, not a break. Every manager that holds an unlocked vault in RAM has the same property. The right framing for notes is "reproducing CVE-2024-33901 and measuring the lock-clear behaviour" — descriptive, correctly scoped, not a disclosure.

## What actually protects you

Two layers, and you can verify both.

- **Lock clears RAM.** Your Step 5 result showed the secret gone after lock. The exposure window is "unlocked, right now", not "forever".
- **Disk encryption closes the only persistent leak.** The real danger was never the live RAM read — it is the unlocked secret reaching *disk* via swap, hibernation, or a crash core, where it survives a reboot in cleartext. Full-disk / swap encryption (LUKS) makes anything paged out ciphertext at rest.

Check your swap really is encrypted:

```bash
cat /proc/swaps                        # what is active (swapon lives in /usr/sbin)
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT   # trace the stack for a 'crypt' layer
```

Read the stack bottom-up. If your active swap is an LVM volume sitting on a `crypto_LUKS` partition, it is encrypted at rest even though `dmsetup table` on the LVM layer reports `linear` — the encryption is the layer beneath it. With that in place, nothing from this exercise survives power-off — swap and the cores both sit on LUKS (the things to watch are hibernation images, crash dumps, or anything written outside the encrypted volumes). The only exposure left is someone already root on your live, unlocked machine.

## Clean up afterwards

The cores you made hold your secrets in cleartext. So does your shell history — you typed password fragments into `grep` — and your terminal scrollback. Tidy all of it:

```bash
shred -uvz kpxc_dump.* kpxc_locked.* kpxc_delayed.*
history -c; shred -u ~/.bash_history; history -w
xsel -bc 2>/dev/null   # or: wl-copy --clear   (Wayland)
```

One caveat: on an SSD/NVMe or a copy-on-write filesystem, `shred` is best-effort — wear-levelling means the controller may have parked those bytes in cells `shred` can never address. If the volume is LUKS-encrypted, that is moot: at rest it is all ciphertext anyway. If it is *not* encrypted, that — not KeePassXC's memory behaviour — is the thing worth fixing.
