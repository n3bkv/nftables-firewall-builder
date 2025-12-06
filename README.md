
# nftables Firewall Builder  
### **Interactive firewall generator with Cloudflare dynamic IP sets, SSH IP whitelisting, and test-mode rollback**

This project provides a fully interactive Bash script that builds a secure `nftables` firewall configuration for Linux servers.  
It’s ideal for self-hosted environments — including Raspberry Pi, 44Net cloud servers, Node-RED portals, and public web servers behind Cloudflare.

The script:

- **Locks down SSH (port 22) to only your chosen LAN networks + external IPs**  
- **Optionally enforces Cloudflare-only access for ports 80/443 (to further lockdown 44Net-Secure-Portal44Net-Secure-Portal
)**  
- **Automatically fetches Cloudflare edge IP ranges (IPv4+IPv6)**
- **Optionally allows outbound NTP (UDP/123) for Authelia/system time sync**
- **Creates & validates a new nftables.conf**  
- **Includes a 60-second TEST MODE with automatic rollback**  
- **Backs up your existing nftables.conf before applying changes**  
- **Builds clean nftables sets/rules customized to your selections**

---

## Files Included

| File | Description |
|------|-------------|
| `setup_nft_firewall.sh` | The main interactive firewall builder script |
| `README.md` | Project documentation (this file) |

---

## Features

### SSH Hardening (Port 22)
- Prompt-driven whitelist of:
  - LAN networks (e.g., `192.168.0.0/16`)
  - External IP addresses your home IP (e.g., `203.0.xxx.xxx`, `44.xx.xxx.xxx`)
- All other SSH attempts are **dropped by default**

### Web Hardening (Ports 80/443)
Two selectable modes:

1. **Cloudflare-Only Mode (Optional)**  
   - Only Cloudflare edge servers can access 80/443  
   - Direct IP access is blocked  
   - Perfect for protecting portal servers

2. **Open Mode**  
   - Normal public access to 80/443 
   - Use for normal websites

### Cloudflare Dynamic IP Sync
- Script fetches the latest Cloudflare IP ranges from:  
  - `https://www.cloudflare.com/ips-v4`  
  - `https://www.cloudflare.com/ips-v6`
- Automatically generates nftables sets:
  - `set cloudflare_ipv4`
  - `set cloudflare_ipv6`

### Test Mode (Safe First Run)
- When enabled:
  - Firewall applies temporarily
  - You must confirm within 60 seconds
  - Otherwise **script restores from backup**
- Prevents accidental server lockouts

### Backup System
Before making changes, the script creates:

```
/etc/nftables.backups/nftables.conf.YYYYMMDD-HHMMSS
```

---

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/n3bkv/nftables-firewall-builder/main/setup_nft_firewall.sh
chmod +x setup_nft_firewall.sh
sudo ./setup_nft_firewall.sh
```
Tip: Run as root or let the script elevate via sudo.


---

## How It Works

The script guides you through five phases:

### 1. Backup existing rules  
Creates a timestamped backup in `/etc/nftables.backups`.

### 2. Choose Test Mode (optional but recommended)
If enabled, the new rules auto-revert after 60s unless confirmed.

### 3. SSH Whitelisting
Prompted to enter:
- LAN CIDRs (comma separated)
- External IPs (comma separated)

### 4. Cloudflare Mode Selection
Choose between:
- Cloudflare-only
- Open Internet access

### 5. Outbound NTP (UDP/123) for Authelia and System Time Sync (required for portal)
Authelia performs its own NTP checks. If outbound UDP/123 is blocked,
it may log errors or fail startup checks even if system time is OK
Choose between:
- Allow outbound NTP (UDP/123)
- Block outbound NTP (not recommended if using Authelia NTP checks)

### 6. Apply & Validate
- Script generates an optimized nftables.conf
- Uses `nft -c` to validate
- Applies, reloads nftables, and persists on reboot

---

## Example Output

```
=== TEST MODE ===
Enable TEST MODE? [y/N]:

=== SSH Whitelist ===
LAN networks: 192.168.0.0/16
External IPs: 203.0.xxx.xxx, 44.xx.xxx.xxx

=== HTTP/HTTPS Hardening ===
1) Cloudflare ONLY on ports 80/443 (recommended if using Cloudflare proxy
- Only Cloudflare edge IPs can reach HTTP/HTTPS
- Server is effectively hidden behind Cloudflare
2) Leave ports 80/443 open to the internet
Choose 1 or 2 [1]:

Fetching Cloudflare IP ranges...

=== Outbound NTP (UDP/123) for Authelia and System Time Sync (required for portal) ==="
Authelia performs its own NTP checks. If outbound UDP/123 is blocked,
it may log errors or fail startup checks even if system time is OK.
  
1) Allow outbound NTP (UDP/123) [recommended]
2) Block outbound NTP (not recommended if using Authelia NTP checks)
  
Allow outbound NTP (UDP/123)? [1]:

Validation OK.
Apply this configuration? [y/N]:
```

After applying:

```
TEST MODE is ON.
Confirm firewall rules? [y/N]:
```

---

## Test Mode Explained

| Action | Result |
|--------|--------|
| Confirm within 60s | New rules stay active |
| Do nothing | Rules rollback to backup automatically |
| Answer No | Backup restored after timeout |

---

## Docker Compatibility & NAT

This script is designed to play nicely with Docker (Traefik, Authelia, Node-RED, etc.) on the same host.

### Separate nftables table: `inet firewall`

Docker uses iptables in "nft" mode and creates its own tables/chains, e.g.:

- `DOCKER`, `DOCKER-USER`, `DOCKER-FORWARD` in the `filter` table  
- NAT rules in the `nat` table

If you `nft flush ruleset`, you wipe those out and later see errors like:

```text
Failed to Setup IP tables: Unable to enable ACCEPT OUTGOING rule:
(iptables failed: ... DOCKER-FORWARD ... No chain/target/match by that name.)
```

To avoid this, the script:

Uses its own table: table inet firewall { ... }

Applies rules with nft -f /etc/nftables.conf without flushing the entire ruleset

This lets your firewall coexist with Docker’s internal rules.

Input/Forward rules friendly to Docker

In the generated config, the input chain includes:

```text

iifname "docker0" accept
iifname "br-*" accept

```

This allows containers on Docker bridges to talk to the host (for example, Traefik calling Authelia on http://authelia:9091, or hitting host services bound to 127.0.0.1/0.0.0.0).

The forward chain is also Docker-friendly:

```text

chain forward {
    type filter hook forward priority 0; policy accept;

    ct state established,related accept
    accept
}

```

This leaves container-to-container and container-to-LAN routing to Docker and any iptables rules it manages.

Docker NAT helper (MASQUERADE)

If Docker is installed and running, the script will offer an optional NAT helper step:

It detects (or prompts for) the Docker bridge subnet (e.g. 172.17.0.0/16).

It offers to add a MASQUERADE rule to the iptables nat table:

```text

iptables -t nat -I POSTROUTING 1 -s <docker-subnet> ! -o docker0 -j MASQUERADE


```

Why this matters:

Without NAT, when a container (e.g. Traefik at 172.18.0.x) calls a LAN host (e.g. Node-RED at 192.168.50.100:1880), the LAN host sees a source IP in 172.18.0.0/16 and has no route back → connections hang.

With MASQUERADE, the source is rewritten to the host LAN IP (e.g. 192.168.50.52), and replies just work.

The script can also optionally persist this NAT rule via iptables-persistent if apt-get is available:

```text

sudo apt-get install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4

```

You can rerun the script later to adjust firewall rules without breaking Docker, and the NAT rule will remain intact.

---


## Requirements

- Linux system with **nftables**
- `curl` (only if Cloudflare mode enabled)
- Bash shell

---

## Compatibility

Tested on:

- Raspberry Pi OS  


---

## License

MIT License © 2025 Dave (N3BKV) - feel free to use, modify and distribute.


---

## Support This Project

If you find this useful, star ⭐ the repo! It helps others discover it.

