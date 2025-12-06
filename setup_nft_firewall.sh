#!/usr/bin/env bash
#
# Interactive nftables firewall setup (with Cloudflare dynamic IPs + test mode + optional NTP)
# - Backs up /etc/nftables.conf
# - Prompts for SSH whitelist IPs (LAN + external)
# - Optionally enables Cloudflare-only access on ports 80/443
# - Optionally allows outbound NTP (UDP/123) for Authelia/system time sync
# - Dynamically fetches Cloudflare IP ranges when needed
# - Generates new /etc/nftables.conf (using table inet firewall)
# - Validates with nft -c and applies WITHOUT flushing Docker’s tables
# - Optional TEST MODE auto-rolls back to backup after 60s unless confirmed
# - Detects Docker and can add a MASQUERADE rule so containers can reach LAN hosts

set -euo pipefail

NFT_CONF="/etc/nftables.conf"
BACKUP_DIR="/etc/nftables.backups"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
TEMP_CONF="/tmp/nftables.conf.$$"
LAST_BACKUP=""
TEST_MODE="n"
CF_CHOICE="1"
ALLOW_NTP="y"   # default: allow outbound NTP

LAN_ARRAY=()
EXT_ARRAY=()
CF_IPV4_LIST=()
CF_IPV6_LIST=()

#--- Helpers -------------------------------------------------------------------

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
  fi
}

require_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    echo "Error: nft command not found. Install nftables first." >&2
    exit 1
  fi
}

backup_conf() {
  mkdir -p "$BACKUP_DIR"
  if [[ -f "$NFT_CONF" ]]; then
    LAST_BACKUP="${BACKUP_DIR}/nftables.conf.${TIMESTAMP}"
    cp "$NFT_CONF" "$LAST_BACKUP"
    echo "Backup created: $LAST_BACKUP"
  else
    echo "No existing $NFT_CONF found. Skipping backup."
    LAST_BACKUP=""
  fi
}

prompt_test_mode() {
  echo
  echo "=== TEST MODE ==="
  echo "In test mode, new nftables rules are applied temporarily."
  echo "If you do NOT confirm them within 60 seconds, the script will"
  echo "automatically restore the previous firewall from backup (if available)."
  echo
  read -rp "Enable TEST MODE? (recommended the first time) [y/N]: " TEST_MODE
  TEST_MODE="${TEST_MODE:-n}"
  if [[ ! "$TEST_MODE" =~ ^[Yy]$ ]]; then
    TEST_MODE="n"
  else
    TEST_MODE="y"
  fi
}

prompt_ssh_whitelist() {
  echo
  echo "=== SSH Whitelist Configuration (port 22) ==="
  echo "Enter LAN networks allowed to access SSH (port 22)."
  echo "Examples: 192.168.0.0/16, 10.0.0.0/8"
  read -rp "LAN networks (comma-separated, leave blank for none): " LAN_INPUT

  echo
  echo "Enter external IPs allowed to access SSH (your home IP, office, etc)."
  echo "Example: 203.0.xxx.xxx, 44.xx.xxx.xxx"
  read -rp "External IPs (comma-separated, leave blank for none): " EXT_INPUT

  # Normalize into arrays
  IFS=',' read -r -a LAN_ARRAY <<< "${LAN_INPUT// /}"
  IFS=',' read -r -a EXT_ARRAY <<< "${EXT_INPUT// /}"
}

prompt_cloudflare_mode() {
  echo
  echo "=== HTTP/HTTPS (ports 80/443) Hardening ==="
  echo "1) Cloudflare ONLY on ports 80/443 (recommended if using Cloudflare proxy)"
  echo "   - Only Cloudflare edge IPs can reach HTTP/HTTPS"
  echo "   - Server is effectively hidden behind Cloudflare"
  echo "2) Leave ports 80/443 open to the internet"
  echo
  read -rp "Choose 1 or 2 [1]: " CF_CHOICE
  CF_CHOICE="${CF_CHOICE:-1}"
  if [[ "$CF_CHOICE" != "1" && "$CF_CHOICE" != "2" ]]; then
    echo "Invalid choice. Defaulting to 1 (Cloudflare only)."
    CF_CHOICE="1"
  fi
}

prompt_ntp_option() {
  echo
  echo "=== Outbound NTP (UDP/123) for Authelia and System Time Sync ==="
  echo "Authelia performs its own NTP checks. If outbound UDP/123 is blocked,"
  echo "it may log errors or fail startup checks even if system time is OK."
  echo
  echo "1) Allow outbound NTP (UDP/123) [recommended]"
  echo "2) Block outbound NTP (not recommended if using Authelia NTP checks)"
  echo
  read -rp "Allow outbound NTP (UDP/123)? [1]: " NTP_CHOICE
  NTP_CHOICE="${NTP_CHOICE:-1}"
  if [[ "$NTP_CHOICE" == "1" ]]; then
    ALLOW_NTP="y"
  else
    ALLOW_NTP="n"
  fi
}

require_curl_if_cloudflare() {
  if [[ "$CF_CHOICE" == "1" ]]; then
    if ! command -v curl >/dev/null 2>&1; then
      echo "Error: curl is required to fetch Cloudflare IP ranges." >&2
      exit 1
    fi
  fi
}

fetch_cloudflare_ips() {
  if [[ "$CF_CHOICE" != "1" ]]; then
    return 0
  fi

  echo
  echo "Fetching Cloudflare IP ranges from cloudflare.com..."
  local v4_url="https://www.cloudflare.com/ips-v4"
  local v6_url="https://www.cloudflare.com/ips-v6"

  mapfile -t CF_IPV4_LIST < <(curl -fsS "$v4_url" || true)
  mapfile -t CF_IPV6_LIST < <(curl -fsS "$v6_url" || true)

  if ((${#CF_IPV4_LIST[@]} == 0 && ${#CF_IPV6_LIST[@]} == 0)); then
    echo "ERROR: Failed to download Cloudflare IP ranges." >&2
    echo "Please check connectivity and try again." >&2
    exit 1
  fi

  echo "Cloudflare IPv4 ranges: ${#CF_IPV4_LIST[@]} entries"
  echo "Cloudflare IPv6 ranges: ${#CF_IPV6_LIST[@]} entries"
}

print_cf_set_ipv4() {
  echo "    set cloudflare_ipv4 {"
  echo "        type ipv4_addr"
  echo "        flags interval;"
  echo "        elements = {"
  local count=${#CF_IPV4_LIST[@]}
  for i in "${!CF_IPV4_LIST[@]}"; do
    local ip="${CF_IPV4_LIST[$i]}"
    [[ -z "$ip" ]] && continue
    if (( i < count - 1 )); then
      echo "            $ip,"
    else
      echo "            $ip"
    fi
  done
  echo "        }"
  echo "    }"
  echo
}

print_cf_set_ipv6() {
  echo "    set cloudflare_ipv6 {"
  echo "        type ipv6_addr"
  echo "        flags interval;"
  echo "        elements = {"
  local count=${#CF_IPV6_LIST[@]}
  for i in "${!CF_IPV6_LIST[@]}"; do
    local ip="${CF_IPV6_LIST[$i]}"
    [[ -z "$ip" ]] && continue
    if (( i < count - 1 )); then
      echo "            $ip,"
    else
      echo "            $ip"
    fi
  done
  echo "        }"
  echo "    }"
  echo
}

detect_docker_and_offer_nat() {
  echo
  echo "=== Docker / NAT Helper (optional) ==="

  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not detected (docker command not found). Skipping Docker NAT helper."
    return 0
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found. Cannot manage Docker NAT rules automatically."
    echo "If you use Docker containers that talk to LAN hosts, consider adding a MASQUERADE rule manually."
    return 0
  fi

  # Probe Docker availability
  if ! docker info >/dev/null 2>&1; then
    echo "Docker appears to be installed but not running or not accessible. Skipping Docker NAT helper."
    return 0
  fi

  # Try to detect the default bridge subnet
  local docker_subnet
  docker_subnet="$(docker network inspect bridge -f '{{ (index .IPAM.Config 0).Subnet }}' 2>/dev/null || true)"

  if [[ -z "$docker_subnet" ]]; then
    docker_subnet="172.17.0.0/16"
    echo
    echo "Could not auto-detect Docker bridge subnet; defaulting to: ${docker_subnet}"
    read -rp "Enter Docker bridge subnet to use for NAT [${docker_subnet}]: " USER_DOCKER_SUBNET
    docker_subnet="${USER_DOCKER_SUBNET:-$docker_subnet}"
  else
    echo
    echo "Detected Docker bridge subnet: ${docker_subnet}"
  fi

  echo
  echo "If Docker containers (e.g. Traefik) need to talk to LAN hosts (e.g. Node-RED at 192.168.x.x),"
  echo "you should have a MASQUERADE rule so replies can find their way back."
  echo
  echo "Proposed iptables NAT rule:"
  echo "  iptables -t nat -I POSTROUTING 1 -s ${docker_subnet} ! -o docker0 -j MASQUERADE"
  echo
  read -rp "Add this Docker MASQUERADE rule now? [Y/n]: " ADD_NAT
  ADD_NAT="${ADD_NAT:-Y}"

  if [[ "$ADD_NAT" =~ ^[Yy]$ ]]; then
    # Only add if not already present
    if iptables -t nat -C POSTROUTING -s "$docker_subnet" ! -o docker0 -j MASQUERADE 2>/dev/null; then
      echo "MASQUERADE rule for ${docker_subnet} already exists. Skipping."
    else
      echo "Adding MASQUERADE rule for Docker subnet ${docker_subnet}..."
      iptables -t nat -I POSTROUTING 1 -s "$docker_subnet" ! -o docker0 -j MASQUERADE
      echo "Rule added."
    fi

    echo
    read -rp "Persist this NAT rule using iptables-persistent? [y/N]: " PERSIST_NAT
    PERSIST_NAT="${PERSIST_NAT:-n}"

    if [[ "$PERSIST_NAT" =~ ^[Yy]$ ]]; then
      if command -v apt-get >/dev/null 2>&1; then
        echo "Installing iptables-persistent (if needed) and saving rules..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
        iptables-save >/etc/iptables/rules.v4
        echo "iptables NAT rules saved to /etc/iptables/rules.v4"
      else
        echo "apt-get not found. Please save iptables rules manually for persistence."
      fi
    fi
  else
    echo "Skipping Docker MASQUERADE rule."
  fi
}

build_conf() {
  echo
  echo "Building new nftables configuration..."

  {
    echo '#!/usr/sbin/nft -f'
    echo
    # Use our own table to avoid stepping on Docker's inet filter table
    echo 'delete table inet firewall'
    echo 'table inet firewall {'

    #--- Cloudflare sets (only if user chose CF-only mode) --------------------
    if [[ "$CF_CHOICE" == "1" ]]; then
      echo
      echo "    #############################################################"
      echo "    # Cloudflare IP Ranges (fetched dynamically)"
      echo "    #############################################################"
      print_cf_set_ipv4
      print_cf_set_ipv6
    fi

    #----------------- Input chain --------------------------------------------
    cat <<'HEADER'

    #############################################################
    # Filter Rules
    #############################################################

    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established / related
        ct state established,related accept

        #########################################################
        # Docker bridge traffic (containers hitting host)
        # This keeps Docker-based services (Traefik, Authelia, etc.)
        # talking to the host without fighting Docker's own rules.
        #########################################################
        iifname "docker0" accept
        iifname "br-*" accept

        #########################################################
        # Basic ICMP (ping) - optional but handy
        #########################################################
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

HEADER

    #----------------- SSH rules ----------------------------------------------
    echo
    echo "        #########################################################"
    echo "        # SSH (port 22) - allowed IPs"
    echo "        #########################################################"

    if ((${#LAN_ARRAY[@]} == 0 && ${#EXT_ARRAY[@]} == 0)); then
      echo "        # WARNING: No SSH whitelist specified. SSH will be blocked for everyone."
    fi

    # LAN networks (also implicitly "trusted" for SSH)
    for lan in "${LAN_ARRAY[@]}"; do
      [[ -z "$lan" ]] && continue
      echo "        # LAN network allowed to SSH"
      echo "        ip saddr ${lan} tcp dport 22 accept"
    done

    # External IPs
    for ip in "${EXT_ARRAY[@]}"; do
      [[ -z "$ip" ]] && continue
      echo "        # External trusted IP for SSH"
      echo "        ip saddr ${ip} tcp dport 22 accept"
    done

    # Default: drop all other SSH
    echo "        # Drop SSH from all other sources"
    echo "        tcp dport 22 drop"
    echo

    #----------------- HTTP/HTTPS rules ---------------------------------------
    echo "        #########################################################"
    echo "        # HTTP/HTTPS (80/443)"
    echo "        #########################################################"

    if [[ "$CF_CHOICE" == "1" ]]; then
      # Cloudflare only
      cat <<'CFHTTP'
        # Allow HTTP/HTTPS only from Cloudflare
        ip saddr @cloudflare_ipv4 tcp dport {80,443} accept
        ip6 saddr @cloudflare_ipv6 tcp dport {80,443} accept

        # Drop direct access to HTTP/HTTPS from everywhere else
        tcp dport {80,443} drop

CFHTTP
    else
      # Ports 80/443 open to internet
      cat <<'OPENHTTP'
        # Allow HTTP/HTTPS from anywhere
        tcp dport {80,443} accept

OPENHTTP
    fi

    #----------------- Default drop for remaining INPUT traffic ---------------
    cat <<'FOOTER'

        #########################################################
        # Default policy: drop everything else (policy drop)
        #########################################################
        drop
    }

FOOTER

    #----------------- Forward chain (Docker-friendly) ------------------------
    echo
    echo "    #############################################################"
    echo "    # Forward Chain (allow Docker to manage container routing)"
    echo "    #############################################################"
    cat <<'FWD'
    chain forward {
        type filter hook forward priority 0; policy accept;

        # Let Docker/userland manage forwarding; we mainly enforce on input.
        ct state established,related accept
        accept
    }

FWD

    #----------------- Output chain (default accept) -------------------------
    echo
    echo "    #############################################################"
    echo "    # Outbound / Output Chain"
    echo "    #############################################################"
    echo "    chain output {"
    echo "        type filter hook output priority 0; policy accept;"
    echo
    echo "        # Allow established/related outbound"
    echo "        ct state established,related accept"
    echo
    echo "        # DNS + web outbound"
    echo "        udp dport 53 accept"
    echo "        tcp dport {53,80,443} accept"
    echo
    if [[ "$ALLOW_NTP" == "y" ]]; then
      echo "        # Allow outbound NTP for Authelia/system time sync"
      echo "        udp dport 123 accept"
    else
      echo "        # Outbound NTP (UDP/123) intentionally not whitelisted"
    fi
    echo
    echo "        # Default accept for anything else"
    echo "        accept"
    echo "    }"
    echo "}"
  } > "$TEMP_CONF"

  echo "New config written to $TEMP_CONF"
}

apply_conf() {
  echo
  echo "Validating new nftables configuration..."
  if ! nft -c -f "$TEMP_CONF"; then
    echo "ERROR: nftables validation failed. Not applying changes." >&2
    exit 1
  fi

  echo "Validation OK."
  echo
  echo "The following configuration will be installed as $NFT_CONF:"
  echo "----------------------------------------------------------"
  sed 's/^/| /' "$TEMP_CONF"
  echo "----------------------------------------------------------"
  read -rp "Apply this configuration? [y/N]: " CONFIRM
  CONFIRM="${CONFIRM:-n}"

  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted by user. New configuration not applied."
    return
  fi

  cp "$TEMP_CONF" "$NFT_CONF"
  echo "Applying configuration..."
  # IMPORTANT: do NOT flush the entire ruleset, to avoid destroying Docker's tables.
  nft -f "$NFT_CONF"
  systemctl enable nftables >/dev/null 2>&1 || true
  # reload if supported; fallback to restart
  systemctl reload nftables 2>/dev/null || systemctl restart nftables
  echo "nftables rules applied."

  if [[ "$TEST_MODE" == "y" ]]; then
    test_mode_rollback_logic
  else
    echo "TEST MODE is OFF. New firewall rules are permanent."
  fi
}

test_mode_rollback_logic() {
  if [[ -z "$LAST_BACKUP" || ! -f "$LAST_BACKUP" ]]; then
    echo "TEST MODE requested, but no backup found to roll back to."
    echo "New rules remain active. Consider re-running with an existing /etc/nftables.conf."
    return
  fi

  echo
  echo "TEST MODE is ON."
  echo "If you do NOT confirm within 60 seconds, the previous firewall will be restored"
  echo "from backup: $LAST_BACKUP"
  echo

  (
    sleep 60
    echo "TEST MODE: Timeout reached, rolling back to backup: $LAST_BACKUP" | systemd-cat -t nft-test 2>/dev/null || true

    if [[ -f "$LAST_BACKUP" ]]; then
      cp "$LAST_BACKUP" "$NFT_CONF"
    fi

    # Re-apply the backup config, but again do NOT flush the whole ruleset.
    nft -f "$NFT_CONF"
    systemctl reload nftables 2>/dev/null || systemctl restart nftables
  ) &
  local rollback_pid=$!

  read -rp "Confirm that everything works and KEEP these firewall rules? [y/N]: " KEEP
  KEEP="${KEEP:-n}"

  if [[ "$KEEP" =~ ^[Yy]$ ]]; then
    if kill "$rollback_pid" >/dev/null 2>&1; then
      wait "$rollback_pid" 2>/dev/null || true
    fi
    echo "New rules kept. TEST MODE rollback cancelled."
  else
    echo "If you lose connectivity, the old firewall will be restored automatically within 60 seconds."
  fi
}

#--- Main ----------------------------------------------------------------------

require_root
require_nft
backup_conf
prompt_test_mode
prompt_ssh_whitelist
prompt_cloudflare_mode
prompt_ntp_option
require_curl_if_cloudflare
fetch_cloudflare_ips
detect_docker_and_offer_nat
build_conf
apply_conf

echo "Done."
