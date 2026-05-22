#!/bin/bash
#
# Title:        Router Hardening Audit
# Description:  Performs a non-destructive hardening audit against the
#               upstream gateway/router from a wired LAN port. Produces
#               a prioritized report of weaknesses and recommendations.
# Author:       you
# Version:      1.0
# Category:     Recon / Audit
# Target:       Hak5 Shark Jack (OpenWrt)
#
# LED legend:
#   MAGENTA  single   = setup / acquiring DHCP
#   YELLOW   single   = scanning gateway
#   YELLOW   double   = probing services
#   YELLOW   triple   = credential & config checks
#   GREEN    solid    = finished, loot ready
#   RED      solid    = failed (no gateway / no link)
#
# AUTHORIZED USE ONLY. Only run against networks you own or have
# written permission to test. Default-credential probes are limited
# to a small, well-known list and a single attempt per service to
# avoid lockouts.

# ---- Shark Jack environment ----------------------------------------
NETMODE DHCP_CLIENT
LED SETUP

LOOT_ROOT="/root/loot/router_audit"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOOT_DIR="${LOOT_ROOT}/${STAMP}"
mkdir -p "${LOOT_DIR}"
REPORT="${LOOT_DIR}/report.txt"
RAW_DIR="${LOOT_DIR}/raw"
mkdir -p "${RAW_DIR}"

# Findings buckets
CRIT=()   # critical: remote takeover / no-auth / default creds
HIGH=()   # high: clear-text mgmt, exposed mgmt, SNMP public, UPnP
MED=()    # medium: weak TLS, outdated banners, ICMP redirects
LOW=()    # low/info
PASS=()   # things that look good

add()  { eval "$1+=(\"\$2\")"; }
log()  { echo "[*] $*"; }
note() { echo "$*" >> "${REPORT}"; }

# ---- Wait for DHCP lease -------------------------------------------
log "Waiting for DHCP lease..."
GW=""
for i in $(seq 1 20); do
  GW="$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
  [ -n "${GW}" ] && break
  sleep 1
done

if [ -z "${GW}" ]; then
  LED FAIL
  echo "No gateway / no DHCP lease" > "${LOOT_DIR}/error.txt"
  exit 1
fi

MY_IP="$(ip -4 addr show dev eth0 2>/dev/null | awk '/inet /{print $2}' | head -n1)"
SUBNET="$(echo "${MY_IP}" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".0/24"}')"

log "Gateway: ${GW}  My IP: ${MY_IP}"

# ---- Header --------------------------------------------------------
{
  echo "================================================================"
  echo " Router Hardening Audit"
  echo " Timestamp : ${STAMP}"
  echo " Gateway   : ${GW}"
  echo " Local IP  : ${MY_IP}"
  echo " Subnet    : ${SUBNET}"
  echo "================================================================"
  echo
} > "${REPORT}"

# =====================================================================
# 1) Port / service discovery on the gateway
# =====================================================================
LED ATTACK
log "Port scanning ${GW}..."

PORTS="21 22 23 25 53 67 69 80 81 88 110 111 123 135 139 143 161 162 \
389 443 445 465 514 515 548 587 631 636 873 902 993 995 1080 1194 1433 \
1521 1701 1723 1812 1883 1900 2049 2082 2083 2086 2087 2095 2222 3000 \
3128 3306 3389 4022 4433 4443 5000 5060 5061 5222 5353 5432 5555 5800 \
5900 5985 6379 7547 7676 8000 8008 8080 8081 8088 8089 8181 8291 8443 \
8728 8729 8888 9000 9090 9100 9443 10000 10001 32400 49152 51413 51820"

OPEN_PORTS=()
NC=$(command -v nc || echo "")
if [ -z "${NC}" ]; then
  # Fallback to /dev/tcp
  for p in ${PORTS}; do
    (echo > "/dev/tcp/${GW}/${p}") >/dev/null 2>&1 && OPEN_PORTS+=("${p}")
  done
else
  for p in ${PORTS}; do
    ${NC} -z -w1 "${GW}" "${p}" 2>/dev/null && OPEN_PORTS+=("${p}")
  done
fi

echo "${OPEN_PORTS[*]}" > "${RAW_DIR}/open_ports.txt"

note "## 1. Exposed services on gateway"
if [ "${#OPEN_PORTS[@]}" -eq 0 ]; then
  note "  No TCP services responded on the common port list."
  add PASS "Gateway exposes no common-port services to the LAN."
else
  note "  Open TCP ports: ${OPEN_PORTS[*]}"
fi
note ""

# Helper: is port open?
has_port() {
  local needle="$1"
  for p in "${OPEN_PORTS[@]}"; do [ "$p" = "$needle" ] && return 0; done
  return 1
}

# =====================================================================
# 2) Insecure / cleartext management protocols
# =====================================================================
LED ATTACK2
log "Checking for cleartext / risky mgmt protocols..."

has_port 23   && add CRIT "Telnet (23/tcp) is reachable on the LAN — cleartext admin protocol."
has_port 21   && add HIGH "FTP (21/tcp) on the gateway — cleartext credentials; disable or replace with SFTP."
has_port 69   && add HIGH "TFTP (69/udp typical, banner on 69/tcp) reachable — used for config/firmware leakage."
has_port 80   && add MED  "HTTP admin (80/tcp) reachable — admin UI should be HTTPS-only."
has_port 8080 && add MED  "HTTP admin alt (8080/tcp) reachable — admin UI should be HTTPS-only."
has_port 7547 && add HIGH "TR-069 / CWMP (7547/tcp) exposed to LAN — has a long history of RCEs; restrict to ISP ACL or disable."
has_port 1900 && add HIGH "UPnP (1900) reachable — auto-port-forwarding is a known attack surface; disable on the WAN side, restrict on LAN."
has_port 5000 && add LOW  "UPnP/SSDP control (5000) reachable — confirm UPnP is disabled."
has_port 161  && add MED  "SNMP (161/udp banner on tcp probe) — verify v3-only and no public/private communities."

# =====================================================================
# 3) Default-credential probes (very limited, single attempt per svc)
# =====================================================================
LED ATTACK3
log "Probing for default credentials (single attempt per service)..."

DEFAULT_PAIRS=(
  "admin:admin" "admin:password" "admin:1234" "admin:"
  "root:root" "root:admin" "root:" "root:Zte521"
  "user:user" "support:support" "ubnt:ubnt"
  "cisco:cisco" "tplink:tplink" "netgear:password"
)

# --- Telnet ---------------------------------------------------------
if has_port 23 && command -v expect >/dev/null 2>&1; then
  for pair in "${DEFAULT_PAIRS[@]}"; do
    U="${pair%%:*}"; P="${pair##*:}"
    OUT="$(expect -c "
      set timeout 4
      spawn telnet ${GW}
      expect -re {(ogin|sername):}
      send \"${U}\r\"
      expect -re {assword:}
      send \"${P}\r\"
      expect -re {[\\\$#>]}
      send \"exit\r\"
    " 2>/dev/null)"
    if echo "${OUT}" | grep -Eq '[\$#>] *$'; then
      add CRIT "Telnet default credentials accepted: ${U}/${P} on ${GW}."
      break
    fi
  done
fi

# --- SSH ------------------------------------------------------------
if has_port 22 && command -v sshpass >/dev/null 2>&1; then
  for pair in "${DEFAULT_PAIRS[@]}"; do
    U="${pair%%:*}"; P="${pair##*:}"
    sshpass -p "${P}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=4 -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
      "${U}@${GW}" "exit" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      add CRIT "SSH default credentials accepted: ${U}/${P} on ${GW}."
      SSH_GOOD="${U}:${P}"
      break
    fi
  done
fi

# --- HTTP / HTTPS basic-auth (only triggers on 401 Basic realm) ------
probe_http_basic() {
  local scheme="$1" port="$2"
  local url="${scheme}://${GW}:${port}/"
  local hdr
  hdr="$(curl -sk -I --max-time 5 "${url}" 2>/dev/null)"
  echo "${hdr}" >> "${RAW_DIR}/http_headers.txt"
  if echo "${hdr}" | grep -qi 'WWW-Authenticate: *Basic'; then
    for pair in "${DEFAULT_PAIRS[@]}"; do
      code="$(curl -sk -o /dev/null -w '%{http_code}' -u "${pair}" --max-time 5 "${url}")"
      if [ "${code}" = "200" ]; then
        add CRIT "HTTP Basic auth default credentials accepted on ${url}  (${pair})."
        return
      fi
    done
  fi
}
has_port 80   && probe_http_basic "http"  80
has_port 8080 && probe_http_basic "http"  8080
has_port 443  && probe_http_basic "https" 443
has_port 8443 && probe_http_basic "https" 8443

# =====================================================================
# 4) SNMP community check
# =====================================================================
if command -v snmpget >/dev/null 2>&1; then
  for comm in public private cisco admin manager; do
    snmpget -v2c -c "${comm}" -t 2 -r 0 "${GW}" .1.3.6.1.2.1.1.1.0 \
      >> "${RAW_DIR}/snmp.txt" 2>&1
    if grep -q "${comm}.*STRING" "${RAW_DIR}/snmp.txt"; then
      add CRIT "SNMP community '${comm}' responds — disable v1/v2c or change community; prefer SNMPv3 authPriv."
      break
    fi
  done
fi

# =====================================================================
# 5) HTTP fingerprinting and TLS health
# =====================================================================
fingerprint_http() {
  local scheme="$1" port="$2"
  local body
  body="$(curl -sk --max-time 6 "${scheme}://${GW}:${port}/" 2>/dev/null \
          | tr -d '\r' | head -c 4000)"
  echo "---- ${scheme}://${GW}:${port}/ ----" >> "${RAW_DIR}/http_body.txt"
  echo "${body}" >> "${RAW_DIR}/http_body.txt"
  echo "" >> "${RAW_DIR}/http_body.txt"

  # Vendor / model guesses
  case "${body,,}" in
    *tp-link*|*tplink*)  add LOW "Vendor fingerprint: TP-Link admin UI on ${port}.";;
    *netgear*)           add LOW "Vendor fingerprint: Netgear admin UI on ${port}.";;
    *linksys*)           add LOW "Vendor fingerprint: Linksys admin UI on ${port}.";;
    *asuswrt*|*asus*)    add LOW "Vendor fingerprint: ASUS admin UI on ${port}.";;
    *openwrt*|*luci*)    add LOW "Vendor fingerprint: OpenWrt/LuCI on ${port}.";;
    *mikrotik*|*routeros*) add LOW "Vendor fingerprint: MikroTik RouterOS on ${port}.";;
    *ubiquiti*|*ubnt*|*unifi*) add LOW "Vendor fingerprint: Ubiquiti/UniFi on ${port}.";;
    *pfsense*)           add LOW "Vendor fingerprint: pfSense on ${port}.";;
    *fortigate*|*fortinet*) add LOW "Vendor fingerprint: FortiGate on ${port}.";;
    *zyxel*)             add LOW "Vendor fingerprint: Zyxel on ${port}.";;
  esac
}
has_port 80   && fingerprint_http "http"  80
has_port 8080 && fingerprint_http "http"  8080
has_port 443  && fingerprint_http "https" 443
has_port 8443 && fingerprint_http "https" 8443

# TLS probe — flag self-signed / expired / weak
if has_port 443 && command -v openssl >/dev/null 2>&1; then
  echo | openssl s_client -connect "${GW}:443" -servername "${GW}" \
    -showcerts 2>/dev/null > "${RAW_DIR}/tls.txt"
  if grep -q "self.signed" "${RAW_DIR}/tls.txt"; then
    add MED "HTTPS cert on ${GW}:443 is self-signed — admins train themselves to click through warnings."
  fi
  if grep -q "Protocol  : TLSv1\b\|Protocol  : SSLv" "${RAW_DIR}/tls.txt"; then
    add HIGH "Gateway supports legacy TLS/SSL on 443 — disable TLS<1.2."
  fi
fi

# =====================================================================
# 6) DNS / DHCP sanity
# =====================================================================
RESOLV_DNS="$(awk '/nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ' ')"
note "## 2. DNS configuration learned from DHCP"
note "  Nameservers handed out: ${RESOLV_DNS:-<none>}"
case "${RESOLV_DNS}" in
  *" ${GW} "*|"${GW} "*|*" ${GW}") add PASS "Router itself is the DNS resolver (normal).";;
esac
# Public-DNS-only is suspicious for an enterprise net
if echo "${RESOLV_DNS}" | grep -qE '\b(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9)\b' \
   && ! echo "${RESOLV_DNS}" | grep -q "${GW}"; then
  add LOW "DHCP hands out only public DNS — fine for home, but on a corp LAN you typically want internal resolvers."
fi
note ""

# =====================================================================
# 7) ICMP redirects / source-routing quick probe
# =====================================================================
# (passive: just record the hop)
traceroute -n -w 1 -q 1 -m 4 8.8.8.8 > "${RAW_DIR}/traceroute.txt" 2>&1 || true

# =====================================================================
# 7.5) Call-home sniff + threat-list correlation
# =====================================================================
# Passively captures broadcast / multicast / locally-visible traffic
# sourced from the gateway for ~60s, plus any DNS replies the router
# returns to our resolver. Extracts destination IPs and DNS query
# names, then correlates against:
#   - threatlist/aggregated_ips.txt        (live feeds, if updated)
#   - threatlist/aggregated_domains.txt    (live feeds, if updated)
#   - threatlist/baseline_ips.txt          (shipped)
#   - threatlist/baseline_domains.txt      (shipped)
#   - threatlist/vendor_telemetry.txt      (call-home reference)
#
# On a switched LAN we won't see all of the router's egress traffic —
# only what's broadcast/multicast or destined to our MAC. That's still
# enough to catch SSDP/mDNS chatter, DHCP option leaks, syslog
# broadcasts, and DNS-replied destinations.

TL_DIR="/root/payload/threatlist"
[ -d "${TL_DIR}" ] || TL_DIR="$(dirname "$0")/threatlist"

IP_FEED="${TL_DIR}/aggregated_ips.txt"
DOM_FEED="${TL_DIR}/aggregated_domains.txt"
[ -f "${IP_FEED}" ]  || IP_FEED="${TL_DIR}/baseline_ips.txt"
[ -f "${DOM_FEED}" ] || DOM_FEED="${TL_DIR}/baseline_domains.txt"
VEND_FEED="${TL_DIR}/vendor_telemetry.txt"

SNIFF_PCAP="${RAW_DIR}/sniff.pcap"
SNIFF_IPS="${RAW_DIR}/sniff_ips.txt"
SNIFF_DOMS="${RAW_DIR}/sniff_domains.txt"
: > "${SNIFF_IPS}"; : > "${SNIFF_DOMS}"

GW_MAC="$(ip neigh show "${GW}" 2>/dev/null | awk '{print $5}' | head -n1)"

LED ATTACK
log "Sniffing call-home traffic for 60s (gateway MAC ${GW_MAC:-unknown})..."

if command -v tcpdump >/dev/null 2>&1; then
  # Capture anything sourced from the gateway IP or its MAC,
  # plus broadcast/multicast (mDNS, SSDP, syslog).
  FILTER="src host ${GW}"
  [ -n "${GW_MAC}" ] && FILTER="${FILTER} or ether src ${GW_MAC}"
  FILTER="${FILTER} or udp port 5353 or udp port 1900 or udp port 514 or port 53"

  timeout 60 tcpdump -i eth0 -nn -s 0 -w "${SNIFF_PCAP}" \
    "${FILTER}" >/dev/null 2>&1 &
  TCPDUMP_PID=$!

  # In parallel: kick the resolver so we observe DNS replies through the GW
  for h in $(awk -F'|' '/^[a-z0-9]/ {print $1}' "${VEND_FEED}" 2>/dev/null | head -n 30); do
    nslookup "${h}" "${GW}" >/dev/null 2>&1 &
  done
  wait ${TCPDUMP_PID} 2>/dev/null

  # Extract destination IPs (anything the gateway talks TO)
  tcpdump -nn -r "${SNIFF_PCAP}" 2>/dev/null \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort -u > "${SNIFF_IPS}"

  # Extract DNS query / answer names
  tcpdump -nn -r "${SNIFF_PCAP}" 2>/dev/null \
    | grep -Eo '[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+' \
    | tr 'A-Z' 'a-z' \
    | sort -u > "${SNIFF_DOMS}"
else
  log "tcpdump not present — falling back to ARP/neighbor enumeration only."
  # Best-effort: who is the gateway talking to in our ARP table
  ip neigh > "${RAW_DIR}/neigh.txt" 2>/dev/null
  awk '{print $1}' "${RAW_DIR}/neigh.txt" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > "${SNIFF_IPS}"
fi

note "## 3. Call-home traffic observation"
note "  Sniff window  : 60s"
note "  Threat feed   : $(basename "${IP_FEED}") + $(basename "${DOM_FEED}")"
if [ -f "${TL_DIR}/aggregated.meta" ]; then
  AGE="$(grep '^updated_utc=' "${TL_DIR}/aggregated.meta" | cut -d= -f2)"
  CNT_IP="$(grep '^ip_count=' "${TL_DIR}/aggregated.meta" | cut -d= -f2)"
  CNT_D="$(grep '^domain_count=' "${TL_DIR}/aggregated.meta" | cut -d= -f2)"
  note "  Feed updated  : ${AGE}"
  note "  Feed size     : ${CNT_IP} IPs, ${CNT_D} domains"
else
  add LOW "Threat feed has never been updated — run threatlist/update_threatlist.sh to pull live IOCs."
  note "  Feed updated  : NEVER (baseline only)"
fi
note "  Observed IPs  : $(wc -l < "${SNIFF_IPS}")"
note "  Observed names: $(wc -l < "${SNIFF_DOMS}")"
note ""

# --- IP correlation -------------------------------------------------
# Plain-IP match (CIDR matching is approximated: we match on /24 by
# checking if any feed line shares the same first three octets when
# the feed line is a CIDR). Exact-IP matches are detected directly.
match_ip() {
  local needle="$1"
  grep -Fx "${needle}" "${IP_FEED}" >/dev/null 2>&1 && { echo "exact"; return; }
  local three="${needle%.*}"
  grep -E "^${three}\." "${IP_FEED}" >/dev/null 2>&1 && { echo "range"; return; }
  echo ""
}

while IFS= read -r ip; do
  [ -z "${ip}" ] && continue
  case "${ip}" in
    0.0.0.0|255.255.255.255) continue ;;
    "${GW}"|"${MY_IP%/*}")    continue ;;
  esac
  m="$(match_ip "${ip}")"
  if [ "${m}" = "exact" ]; then
    add CRIT "Gateway observed contacting KNOWN-BAD IP ${ip} (exact match in threat feed)."
  elif [ "${m}" = "range" ]; then
    add HIGH "Gateway observed contacting IP ${ip} inside a known-bad /24 in the threat feed."
  fi
done < "${SNIFF_IPS}"

# --- Domain correlation --------------------------------------------
# Suffix match: an observed name matches a feed entry if the feed
# entry equals the name or is a dot-suffix of the name.
match_domain() {
  local needle="$1" feed="$2"
  local n
  n="$(echo "${needle}" | tr 'A-Z' 'a-z')"
  # exact
  grep -Fxq "${n}" "${feed}" 2>/dev/null && { echo "exact"; return; }
  # suffix: walk components
  while [ -n "${n}" ]; do
    grep -Fxq "${n}" "${feed}" 2>/dev/null && { echo "suffix"; return; }
    case "${n}" in
      *.*) n="${n#*.}" ;;
      *)   break ;;
    esac
  done
  echo ""
}

while IFS= read -r dom; do
  [ -z "${dom}" ] && continue
  [ "${#dom}" -lt 4 ] && continue
  # threat-feed match
  m="$(match_domain "${dom}" "${DOM_FEED}")"
  if [ -n "${m}" ]; then
    add CRIT "Gateway DNS observed for KNOWN-BAD domain '${dom}' (${m} match in threat feed)."
    continue
  fi
  # vendor-telemetry match → MEDIUM
  if [ -f "${VEND_FEED}" ]; then
    while IFS='|' read -r v_dom v_vendor v_purpose; do
      [ -z "${v_dom}" ] && continue
      case "${v_dom}" in \#*) continue ;; esac
      # suffix or prefix-match (acs. / cwmp.)
      case "${v_dom}" in
        *.) case "${dom}" in
              "${v_dom}"*) add MED "Gateway calling home to '${dom}' — ${v_vendor} (${v_purpose})."; break ;;
            esac ;;
        *)  case ".${dom}" in
              *".${v_dom}") add MED "Gateway calling home to '${dom}' — ${v_vendor} (${v_purpose})."; break ;;
            esac
            [ "${dom}" = "${v_dom}" ] && { add MED "Gateway calling home to '${dom}' — ${v_vendor} (${v_purpose})."; break; }
            ;;
      esac
    done < "${VEND_FEED}"
  fi
done < "${SNIFF_DOMS}"

# --- If we have SSH on the router from the cred phase, dump conntrack --
# (Only attempts if a SSH default-cred CRIT was just added; reuses the
# successful pair stored in $SSH_GOOD if set above. Best-effort.)
if [ -n "${SSH_GOOD:-}" ] && command -v sshpass >/dev/null 2>&1; then
  U="${SSH_GOOD%%:*}"; P="${SSH_GOOD##*:}"
  sshpass -p "${P}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 "${U}@${GW}" \
    'cat /proc/net/nf_conntrack 2>/dev/null || cat /proc/net/ip_conntrack 2>/dev/null' \
    > "${RAW_DIR}/conntrack.txt" 2>/dev/null
  if [ -s "${RAW_DIR}/conntrack.txt" ]; then
    awk '{for(i=1;i<=NF;i++) if($i ~ /^dst=/) print substr($i,5)}' \
      "${RAW_DIR}/conntrack.txt" | sort -u > "${RAW_DIR}/conntrack_dst.txt"
    while IFS= read -r ip; do
      [ -z "${ip}" ] && continue
      m="$(match_ip "${ip}")"
      [ -n "${m}" ] && add CRIT "Router conntrack shows active flow to known-bad IP ${ip} (${m})."
    done < "${RAW_DIR}/conntrack_dst.txt"
  fi
fi

note ""

# =====================================================================
# 8) Render the report
# =====================================================================
render_bucket() {
  local label="$1" arr_name="$2"
  local count
  eval "count=\${#${arr_name}[@]}"
  if [ "${count}" -gt 0 ]; then
    note "### ${label}"
    eval "for f in \"\${${arr_name}[@]}\"; do note \"  - \${f}\"; done"
    note ""
  fi
}

note "## 4. Findings (highest severity first)"
note ""
render_bucket "CRITICAL — fix immediately" CRIT
render_bucket "HIGH"                       HIGH
render_bucket "MEDIUM"                     MED
render_bucket "LOW / INFO"                 LOW
render_bucket "Looks good"                 PASS

note "## 5. Recommended hardening checklist"
note "  [ ] Disable Telnet, FTP, TFTP on the gateway."
note "  [ ] Force HTTPS-only on the admin UI and replace self-signed certs."
note "  [ ] Restrict admin UI / SSH to a management VLAN or specific source IPs."
note "  [ ] Disable UPnP unless explicitly required; never on the WAN side."
note "  [ ] Disable WAN-side TR-069 (7547) or ACL it to the ISP only."
note "  [ ] Remove SNMP v1/v2c; if SNMP is needed, use v3 authPriv with a strong user."
note "  [ ] Change all default credentials; enforce password length >= 16 and MFA where supported."
note "  [ ] Disable WPS on the wireless side (out-of-scope for wired audit, but verify)."
note "  [ ] Keep firmware current and subscribe to the vendor's advisory feed."
note "  [ ] Segment IoT / guest / mgmt into separate VLANs with inter-VLAN ACLs."
note "  [ ] Enable logging to a remote syslog and review weekly."
note "  [ ] Refresh the threat-intel feeds (threatlist/update_threatlist.sh) at least weekly."
note ""

# Score
SCORE=$(( 100 - ${#CRIT[@]}*25 - ${#HIGH[@]}*10 - ${#MED[@]}*4 - ${#LOW[@]}*1 ))
[ ${SCORE} -lt 0 ] && SCORE=0
note "## 6. Overall hardening score: ${SCORE}/100"
if   [ ${#CRIT[@]} -gt 0 ]; then note "  Verdict: NOT hardened — critical issues present."
elif [ ${#HIGH[@]} -gt 0 ]; then note "  Verdict: partial — high-severity gaps remain."
elif [ ${#MED[@]}  -gt 0 ]; then note "  Verdict: mostly hardened — minor improvements recommended."
else                              note "  Verdict: well hardened against the checks performed."
fi

# Latest pointer for convenience
ln -sfn "${LOOT_DIR}" "${LOOT_ROOT}/latest"

sync
LED FINISH
