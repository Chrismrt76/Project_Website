# Router Hardening Audit — Shark Jack payload

A non-destructive LAN-side audit you can plug into any switch port. It
fingerprints the upstream gateway, inventories exposed services, runs a
short list of well-known default credentials against any auth surface it
finds, and writes a prioritized hardening report to the Shark Jack's
loot directory.

## What it checks

1. **Exposed management services** — Telnet, FTP, TFTP, HTTP, HTTPS,
   SSH, SNMP, UPnP/SSDP, TR-069/CWMP, RDP, mDNS, etc.
2. **Cleartext admin protocols** — flags Telnet/FTP/HTTP-admin as
   CRITICAL/HIGH.
3. **Default credentials** — a *single* attempt per service against a
   short list (admin/admin, root/root, ubnt/ubnt, etc.) on Telnet, SSH,
   and HTTP Basic. Single-attempt-per-service to avoid lockouts.
4. **SNMP communities** — tries `public`, `private`, `cisco`, `admin`,
   `manager` on v2c.
5. **TLS health** — self-signed / TLS<1.2 on the admin port.
6. **Vendor fingerprint** — TP-Link / Netgear / OpenWrt / MikroTik /
   pfSense / FortiGate / Zyxel / UniFi from the login page.
7. **DHCP-handed DNS sanity** — flags weird DNS handouts.
8. **Call-home traffic correlation** — passively sniffs ~60s of traffic
   from the gateway (broadcast/multicast + locally-visible flows), plus
   DNS replies, extracts destination IPs and queried domains, and
   correlates against an updatable threat-intel list:
     - exact / CIDR match in feed → **CRITICAL**
     - vendor-telemetry / call-home host → **MEDIUM**
   If the cred-probe phase recovered SSH on the router, the script
   also dumps `/proc/net/nf_conntrack` and correlates its destinations.
9. **Score & checklist** — a 0–100 score and a copy/paste hardening
   checklist at the bottom of the report.

## Threat-intel feeds (the "known threat actor list")

Everything lives under `threatlist/`:

```
threatlist/
├── sources.conf            # feed URLs (edit to add/remove)
├── baseline_ips.txt        # static IOCs shipped in repo (your edits go here)
├── baseline_domains.txt    # static domain IOCs
├── vendor_telemetry.txt    # known router call-home endpoints (info)
├── update_threatlist.sh    # pulls every feed, merges with baselines
├── aggregated_ips.txt      # ← generated; used by payload.sh
├── aggregated_domains.txt  # ← generated; used by payload.sh
└── aggregated.meta         # ← generated; timestamp + counts
```

### Feeds pulled by default (all free, no key required)

- abuse.ch Feodo Tracker (botnet C2 IPs)
- abuse.ch ThreatFox (multi-malware IOCs)
- abuse.ch SSLBL (TLS-cert-based C2)
- abuse.ch URLhaus (malware delivery URLs)
- FireHOL Level 1 (high-confidence aggregated blocklist)
- Emerging Threats compromised-IPs
- CINS Army (CINSscore badguys)
- OpenPhish community feed
- Spamhaus DROP / EDROP

### Updating the list

Anywhere with `curl` (your laptop, the Shark Jack while online):

```
cd threatlist
./update_threatlist.sh           # pull all feeds, merge with baseline
./update_threatlist.sh --dry-run # show what would be fetched
```

Then copy `aggregated_ips.txt`, `aggregated_domains.txt`, and
`aggregated.meta` to the Shark Jack at `/root/payload/threatlist/`. The
payload will pick them up automatically; if they're missing, it falls
back to the baselines.

To **add your own indicators**, append IPs/CIDRs to `baseline_ips.txt`
or domains to `baseline_domains.txt`, then re-run the updater. To
**add a new feed**, add a line to `sources.conf` in the form
`ip|<url>` or `domain|<url>` or `csv_ip|<url>` or `urlhaus|<url>`.

## Install

On a Shark Jack in arming mode:

```
cp payload.sh /root/payload/payload.sh
```

Or via the Shark Jack Cloud C2 / `scp`:

```
scp payload.sh root@<sharkjack>:/root/payload/payload.sh
```

The script is self-contained — it uses tools already on stock Shark Jack
firmware (`curl`, `nc`, `openssl`, `traceroute`) and *optionally* uses
`expect`, `sshpass`, and `snmpget` if you've added them via `opkg`. The
audit still runs without them; it just skips those probes.

To add the optional helpers (recommended):

```
opkg update && opkg install sshpass expect snmp-utils tcpdump
```

`tcpdump` is what powers the call-home sniff phase — without it, the
correlation falls back to ARP/neighbor enumeration only.

## LED legend

| LED state            | Meaning                          |
|----------------------|----------------------------------|
| MAGENTA single       | Acquiring DHCP                   |
| YELLOW single        | Port scanning the gateway        |
| YELLOW double        | Probing services / TLS / HTTP    |
| YELLOW triple        | Default-credential & SNMP checks |
| GREEN solid (FINISH) | Done — pull loot                 |
| RED solid (FAIL)     | No gateway / no DHCP             |

## Pulling loot

Switch the Shark Jack to **arming mode** and:

```
scp -r root@172.16.24.1:/root/loot/router_audit/latest ./
```

`latest` is a symlink to the most recent run. Inside you get:

```
router_audit/<timestamp>/
├── report.txt         # human-readable findings + checklist + score
└── raw/
    ├── open_ports.txt
    ├── http_headers.txt
    ├── http_body.txt
    ├── tls.txt
    ├── snmp.txt
    ├── traceroute.txt
    ├── sniff.pcap          # 60s capture from the call-home phase
    ├── sniff_ips.txt       # extracted destination IPs
    ├── sniff_domains.txt   # extracted DNS query/answer names
    └── conntrack.txt       # router /proc/net/nf_conntrack (if SSH worked)
```

## Report format

The report groups findings as:

- **CRITICAL** — remote takeover / no-auth / default creds accepted
- **HIGH** — clear-text mgmt, exposed mgmt, SNMP public, UPnP, TR-069
- **MEDIUM** — self-signed TLS, HTTP admin, outdated banners
- **LOW / INFO** — vendor fingerprint, cosmetic
- **Looks good** — controls that passed

…followed by a 10-item hardening checklist and a 0–100 score.

## Authorized use only

Only run this against networks you own or have written permission to
test. The default-credential probes are intentionally limited (one
attempt per credential per service) to avoid lockouts, but they are
still an authentication attempt and may be logged by the target.
