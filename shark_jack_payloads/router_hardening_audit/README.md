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
8. **Score & checklist** — a 0–100 score and a copy/paste hardening
   checklist at the bottom of the report.

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
opkg update && opkg install sshpass expect snmp-utils
```

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
    └── traceroute.txt
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
