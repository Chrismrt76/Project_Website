#!/bin/bash
#
# update_threatlist.sh
# Fetches every feed listed in sources.conf, normalizes them to plain
# IP and domain lists, merges with the shipped baseline_*, and writes
# aggregated_ips.txt + aggregated_domains.txt for the payload to use.
#
# Run on the Shark Jack while it has internet, or anywhere with curl,
# then copy the aggregated_*.txt files to the device.
#
# Usage:
#   ./update_threatlist.sh            # full refresh
#   ./update_threatlist.sh --dry-run  # show what would be fetched

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${DIR}/sources.conf"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

if [ ! -f "${SRC}" ]; then
  echo "missing ${SRC}" >&2
  exit 1
fi

IP_OUT="${DIR}/aggregated_ips.txt"
DOM_OUT="${DIR}/aggregated_domains.txt"
META="${DIR}/aggregated.meta"

# --- normalizers ----------------------------------------------------
ip_regex='([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?'
dom_regex='([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}'

fetch() {
  local url="$1" dest="$2"
  if [ "${DRY}" = "1" ]; then
    echo "DRY: would fetch ${url}"
    return
  fi
  curl -fsSL --max-time 30 -A "ShakJack-RouterAudit/1.0" "${url}" -o "${dest}" 2>/dev/null
}

extract_ip() {
  grep -Eo "^${ip_regex}|[^0-9.]${ip_regex}" "$1" 2>/dev/null \
    | grep -Eo "${ip_regex}" \
    | sort -u
}
extract_domain() {
  # URLhaus / OpenPhish formats: full URLs. Strip scheme & path.
  sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' "$1" 2>/dev/null \
    | tr 'A-Z' 'a-z' \
    | grep -E "^${dom_regex}$" \
    | sort -u
}

# --- aggregate ------------------------------------------------------
: > "${TMP}/ips.acc"
: > "${TMP}/doms.acc"
COUNT_OK=0
COUNT_FAIL=0
SOURCES_USED=()

while IFS= read -r line; do
  # strip comments & blanks
  line="${line%%#*}"
  line="$(echo "${line}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "${line}" ] && continue

  type="${line%%|*}"
  url="${line#*|}"
  [ -z "${url}" ] && continue

  fname="${TMP}/$(echo "${url}" | tr '/:?&=' '_____')"
  echo "[+] ${type}  ${url}"
  if fetch "${url}" "${fname}" && [ -s "${fname}" ]; then
    COUNT_OK=$((COUNT_OK+1))
    SOURCES_USED+=("${url}")
    case "${type}" in
      ip|csv_ip)
        extract_ip "${fname}" >> "${TMP}/ips.acc"
        ;;
      domain)
        tr 'A-Z' 'a-z' < "${fname}" | grep -Eo "${dom_regex}" \
          | sort -u >> "${TMP}/doms.acc"
        ;;
      urlhaus)
        # text feed of URLs; strip to host
        extract_domain "${fname}" >> "${TMP}/doms.acc"
        # some entries are bare IPs in URLhaus too
        extract_ip "${fname}" >> "${TMP}/ips.acc"
        ;;
      *)
        echo "    unknown type '${type}', skipping"
        ;;
    esac
  else
    COUNT_FAIL=$((COUNT_FAIL+1))
    echo "    fetch failed"
  fi
done < "${SRC}"

[ "${DRY}" = "1" ] && exit 0

# Merge with baselines
cat "${DIR}/baseline_ips.txt" 2>/dev/null \
  | sed 's/#.*$//' | tr -d ' \t' | grep -E "^${ip_regex}$" \
  >> "${TMP}/ips.acc"

cat "${DIR}/baseline_domains.txt" 2>/dev/null \
  | sed 's/#.*$//' | tr -d ' \t' | tr 'A-Z' 'a-z' \
  | grep -E "^${dom_regex}$" >> "${TMP}/doms.acc"

sort -u "${TMP}/ips.acc"  > "${IP_OUT}"
sort -u "${TMP}/doms.acc" > "${DOM_OUT}"

{
  echo "updated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "sources_ok=${COUNT_OK}"
  echo "sources_failed=${COUNT_FAIL}"
  echo "ip_count=$(wc -l < "${IP_OUT}")"
  echo "domain_count=$(wc -l < "${DOM_OUT}")"
  echo "feeds:"
  for u in "${SOURCES_USED[@]}"; do echo "  - ${u}"; done
} > "${META}"

echo
echo "Done."
echo "  IPs    : $(wc -l < "${IP_OUT}")"
echo "  Domains: $(wc -l < "${DOM_OUT}")"
echo "  Meta   : ${META}"
