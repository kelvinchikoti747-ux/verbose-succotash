#!/usr/bin/env bash
# authorized-scan.sh
# Automated reconnaissance and web-surface scanning for AUTHORIZED TESTING ONLY.
# USAGE:
#   ./authorized-scan.sh target.example.com
#   ./authorized-scan.sh -f targets.txt
#
# REQUIREMENTS (install before running):
#   - nmap
#   - nikto
#   - curl (usually installed)
#
# NOTE: Do NOT use this against systems you do not own or do not have explicit written permission to test.

set -euo pipefail

print_usage() {
  cat <<EOF
authorized-scan.sh - quick reconnaissance for AUTHORIZED TESTING ONLY

Usage:
  $0 target.example.com
  $0 -f targets.txt

This script runs nmap to discover open ports and version info, and runs nikto
against discovered HTTP ports. Results are stored in ./scan-results/<timestamp>.

Always have written permission before scanning a target.
EOF
}

if [[ "${1:-}" == "" ]]; then
  print_usage
  exit 1
fi

# parse args
if [[ "$1" == "-f" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Missing filename after -f"
    exit 1
  fi
  if [[ ! -f "$2" ]]; then
    echo "File not found: $2"
    exit 1
  fi
  mapfile -t TARGETS < "$2"
else
  TARGETS=("$1")
fi

# check required tools
require() {
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Required tool '$cmd' not found. Install it and re-run."
      exit 2
    fi
  done
}
require nmap nikto curl

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUTDIR="scan-results-$TIMESTAMP"
mkdir -p "$OUTDIR"

for target in "${TARGETS[@]}"; do
  target_clean="$(echo "$target" | tr '/' '_' | tr ':' '_')"
  echo "=== Scanning target: $target ==="

  # Full TCP port scan (fast-ish): -p- scans all ports, -T4 speeds up
  echo "[*] Running nmap - this may take time..."
  nmap -sS -p- -T4 --min-rate 1000 -oA "$OUTDIR/nmap-full-$target_clean" "$target"

  # Service/version scan on common ports and to get web ports
  nmap -sV -p 21,22,23,25,53,80,110,143,443,445,3389,8000,8080,8443 -oG "$OUTDIR/nmap-services-$target_clean.gnmap" "$target" >/dev/null

  # Extract open ports from the grepable output
  open_ports=$(awk '/Ports: / { for(i=0;i<NF;i++) if ($i ~ /[0-9]+\/open/) { split($i,p,"/"); printf "%s ", p[1] } }' "$OUTDIR/nmap-services-$target_clean.gnmap" || true)
  echo "[*] Open ports: ${open_ports:-none}"

  # Identify likely HTTP ports for nikto
  http_ports=()
  for p in $open_ports; do
    case "$p" in
      80|443|8000|8080|8443|8008|8888) http_ports+=("$p") ;;
    esac
  done

  if [[ ${#http_ports[@]} -eq 0 ]]; then
    echo "[*] No common HTTP ports found. Skipping nikto for $target."
  else
    for port in "${http_ports[@]}"; do
      proto="http"
      if [[ "$port" == "443" || "$port" == "8443" ]]; then
        proto="https"
      fi
      url="${proto}://${target}:${port}"
      echo "[*] Running nikto against $url ..."
      # nikto output files
      nikto_out="$OUTDIR/nikto-${target_clean}-${port}.txt"
      # Run nikto (may be slow)
      nikto -h "$url" -output "$nikto_out" >/dev/null 2>&1 || echo "[!] nikto exited non-zero for $url (check $nikto_out)"
      echo "[+] Saved nikto output to $nikto_out"
    done
  fi

  # Simple HTTP(s) fetch of root for quick response check
  for port in "${http_ports[@]}"; do
    proto="http"
    if [[ "$port" == "443" || "$port" == "8443" ]]; then
      proto="https"
    fi
    curl --max-time 10 -s -D "$OUTDIR/headers-${target_clean}-${port}.txt" -o "$OUTDIR/body-${target_clean}-${port}.html" "${proto}://${target}:${port}" || echo "[!] curl failed for ${target}:${port}"
  done

  echo "=== Completed scanning $target. Results in $OUTDIR ==="
done

echo "Scan finished. Results directory: $OUTDIR"
echo "IMPORTANT: Review results, obtain consent, and follow responsible disclosure if you find vulnerabilities."