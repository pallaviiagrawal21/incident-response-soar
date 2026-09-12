#!/usr/bin/env bash
# Quick demo: dry-run both bundled playbooks against a sample incident.
# Run from the repository root: ./scripts/run_dry_run_demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."

INCIDENT_FILE="$(mktemp)"
trap 'rm -f "$INCIDENT_FILE"' EXIT

cat > "$INCIDENT_FILE" << 'EOF'
{
  "sender_domain": "phish-example.com",
  "malicious_link_domain": "creds-harvest.example.net",
  "affected_user": "jdoe",
  "affected_host": "ws-jdoe-01",
  "lateral_movement_host": "srv-file01",
  "c2_indicator": "bad-c2.example.net",
  "ransom_binary_hash": "d41d8cd98f00b204e9800998ecf8427e"
}
EOF

echo "=== Validating both playbooks ==="
ir-soar validate-playbook phishing_lateral_movement
ir-soar validate-playbook ransomware

echo
echo "=== Dry-run: phishing_lateral_movement ==="
ir-soar run --playbook phishing_lateral_movement --dry-run \
  --incident-file "$INCIDENT_FILE" --non-interactive

echo
echo "=== Dry-run: ransomware ==="
ir-soar run --playbook ransomware --dry-run \
  --incident-file "$INCIDENT_FILE" --non-interactive

echo
echo "Demo complete. See ./logs/audit.jsonl for the hash-chained audit trail."
