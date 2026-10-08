#!/usr/bin/env bash
# pia-region-test.sh — speedtest PIA WireGuard exits one region at a time,
# independently of the OPNsense tunnel.
#
# Usage:
#   ./pia-region-test.sh list                                  # port-forward regions (no creds needed)
#   PIA_USER=p1234567 PIA_PASS='...' ./pia-region-test.sh nl_amsterdam ca_toronto swiss
#   PIA_USER=p1234567 PIA_PASS='...' ./pia-region-test.sh all  # every port-forward region (slow)
#
# Results append to /root/pia-test/results.csv
set -euo pipefail

WORK=/root/pia-test
IFACE=piatest
CONF="$WORK/$IFACE.conf"
CA="$WORK/ca.rsa.4096.crt"
RESULTS="$WORK/results.csv"
mkdir -p "$WORK"; cd "$WORK"

for c in curl jq wg wg-quick speedtest; do
  command -v "$c" >/dev/null || { echo "missing dependency: $c"; exit 1; }
done

[[ -f $CA ]] || curl -fsSL -o "$CA" \
  https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt

# First line of the server list is JSON; the rest is a signature.
curl -fsS -o servers.raw 'https://serverlist.piaservers.net/vpninfo/servers/v6' \
  || { echo "server list download failed"; exit 1; }
head -1 servers.raw > servers.json

if [[ ${1:-} == list || $# -eq 0 ]]; then
  jq -r '.regions[] | select(.port_forward) | "\(.id)\t\(.name)"' servers.json | sort
  exit 0
fi

: "${PIA_USER:?set PIA_USER}" "${PIA_PASS:?set PIA_PASS}"
# Token: try the web API first; fall back to a regional meta server (authv3).
TOKEN=$(curl -fsS -X POST https://www.privateinternetaccess.com/api/client/v2/token \
  --form "username=$PIA_USER" --form "password=$PIA_PASS" 2>/dev/null | jq -r .token 2>/dev/null) || TOKEN=""
if [[ -z $TOKEN || $TOKEN == null ]]; then
  echo "web token API failed; trying meta servers..."
  TOKEN=""
  while read -r MIP MCN; do
    TOKEN=$(curl -fsS -u "$PIA_USER:$PIA_PASS" --connect-to "$MCN::$MIP:" --cacert "$CA" \
      "https://$MCN/authv3/generateToken" 2>/dev/null | jq -r .token 2>/dev/null) || TOKEN=""
    [[ -n $TOKEN && $TOKEN != null ]] && { echo "token via meta server $MCN"; break; }
    TOKEN=""
  done < <(jq -r --argjson want "$(printf '%s\n' "${@}" | jq -R . | jq -s .)" \
      '.regions[] | select(($want | index("all")) or (.id as $i | $want | index($i))) | .servers.meta[0] | "\(.ip) \(.cn)"' servers.json)
fi
[[ -n $TOKEN ]] || { echo "PIA token request failed (web API and meta servers)"; exit 1; }

if [[ $1 == all ]]; then
  mapfile -t REGIONS < <(jq -r '.regions[] | select(.port_forward) | .id' servers.json)
else
  REGIONS=("$@")
fi

cleanup() { wg-quick down "$CONF" &>/dev/null || true; }
trap cleanup EXIT

[[ -f $RESULTS ]] || echo '"timestamp","region","pia_server","ping_ms","down_mbps","up_mbps","speedtest_server"' > "$RESULTS"

for R in "${REGIONS[@]}"; do
  IP=""; CN=""
  read -r IP CN < <(jq -r --arg r "$R" \
    '.regions[] | select(.id==$r) | .servers.wg[0] | "\(.ip) \(.cn)"' servers.json) || true
  if [[ -z $IP || $IP == null ]]; then echo "[$R] unknown region or no WireGuard server"; continue; fi

  PRIV=$(wg genkey); PUB=$(wg pubkey <<<"$PRIV")
  KEY=$(curl -fsS -G --connect-to "$CN::$IP:" --cacert "$CA" \
          --data-urlencode "pt=$TOKEN" --data-urlencode "pubkey=$PUB" \
          "https://$CN:1337/addKey") || { echo "[$R] addKey request failed"; continue; }
  [[ $(jq -r .status <<<"$KEY") == OK ]] || { echo "[$R] addKey error: $KEY"; continue; }

  umask 077
  cat > "$CONF" <<EOF
[Interface]
Address = $(jq -r .peer_ip <<<"$KEY")
PrivateKey = $PRIV
MTU = 1420

[Peer]
PublicKey = $(jq -r .server_key <<<"$KEY")
AllowedIPs = 0.0.0.0/0
Endpoint = $IP:$(jq -r .server_port <<<"$KEY")
PersistentKeepalive = 25
EOF

  wg-quick up "$CONF" >/dev/null
  sleep 3
  echo "[$R] testing via $CN ($IP)..."
  if OUT=$(timeout 120 speedtest --accept-license --accept-gdpr -f json 2>/dev/null); then
    jq -r --arg r "$R" --arg cn "$CN" '[
        .timestamp, $r, $cn,
        (.ping.latency*10|round/10),
        (.download.bandwidth*8/1e4|round/100),
        (.upload.bandwidth*8/1e4|round/100),
        "\(.server.name) (\(.server.location))"
      ] | @csv' <<<"$OUT" | tee -a "$RESULTS"
  else
    echo "[$R] speedtest failed"
  fi
  wg-quick down "$CONF" >/dev/null
done

echo; echo "Results: $RESULTS"
