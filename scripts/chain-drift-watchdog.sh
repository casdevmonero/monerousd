#!/bin/bash
# chain-drift-watchdog.sh — alert when one peer falls behind another.
#
# Closes the v1.2.205 incident class: edge daemon ran 23,575 blocks
# behind VPS for 15+ hours before being noticed. A simple cron that
# compares heights every minute and pages the operator on drift >
# DRIFT_THRESHOLD blocks would have caught it in seconds.
#
# WHAT IT DOES
#
#   - Polls every configured peer's RPC endpoint (json_rpc get_info).
#   - Compares max(height) vs each peer's height.
#   - On any peer drifting > DRIFT_THRESHOLD blocks, writes
#     /var/log/chain-drift.log + fires an alert webhook (optional).
#   - Records last-known good state in /var/lib/chain-drift/state.json
#     so consecutive-drift counts ride across cron firings.
#
# CRON
#
#   /etc/cron.d/chain-drift-watchdog:
#   * * * * * root /usr/local/bin/chain-drift-watchdog.sh \
#               >> /var/log/chain-drift.log 2>&1
#
# CONFIG (env)
#
#   PEERS                        comma-separated rpc URLs
#                                default: http://127.0.0.1:17750/json_rpc,http://${MONEROUSD_EDGE_HOST}:17750/json_rpc
#   DRIFT_THRESHOLD              max acceptable drift (default 50)
#   ALERT_WEBHOOK                POST {alert} JSON to URL on drift
#   ALERT_RECOVERY_THRESHOLD     min drifted-ticks before alerting
#                                (default 3 — avoids transient warns)
#
# OUTPUT — one line per tick:
#   ok    — every peer within threshold
#   warn  — drift detected, NOT yet at alert threshold
#   alert — drift sustained past threshold; webhook fired (if set)
#
# Per CLAUDE.md rule 110d (engineering ethic — diagnose, never silently
# bury): output is intentionally noisy enough to grep, terse enough to
# fit in cron mail. log+alert separation lets ops route severity.

set -u

PEERS="${PEERS:-http://127.0.0.1:17750/json_rpc,http://${MONEROUSD_EDGE_HOST}:17750/json_rpc}"
DRIFT_THRESHOLD="${DRIFT_THRESHOLD:-50}"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
ALERT_RECOVERY_THRESHOLD="${ALERT_RECOVERY_THRESHOLD:-3}"
STATE_DIR=/var/lib/chain-drift
STATE_FILE="$STATE_DIR/state.json"

mkdir -p "$STATE_DIR"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(now) [chain-drift] $*"; }

# ── Poll every peer ──────────────────────────────────────────────
declare -A heights
declare -A reachable
max_height=0

IFS=',' read -ra PEER_ARR <<< "$PEERS"
for peer in "${PEER_ARR[@]}"; do
  resp=$(curl -sSf --max-time 5 -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"get_info"}' "$peer" 2>/dev/null || echo '')
  if [[ -z "$resp" ]]; then
    heights["$peer"]=-1
    reachable["$peer"]=0
    continue
  fi
  h=$(echo "$resp" | jq -r '.result.height // empty' 2>/dev/null)
  if [[ -z "$h" || "$h" == "null" ]]; then
    heights["$peer"]=-1
    reachable["$peer"]=0
    continue
  fi
  heights["$peer"]="$h"
  reachable["$peer"]=1
  if (( h > max_height )); then max_height=$h; fi
done

# ── Compute drift per peer ──────────────────────────────────────
worst_drift=0
worst_peer=""
declare -A drift_by_peer
for peer in "${!heights[@]}"; do
  h=${heights["$peer"]}
  if (( h < 0 )); then
    drift_by_peer["$peer"]=-1
    continue
  fi
  d=$(( max_height - h ))
  drift_by_peer["$peer"]=$d
  if (( d > worst_drift )); then
    worst_drift=$d
    worst_peer="$peer"
  fi
done

# ── State machine ───────────────────────────────────────────────
prev_state='{"consecutive_warns":0,"last_alert_at":null}'
if [[ -f "$STATE_FILE" ]]; then
  prev_state=$(cat "$STATE_FILE" 2>/dev/null || echo "$prev_state")
fi
prev_warns=$(echo "$prev_state" | jq -r '.consecutive_warns // 0' 2>/dev/null || echo 0)

status="ok"
if (( worst_drift > DRIFT_THRESHOLD )); then
  status="warn"
  prev_warns=$(( prev_warns + 1 ))
  if (( prev_warns >= ALERT_RECOVERY_THRESHOLD )); then
    status="alert"
  fi
else
  prev_warns=0
fi

# ── Persist state ────────────────────────────────────────────────
ts=$(now)
jq -n \
  --arg ts "$ts" \
  --argjson warns $prev_warns \
  --argjson max $max_height \
  --argjson drift $worst_drift \
  --arg worst "$worst_peer" \
  --arg status "$status" \
  '{ ts: $ts, status: $status, max_height: $max, worst_drift: $drift,
     worst_peer: $worst, consecutive_warns: $warns }' > "$STATE_FILE"

# ── Emit summary line + alert when promoted ─────────────────────
peer_summary=""
for peer in "${PEER_ARR[@]}"; do
  h=${heights["$peer"]}
  d=${drift_by_peer["$peer"]}
  if (( h < 0 )); then
    peer_summary="$peer_summary [unreachable]"
  else
    peer_summary="$peer_summary $(echo "$peer" | sed -E 's,https?://,,;s,/json_rpc,,'):h=$h,d=$d"
  fi
done

case "$status" in
  ok)    log "ok max=$max_height drift=$worst_drift  $peer_summary" ;;
  warn)  log "warn max=$max_height drift=$worst_drift on $worst_peer (consecutive=$prev_warns/$ALERT_RECOVERY_THRESHOLD)  $peer_summary" ;;
  alert)
    log "ALERT max=$max_height drift=$worst_drift on $worst_peer  $peer_summary"
    if [[ -n "$ALERT_WEBHOOK" ]]; then
      payload=$(jq -n \
        --arg ts "$ts" \
        --arg worst "$worst_peer" \
        --argjson drift $worst_drift \
        --argjson max $max_height \
        '{event:"chain_drift_alert",ts:$ts,worst_peer:$worst,worst_drift:$drift,max_height:$max}')
      curl -sSf --max-time 10 -X POST -H 'Content-Type: application/json' \
        -d "$payload" "$ALERT_WEBHOOK" > /dev/null 2>&1 \
        || log "alert webhook POST failed"
    fi
    ;;
esac
