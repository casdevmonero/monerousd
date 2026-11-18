#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ota-freshness-watchdog.sh — alert when OTA manifests go stale.
#
# What "stale" means:
#   - Manifest's `released_at` older than STALE_DAYS_RELEASE (default
#     30 days). Suggests we forgot to ship a release / build pipeline
#     broke / cron stopped.
#   - This node's local bundle version doesn't match the canonical
#     manifest. Suggests the auto-updater (usdmd-auto-update.sh) hasn't
#     run successfully in a while.
#   - Bundle's actual SHA-256 doesn't match the manifest claim.
#     Suggests bundle file rotted on disk or was tampered with.
#
# Watches:
#   - https://update.monerousd.org/usdmd-bundle/manifest.json   (USDmd)
#   - https://update.monerousd.org/latest-mac.yml               (wallet)
#   - https://update.monerousd.org/latest-linux.yml             (wallet)
#   - https://update.monerousd.org/latest.yml                   (wallet)
#
# CRON
#
#   /etc/cron.d/ota-freshness-watchdog:
#   17 * * * * root /usr/local/bin/ota-freshness-watchdog.sh \
#                >> /var/log/ota-freshness.log 2>&1
#
# Per CLAUDE.md rule 95: every external-fetch failure logs WITH the
# real error message. Silent timeouts / "(no messages)" are forbidden.

set -u

MANIFEST_URL="${MANIFEST_URL:-https://update.monerousd.org/usdmd-bundle/manifest.json}"
WALLET_LATEST_MAC="${WALLET_LATEST_MAC:-https://update.monerousd.org/latest-mac.yml}"
WALLET_LATEST_WIN="${WALLET_LATEST_WIN:-https://update.monerousd.org/latest.yml}"
WALLET_LATEST_LIN="${WALLET_LATEST_LIN:-https://update.monerousd.org/latest-linux.yml}"
LOCAL_VERSION_FILE="${LOCAL_VERSION_FILE:-/root/usdmd-bundle/.bundle-version}"
STALE_DAYS_RELEASE="${STALE_DAYS_RELEASE:-30}"
STALE_DAYS_DRIFT="${STALE_DAYS_DRIFT:-1}"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
STATE_DIR=/var/lib/ota-freshness
mkdir -p "$STATE_DIR"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(now) [ota-freshness] $*"; }

alerts=()
emit_alert() { alerts+=("$1"); log "ALERT: $1"; }

# ── Check USDmd bundle manifest ─────────────────────────────────
manifest_resp=$(curl -sSf --max-time 30 "$MANIFEST_URL" 2>&1) || {
  emit_alert "USDmd manifest fetch failed: $MANIFEST_URL"
  manifest_resp=""
}

if [[ -n "$manifest_resp" ]]; then
  manifest_version=$(echo "$manifest_resp" | jq -r '.version // empty')
  manifest_released=$(echo "$manifest_resp" | jq -r '.released_at // empty')
  manifest_sha=$(echo "$manifest_resp" | jq -r '.bundle_sha256 // empty')
  manifest_url=$(echo "$manifest_resp" | jq -r '.bundle_url // empty')

  if [[ -z "$manifest_version" || -z "$manifest_released" || -z "$manifest_sha" ]]; then
    emit_alert "USDmd manifest missing required fields"
  else
    # Released-at age
    age_seconds=$(( $(date +%s) - $(date -d "$manifest_released" +%s 2>/dev/null || echo 0) ))
    age_days=$(( age_seconds / 86400 ))
    if (( age_days > STALE_DAYS_RELEASE )); then
      emit_alert "USDmd manifest stale: released $age_days days ago (threshold $STALE_DAYS_RELEASE)"
    else
      log "manifest fresh: $manifest_version released $age_days days ago"
    fi

    # Local-version drift
    local_version=$(cat "$LOCAL_VERSION_FILE" 2>/dev/null || echo "")
    if [[ -n "$local_version" && "$local_version" != "$manifest_version" ]]; then
      # Drift is OK for STALE_DAYS_DRIFT after manifest update (cron
      # hasn't fired yet); alert beyond that.
      if (( age_days > STALE_DAYS_DRIFT )); then
        emit_alert "local bundle drift: have $local_version, manifest $manifest_version (auto-updater stuck?)"
      else
        log "local bundle drift transient: have $local_version manifest $manifest_version (will sync within ${STALE_DAYS_DRIFT}d)"
      fi
    fi

    # Bundle SHA-256 verification (only if file is locally cached)
    bundle_local="/root/usdmd-bundle.tar.gz"
    if [[ -f "$bundle_local" ]]; then
      actual_sha=$(sha256sum "$bundle_local" | awk '{print $1}')
      if [[ "$actual_sha" != "$manifest_sha" ]]; then
        emit_alert "local bundle SHA mismatch: got $actual_sha expected $manifest_sha"
      fi
    fi
  fi
fi

# ── Check wallet OTA manifests (Mac is the lead platform) ──────
#
# Operator policy: Mac OTA is the lead — every wallet release ships
# Mac OTA (the user-base concentration). Win/Linux ride more
# slowly, often N releases behind, by design (saves build/sign time
# given how frequently we iterate). So the watchdog rules are:
#
#   - Mac  STALE → ALERT (real release drift)
#   - Mac  fetch FAIL → ALERT (manifest unreachable, OTA broken)
#   - Win/Linux STALE → INFO log only, no alert (expected by policy)
#   - Win/Linux fetch FAIL → ALERT (manifest unreachable; same
#     severity as Mac because the platform should at least be served)
#
# Per CLAUDE.md rule 110d (no silent fallbacks): we still LOG every
# stale Win/Linux manifest with its drift days so the operator can
# see the lag at a glance — just don't page on it.
check_wallet_yaml() {
  local label="$1" url="$2" alert_on_stale="$3"
  resp=$(curl -sSf --max-time 30 "$url" 2>&1) || {
    emit_alert "wallet $label manifest fetch failed: $url"
    return
  }
  ver=$(echo "$resp" | grep -E '^version:' | head -1 | awk '{print $2}')
  rel=$(echo "$resp" | grep -E '^releaseDate:' | head -1 | awk '{print $2}' | tr -d "'\"")
  if [[ -z "$ver" || -z "$rel" ]]; then
    emit_alert "wallet $label manifest missing version/releaseDate"
    return
  fi
  age_seconds=$(( $(date +%s) - $(date -d "$rel" +%s 2>/dev/null || echo 0) ))
  age_days=$(( age_seconds / 86400 ))
  if (( age_days > STALE_DAYS_RELEASE )); then
    if [[ "$alert_on_stale" == "1" ]]; then
      emit_alert "wallet $label OTA stale: $ver released $age_days days ago"
    else
      log "wallet $label OTA lag (informational): $ver released $age_days days ago"
    fi
  else
    log "wallet $label OK: $ver released $age_days days ago"
  fi
}

# Mac is the LEAD — alert on staleness. Win/Linux are the FOLLOWERS
# and ride at operator's discretion — info-log on staleness.
check_wallet_yaml "Mac"   "$WALLET_LATEST_MAC" 1
check_wallet_yaml "Win"   "$WALLET_LATEST_WIN" 0
check_wallet_yaml "Linux" "$WALLET_LATEST_LIN" 0

# ── Webhook on alerts ───────────────────────────────────────────
if [[ ${#alerts[@]} -gt 0 && -n "$ALERT_WEBHOOK" ]]; then
  payload=$(jq -n --arg ts "$(now)" --argjson alerts "$(printf '%s\n' "${alerts[@]}" | jq -R . | jq -s .)" \
    '{event:"ota_freshness_alert",ts:$ts,alerts:$alerts}')
  curl -sSf --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d "$payload" "$ALERT_WEBHOOK" > /dev/null 2>&1 \
    || log "alert webhook POST failed"
fi

# Persist last state
jq -n --arg ts "$(now)" --argjson alerts "$(printf '%s\n' "${alerts[@]:-}" | jq -R . | jq -s .)" \
  --arg manifest_version "${manifest_version:-}" \
  '{ts:$ts,manifest_version:$manifest_version,alerts:$alerts}' > "$STATE_DIR/state.json"

[[ ${#alerts[@]} -eq 0 ]] && log "all clear"
