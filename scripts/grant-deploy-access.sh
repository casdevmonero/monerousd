#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# ─────────────────────────────────────────────────────────────────────
# grant-deploy-access.sh
#
# One-shot setup so Claude Code can run the safe-deploy scripts +
# ssh / rsync / scp to the production hosts without per-action
# permission prompts.
#
# Two things happen:
#   1. Bash allowlist patterns are merged into
#      .claude/settings.local.json (no clobber — only adds new ones).
#   2. Tells you to run `ssh-copy-id` once for each host so SSH key
#      auth replaces the brittle expect-script + password approach.
#
# Re-running is idempotent: patterns already present are skipped.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

PROJECT_ROOT=$HOME/Desktop/connect
SETTINGS="$PROJECT_ROOT/.claude/settings.local.json"

if [ ! -d "$PROJECT_ROOT/.claude" ]; then
  echo "  no .claude/ dir at $PROJECT_ROOT — bail" >&2
  exit 1
fi

python3 <<PY
import json
import os

settings_path = "$SETTINGS"

new_patterns = [
  # SSH / rsync / scp to production hosts
  "Bash(ssh root@${MONEROUSD_EDGE_HOST}:*)",
  "Bash(ssh root@${MONEROUSD_VPS_HOST}:*)",
  "Bash(ssh -o*root@${MONEROUSD_EDGE_HOST}:*)",
  "Bash(ssh -o*root@${MONEROUSD_VPS_HOST}:*)",
  "Bash(rsync*${MONEROUSD_EDGE_HOST}*)",
  "Bash(rsync*${MONEROUSD_VPS_HOST}*)",
  "Bash(scp*${MONEROUSD_EDGE_HOST}*)",
  "Bash(scp*${MONEROUSD_VPS_HOST}*)",
  # Safe-deploy scripts
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-ota.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-ion-backend.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-ion-frontend.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-monerousd-site.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-explorer.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-pow-signal-daemon.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-usdmd-binary.sh:*)",
  "Bash(bash $PROJECT_ROOT/scripts/safe-deploy-attestations-rpc.sh:*)",
]

if os.path.exists(settings_path):
    with open(settings_path) as fh:
        cfg = json.load(fh)
else:
    cfg = {}

cfg.setdefault("permissions", {}).setdefault("allow", [])
existing = set(cfg["permissions"]["allow"])
added = [p for p in new_patterns if p not in existing]
cfg["permissions"]["allow"].extend(added)

with open(settings_path, "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")

print(f"  patterns added this run : {len(added)}")
print(f"  total allow patterns    : {len(cfg['permissions']['allow'])}")
if added:
    print(f"  new patterns            :")
    for p in added:
        print(f"    + {p}")
PY

echo ""
echo "  ──────────────────────────────────────────────────────────────"
echo "  next: copy your SSH key to both production hosts (one-time)."
echo "  each command will prompt for root password ONCE; after that,"
echo "  ssh / rsync / scp work without password."
echo "  ──────────────────────────────────────────────────────────────"
echo ""
echo "    ssh-copy-id -i ~/.ssh/id_ed25519.pub root@${MONEROUSD_EDGE_HOST}"
echo "    ssh-copy-id -i ~/.ssh/id_ed25519.pub root@${MONEROUSD_VPS_HOST}"
echo ""
echo "  then in the chat, say 'ready' and I'll run the recovery + OTA"
echo "  ship end-to-end."
