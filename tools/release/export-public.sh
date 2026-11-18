#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# export-public.sh — lay the PUBLIC MonerousD repository from this one, with a FRESH history.
#
#   tools/release/export-public.sh <dest-dir> [<git-ref>]
#
# What it does, in order (nothing is ever pushed — publishing stays a person's step):
#   1. `git archive <ref>` (default HEAD) of the tracked tree only: nothing untracked can leak in.
#   2. drops what is the operator's or the agents' own, never the product's: the agent charters and harness notes,
#      the top-level operator `scripts/` (deploys and server setup), this release tool;
#   3. rewrites the operator's server addresses to RFC 5737 documentation addresses;
#   4. REFUSES (exit 2) if the result still holds any release blocker: a private key or token, the private set-aside
#      generator or its paths, a personal email or home path, an operator address, a stale licence name;
#   5. `git init` + ONE initial commit by "The MoneroUSD Protocol" — the private history (personal emails, removed
#      secrets) never reaches the public repository.
set -euo pipefail
DEST=${1:?usage: export-public.sh <dest-dir> [<git-ref>]}
REF=${2:-HEAD}
SRC=$(git rev-parse --show-toplevel)
[ -e "$DEST" ] && { echo "[export] $DEST exists; give a new directory" >&2; exit 1; }
mkdir -p "$DEST"
git -C "$SRC" archive "$REF" | tar -x -C "$DEST"
cd "$DEST"

# 2. not the product
rm -rf AGENTS.md docs/AGENT-LANE-HARNESS-*.md docs/MASTER-BUILD-PROMPT.md scripts tools/release

# 3. operator addresses -> documentation addresses (RFC 5737)
grep -rIlE '148\.163\.122\.39|72\.61\.4\.19' . 2>/dev/null | while read -r f; do
  perl -pi -e 's/148\.163\.122\.39/203.0.113.10/g; s/72\.61\.4\.19/203.0.113.11/g' "$f"
done

# 4. the gate
fail=0
check() { # label, extended regex
  local hits
  hits=$(grep -rIlE "$2" . 2>/dev/null | head -5 || true)
  if [ -n "$hits" ]; then echo "[export] ⛔ $1:"; echo "$hits" | sed 's/^/    /'; fail=1; fi
}
check "private key material"   'BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_|xox[bpas]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}'
check "set-aside generator"    'gen-founder|\.usdmd-genesis-local|gen_genesis_notes|GENESIS_PQ_NOTES|gpc\.hex|MONEROUSD_LOCAL_NOTES|set-aside-gen'
check "home folder path"       '/Users/[A-Za-z]|/home/[a-z][a-z0-9_-]*/'
# The personal names and operator addresses to refuse are read from a file on this machine only, never written here:
# a published pattern would itself be the leak. One extended regex per line; a missing file refuses the export.
PRIVATE_PATTERNS="${MONEROUSD_PRIVATE_PATTERNS:-$HOME/.monerousd-private-patterns}"
if [ -s "$PRIVATE_PATTERNS" ]; then
  check "personal data or operator address" "$(grep -v '^#' "$PRIVATE_PATTERNS" | grep . | paste -sd'|' -)"
else
  echo "[export] ⛔ no private pattern file at $PRIVATE_PATTERNS"; fail=1
fi
check "stale licence name"     'MoneroUSD Protocol License|LICENSE\.MoneroUSD|LicenseRef-MoneroUSD|attribution/display'
for f in LICENSE NOTICE README.md SECURITY.md CONTRIBUTING.md monerousd-node-zkdag/sites/ionswap-monerousd-org/LICENSE; do
  [ -s "$f" ] || { echo "[export] ⛔ missing $f"; fail=1; }
done
if grep -q 'SECURITY-CONTACT-TO-BE-SET' SECURITY.md; then
  echo "[export] ⚠ SECURITY.md still names no contact address: set it before publishing"
fi
[ "$fail" = 0 ] || { echo "[export] REFUSED: $DEST holds a release blocker (left in place to read)"; exit 2; }

# 5. fresh history
git init -q -b main
git add -A
GIT_AUTHOR_NAME="The MoneroUSD Protocol" GIT_AUTHOR_EMAIL="noreply@monerousd.org" \
GIT_COMMITTER_NAME="The MoneroUSD Protocol" GIT_COMMITTER_EMAIL="noreply@monerousd.org" \
  git commit -q -m "MonerousD: initial public release"
echo "[export] ✅ $DEST: $(git ls-files | wc -l | tr -d ' ') files, one commit $(git rev-parse --short HEAD), $(du -sh . | cut -f1)"
echo "[export] nothing was pushed. Publishing is: create the empty public repository, then \`git remote add origin <url> && git push -u origin main\` from $DEST."
