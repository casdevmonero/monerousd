#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# njalla-keychain.sh — macOS Keychain wrapper for the Njalla
# "bootstrap" API token.
#
# The bootstrap token is the long-lived master key. It is stored
# in the OS keychain (encrypted at rest, gated by the user's login
# password) and NEVER appears on the command line, in shell
# history, in chat, or in files on disk.
#
# Day-to-day publish scripts do NOT use this token directly. They
# call `njalla-keychain.sh get`, mint a short-lived "ephemeral"
# token via the Njalla `add-token` API, do their work, and call
# `remove-token` to delete the ephemeral token before exiting.
# That way:
#   - The master token's exposure surface is one process per
#     publish run, in-memory only, for ~10 seconds.
#   - The ephemeral token is destroyed before any human ever sees
#     it. If it leaks (e.g. into a log file), it's already revoked.
#   - Master-token rotation is one command (`njalla-keychain.sh
#     set`) and you don't have to touch any script or config.
#
# Setup (one time, after generating a token at
# https://njal.la/settings/api/):
#
#   bash scripts/njalla-keychain.sh set
#   (paste your token at the prompt)
#
# Verification:
#   bash scripts/njalla-keychain.sh get  # should echo your token
#
# Rotation (every few months, or any time you suspect leak):
#   1. Generate a new token at njal.la
#   2. Run `bash scripts/njalla-keychain.sh set` and paste the new one
#   3. Delete the OLD token via njal.la/settings/api/

set -euo pipefail

SERVICE="monerousd-njalla-bootstrap"
ACCOUNT="$(id -un)"

cmd="${1:-help}"

case "$cmd" in
  set)
    # Read the token from stdin (or prompt if a tty). Never echo it.
    if [ -t 0 ]; then
      printf "Paste Njalla bootstrap token (input hidden): " >&2
      stty -echo
      read -r token
      stty echo
      printf "\n" >&2
    else
      read -r token
    fi
    if [ -z "$token" ]; then
      echo "no token given — aborting" >&2
      exit 2
    fi
    # Replace any existing entry; -U updates if present.
    security add-generic-password -U \
      -s "$SERVICE" -a "$ACCOUNT" -w "$token" \
      -T "" \
      >/dev/null 2>&1 || {
        echo "failed to write to keychain" >&2
        exit 3
      }
    echo "ok — bootstrap token stored under service '$SERVICE' for user '$ACCOUNT'" >&2
    ;;
  get)
    security find-generic-password -s "$SERVICE" -a "$ACCOUNT" -w 2>/dev/null || {
      echo "no token in keychain — run \`bash $0 set\` first" >&2
      exit 4
    }
    ;;
  delete)
    security delete-generic-password -s "$SERVICE" -a "$ACCOUNT" >/dev/null 2>&1 && \
      echo "ok — removed bootstrap token from keychain" >&2 || \
      echo "no token to remove" >&2
    ;;
  status)
    if security find-generic-password -s "$SERVICE" -a "$ACCOUNT" -g 2>&1 >/dev/null | grep -q "password:"; then
      echo "bootstrap token IS stored in keychain"
    else
      # Fallback: check existence without revealing
      security find-generic-password -s "$SERVICE" -a "$ACCOUNT" >/dev/null 2>&1 && \
        echo "bootstrap token IS stored in keychain" || \
        echo "bootstrap token is NOT stored — run \`bash $0 set\` first"
    fi
    ;;
  *)
    echo "Usage: $0 {set|get|delete|status}"
    echo
    echo "  set     — store the bootstrap Njalla API token in macOS Keychain (interactive prompt)"
    echo "  get     — print the stored bootstrap token to stdout (used by publish scripts)"
    echo "  delete  — remove the stored token from Keychain"
    echo "  status  — report whether a token is currently stored"
    exit 1
    ;;
esac
