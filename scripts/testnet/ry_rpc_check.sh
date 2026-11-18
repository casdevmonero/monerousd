#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

pkill -f 38191 2>/dev/null; sleep 2
rm -rf /tmp/ry_d3; mkdir -p /tmp/ry_d3
cd /root/MoneroUSD-clean/monero/build/bin
./USDmd --regtest --offline --no-zmq --p2p-bind-port 38192 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38191 --data-dir /tmp/ry_d3 --fixed-difficulty 1 --log-level 1 > /tmp/ry_d3.log 2>&1 &
DPID=$!
sleep 30
echo "=== process alive? ==="; ps -p $DPID >/dev/null && echo "ALIVE pid $DPID" || echo "DEAD"
echo "=== listening ports (daemon) ==="; ss -tlnp 2>/dev/null | grep -E "3819|usdmd|USDmd" || echo "none on 3819x"
echo "=== /get_height ==="; curl -s -m 5 http://127.0.0.1:38191/get_height; echo
echo "=== /json_rpc get_info ==="; curl -s -m 5 http://127.0.0.1:38191/json_rpc -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":"0","method":"get_info"}'; echo
echo "=== full log tail ==="; tail -16 /tmp/ry_d3.log
kill $DPID 2>/dev/null
