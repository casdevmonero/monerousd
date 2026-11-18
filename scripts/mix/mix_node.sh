#!/bin/bash
# The node, with its outside network cut by the OS when $NET_ROOT/tor-cut says so. Same binary, same flags; nothing inside the node
# knows. net.py starts this in place of the node (NET_NODE_BIN), and `exec` keeps the pid net.py recorded.
#   tor-cut holds "all":   every outbound IP refused, so Tor cannot run. The nodes must use their Unix sockets.
#   tor-cut holds "local": every outbound address refused except this machine, so Tor cannot run and relay faces can.
#   no file:               nothing is cut.
ROOT="${NET_ROOT:?}"
BIN="${MIX_REAL_NODE_BIN:?}"
cut=""
[ -f "$ROOT/tor-cut" ] && cut=$(cat "$ROOT/tor-cut")
case "$cut" in
  all) exec sandbox-exec -p '(version 1)(allow default)(deny network-outbound (remote ip "*:*"))' "$BIN" "$@" ;;
  local) exec sandbox-exec -p '(version 1)(allow default)(deny network-outbound (remote ip "*:*"))(allow network-outbound (remote ip "localhost:*"))' "$BIN" "$@" ;;
  *) exec "$BIN" "$@" ;;
esac
