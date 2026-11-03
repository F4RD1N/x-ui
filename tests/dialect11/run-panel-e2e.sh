#!/usr/bin/env bash
set -euo pipefail
# All sockets and panel sysctl adjustments stay in a disposable network namespace.
# No installed panel, systemd unit, host firewall, or production database is used.
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} != --inside ]]; then
  export D11_HOST_NETNS
  D11_HOST_NETNS=$(readlink /proc/self/ns/net)
  exec unshare --net "$0" --inside "$@"
fi
shift
[[ $(readlink /proc/self/ns/net) != "$D11_HOST_NETNS" ]] || exit 90
ip link set lo up
ip address add 198.18.0.1/32 dev lo
exec python3 "$HERE/panel-e2e.py" "$@"
