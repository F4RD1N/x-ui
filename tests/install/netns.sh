#!/bin/bash
# Applies "x-ui tune" to a throwaway network namespace and checks the result,
# without touching this machine's own kernel settings or files.
#
#   sudo tests/install/netns.sh <x-ui binary>
#
# Inside a private mount + network namespace:
#   - /proc/sys is remounted read-only except /proc/sys/net (the LXC
#     "proc:mixed" model), and /sys read-only, so the kernel itself refuses
#     any write that is not per-namespace;
#   - x-ui's file locations (/etc/sysctl.d, x-ui.service.d, modules-load.d,
#     modprobe.d, /var/lib) are tmpfs copies;
#   - XUI_TUNE_ONLY=net limits live writes to /proc/sys/net and runs no
#     external command.
# It checks that apply writes what its plan said, that a second apply
# changes nothing, that revert restores the namespace's values exactly, and
# finally that the host's sysctls and files are byte-for-byte unchanged.
set -euo pipefail

BIN=$(readlink -f "${1:?usage: netns.sh <x-ui binary>}")
[[ $EUID -eq 0 ]] || { echo "netns.sh needs root" >&2; exit 1; }
command -v unshare >/dev/null || { echo "netns.sh needs unshare" >&2; exit 1; }
command -v python3 >/dev/null || { echo "netns.sh needs python3" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

host_snapshot() {
    {
        find /proc/sys/net/core /proc/sys/net/ipv4 /proc/sys/net/netfilter /proc/sys/net/ipv6/route \
            -maxdepth 1 -type f -perm -u+r 2>/dev/null | grep -v nf_conntrack_count | sort | while read -r f; do
            printf '%s=%s\n' "$f" "$(cat "$f" 2>/dev/null | tr '\n\t' '  ')"
        done
        for f in fs/file-max fs/nr_open kernel/pid_max vm/swappiness vm/max_map_count vm/min_free_kbytes; do
            printf '%s=%s\n' "$f" "$(cat /proc/sys/$f)"
        done
        for d in /etc/sysctl.d /etc/systemd/system/x-ui.service.d /etc/modules-load.d /etc/modprobe.d /var/lib/x-ui; do
            if [[ -e $d ]]; then find "$d" -type f -exec sha256sum {} + 2>/dev/null; fi
        done | sort
        if [[ -r /sys/module/nf_conntrack/parameters/hashsize ]]; then
            echo "hashsize=$(cat /sys/module/nf_conntrack/parameters/hashsize)"
        fi
    }
}

host_snapshot > "$work/host.before"

# Two namespaces: one that sees this machine's sysctl.d files (whose values
# x-ui must keep), and one with none (a fresh machine: every key applies).
rc=0
for scenario in host-files fresh; do
set +e
unshare --net --mount --propagation private bash -s "$BIN" "$work/$scenario" "$scenario" <<'INNER'
set -euo pipefail
BIN=$1; W=$2; SCENARIO=$3
mkdir -p "$W"
fail() { echo "FAIL: $*" >&2; exit 1; }

mount --bind /proc/sys /proc/sys
mount -o remount,bind,ro /proc/sys
mount --bind /proc/sys/net /proc/sys/net
mount -o remount,bind,rw /proc/sys/net
mount --bind /sys /sys
mount -o remount,bind,ro /sys
for d in /etc/sysctl.d /etc/systemd/system /etc/modules-load.d /etc/modprobe.d; do
    mkdir -p "$W/copy$d"
    [[ -d $d ]] || continue
    cp -a "$d/." "$W/copy$d/"
    mount -t tmpfs tmpfs "$d"
    cp -a "$W/copy$d/." "$d/"
done
mount -t tmpfs tmpfs /var/lib
if [[ $SCENARIO == fresh ]]; then
    find /etc/sysctl.d -mindepth 1 -delete
fi
# The guard holds: a global key cannot be written from here.
if echo 1 2>/dev/null > /proc/sys/vm/swappiness; then fail "vm.swappiness was writable"; fi

export XUI_TUNE_ONLY=net
"$BIN" tune status --json > "$W/before.json" || fail "status before"
"$BIN" tune apply --boot | tee "$W/apply1.txt"
"$BIN" tune status --json > "$W/after.json" || fail "status after"
"$BIN" tune apply --boot > "$W/apply2.txt"
[[ -s "$W/apply2.txt" ]] && fail "second apply changed something: $(cat "$W/apply2.txt")"
"$BIN" tune status --check >/dev/null || fail "status --check reports drift after apply"
[[ -f /etc/sysctl.d/51-x-ui.conf ]] || fail "no 51-x-ui.conf in the namespace"
"$BIN" tune revert > "$W/revert.txt" || fail "revert"
"$BIN" tune status --json > "$W/reverted.json" || fail "status reverted"

python3 -I - "$W" "$SCENARIO" <<'PY'
import json, sys
w = sys.argv[1]
load = lambda n: json.load(open(f"{w}/{n}"))
before, after, reverted = load("before.json"), load("after.json"), load("reverted.json")
keys = lambda d: {k["key"]: k for k in d["plan"]["sysctl"]}
b, a, r = keys(before), keys(after), keys(reverted)
errors, changed = [], []
for k, kb in b.items():
    ka, kr = a[k], r[k]
    if kb.get("write"):
        changed.append(k)
        if ka["live"] != kb["write"]:
            errors.append(f"{k}: planned {kb['write']}, live {ka['live']}")
    elif kb["live"] != ka["live"]:
        errors.append(f"{k}: changed without a plan: {kb['live']} -> {ka['live']}")
    if ka.get("write"):
        errors.append(f"{k}: still not applied ({ka['write']})")
    if kr["live"] != kb["live"]:
        errors.append(f"{k}: revert left {kr['live']}, was {kb['live']}")
    if not k.startswith("net.") and kb["state"] != "read-only":
        errors.append(f"{k}: {kb['state']}, expected read-only")
for k in ["net.core.rmem_max", "net.core.netdev_max_backlog", "net.ipv4.tcp_max_orphans"]:
    if k in b and b[k]["state"] not in ("missing", "read-only"):
        errors.append(f"{k} is global, but is {b[k]['state']} in a child namespace")
if len(changed) < 5:
    errors.append(f"only {len(changed)} keys changed: {changed}")
print(f"netns ({sys.argv[2]}): {len(changed)} keys applied and reverted: {', '.join(sorted(changed))}")
if errors:
    print("\n".join("FAIL: " + e for e in errors))
    sys.exit(1)
PY
INNER
[[ $? -eq 0 ]] || rc=1
set -e
done

host_snapshot > "$work/host.after"
if ! diff -u "$work/host.before" "$work/host.after"; then
    echo "FAIL: the host's settings or files changed" >&2
    exit 1
fi
if [[ $rc -ne 0 ]]; then
    echo "FAIL: namespace checks failed" >&2
    exit 1
fi
echo "netns: PASS (host unchanged)"
