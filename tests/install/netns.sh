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
# changes nothing, that revert restores the namespace's values exactly (a key
# handed back to another sysctl file keeps that file's value), and finally
# that the host's sysctls and files are byte-for-byte unchanged.
#
# A third namespace tunes NICs: a veth pair v0 (4 queues, 2 in use) whose
# peer sits in a namespace of its own as the gateway, and a single-queue
# veth s0. A fresh sysfs is mounted read-only with only those devices' queue
# directories writable, and /proc/irq is read-only. XUI_TUNE_NIC=v0,s0 makes
# them the uplinks: XPS on v0 and RPS/RFS on s0 as planned, a second apply
# changes nothing, "tune queues --now" raises v0 to 4 queues under the
# watchdog (it pings the gateway's namespace), and revert puts every queue
# file back. The host's interrupt CPUs and RPS/XPS files must not change.
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
        for f in /proc/irq/*/smp_affinity_list /sys/class/net/*/queues/*/rps_cpus \
            /sys/class/net/*/queues/*/rps_flow_cnt /sys/class/net/*/queues/*/xps_cpus; do
            if [[ -r $f ]]; then printf '%s=%s\n' "$f" "$(cat "$f" 2>/dev/null)"; fi
        done
        for f in /etc/systemd/system/irqbalance.service.d /etc/systemd/system/x-ui-nic.service; do
            if [[ -e $f ]]; then find "$f" -type f -exec sha256sum {} +; fi
        done
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
    # A key handed back takes another sysctl file's value and x-ui drops it,
    # so revert leaves that value; every other key goes back to before.
    if kb.get("hand_back"):
        if kb["write"] != kb.get("others"):
            errors.append(f"{k}: handed back {kb['write']}, but {kb.get('others_file')} sets {kb.get('others')}")
        if kr["live"] != kb["write"]:
            errors.append(f"{k}: revert left {kr['live']}, handed back {kb['write']}")
    elif kr["live"] != kb["live"]:
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

# NIC tuning on veth devices, with the gateway in a namespace of its own.
set +e
unshare --net --mount --propagation private bash -s "$BIN" "$work/nic" <<'INNER'
set -euo pipefail
BIN=$1; W=$2
mkdir -p "$W"
fail() { echo "FAIL: $*" >&2; exit 1; }
gw=""
cleanup() { if [[ -n $gw ]]; then kill "$gw" 2>/dev/null || true; fi; }
trap cleanup EXIT

ip link set lo up
ip link add v0 numrxqueues 4 numtxqueues 4 type veth peer name v1 numrxqueues 4 numtxqueues 4
ip link add s0 numrxqueues 1 numtxqueues 1 type veth peer name s1 numrxqueues 1 numtxqueues 1
# The gateway: v1 in a network namespace that lives as long as its process.
unshare --net sleep 600 &
gw=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ $(readlink "/proc/$gw/ns/net") != "$(readlink /proc/self/ns/net)" ]] && break
    sleep 0.1
done
ip link set v1 netns "$gw"
nsenter --net="/proc/$gw/ns/net" sh -c 'ip link set lo up; ip addr add 192.0.2.1/24 dev v1; ip link set v1 up'
ip addr add 192.0.2.2/24 dev v0
ip link set v0 up; ip link set s0 up; ip link set s1 up
ip route add default via 192.0.2.1 dev v0
ethtool -L v0 rx 2 tx 2
ping -c1 -W2 192.0.2.1 >/dev/null || fail "the gateway's namespace does not answer"

mount --bind /proc/sys /proc/sys
mount -o remount,bind,ro /proc/sys
mount --bind /proc/sys/net /proc/sys/net
mount -o remount,bind,rw /proc/sys/net
mount --bind /proc/irq /proc/irq
mount -o remount,bind,ro /proc/irq
# This namespace's sysfs, read-only but for the test devices' queues.
mount -t sysfs sysfs /sys
mount --bind /sys /sys
mount -o remount,bind,ro /sys
for d in v0 s0; do
    mount --bind "/sys/class/net/$d/queues" "/sys/class/net/$d/queues"
    mount -o remount,bind,rw "/sys/class/net/$d/queues"
done
for d in /etc/sysctl.d /etc/systemd/system /etc/modules-load.d /etc/modprobe.d; do
    mkdir -p "$W/copy$d"
    [[ -d $d ]] || continue
    cp -a "$d/." "$W/copy$d/"
    mount -t tmpfs tmpfs "$d"
    cp -a "$W/copy$d/." "$d/"
done
mount -t tmpfs tmpfs /var/lib
if echo 1500 2>/dev/null > /sys/class/net/v0/mtu; then fail "/sys was writable outside the queues"; fi
if echo 0 2>/dev/null > /proc/irq/default_smp_affinity; then fail "/proc/irq was writable"; fi

queues() {
    for f in /sys/class/net/{v0,s0}/queues/*/{xps_cpus,rps_cpus,rps_flow_cnt}; do
        if [[ -r $f ]]; then echo "$f=$(cat "$f" 2>/dev/null)"; fi
    done
}
queues > "$W/queues.before"
export XUI_TUNE_ONLY=net XUI_TUNE_NIC=v0,s0
"$BIN" tune status --json > "$W/before.json" || fail "status before"
"$BIN" tune apply > "$W/apply1.txt" || fail "apply"
cat "$W/apply1.txt"
"$BIN" tune status --json > "$W/after.json" || fail "status after"
"$BIN" tune apply > "$W/apply2.txt" || fail "second apply"
grep -q "nothing to change" "$W/apply2.txt" || fail "second apply changed something: $(cat "$W/apply2.txt")"
"$BIN" tune status --check >/dev/null || fail "status --check reports drift after apply"
"$BIN" tune nic > "$W/nic.txt" || fail "tune nic"
grep -q "nothing to change" "$W/nic.txt" || fail "tune nic changed something: $(cat "$W/nic.txt")"
"$BIN" tune queues > "$W/queues.txt" || fail "tune queues"
grep -q "v0: 2 of 4 queues: 4 at the next boot" "$W/queues.txt" || fail "queue plan: $(cat "$W/queues.txt")"
"$BIN" tune queues --now > "$W/raise.txt" || fail "queues --now: $(cat "$W/raise.txt")"
cat "$W/raise.txt"
ethtool -l v0 | tail -4 | grep -q "RX:[[:space:]]*4" || fail "v0 not raised: $(ethtool -l v0)"
"$BIN" tune status --json > "$W/raised.json" || fail "status raised"
"$BIN" tune status --check >/dev/null || fail "status --check reports drift after the raise"
"$BIN" tune revert > "$W/revert.txt" || fail "revert"
cat "$W/revert.txt"
grep -q "v0 keeps 4 queues until the next reboot (2 after it)" "$W/revert.txt" || fail "revert did not report the queues"
ethtool -l v0 | tail -4 | grep -q "RX:[[:space:]]*4" || fail "revert changed the queue count"
queues > "$W/queues.reverted"

python3 -I - "$W" <<'PY'
import json, sys
w = sys.argv[1]
load = lambda n: json.load(open(f"{w}/{n}"))
before, after, raised = load("before.json"), load("after.json"), load("raised.json")
def mask(s):
    cpus, base = set(), 0
    for g in reversed(s.strip().split(",")):
        v = int(g, 16)
        cpus |= {base + b for b in range(32) if v >> b & 1}
        base += 32
    return cpus
def cpulist(s):
    out = set()
    if s in ("", "-"):
        return out
    for p in s.split(","):
        a, _, b = p.partition("-")
        out |= set(range(int(a), int(b or a) + 1))
    return out
def files(name):
    return dict(l.strip().split("=", 1) for l in open(f"{w}/{name}") if "=" in l)
errors = []
nics = {n["nic"]["name"]: n for n in before["nics"]["nics"]}
if set(nics) != {"v0", "s0"}:
    errors.append(f"uplinks {sorted(nics)}")
eligible = cpulist(before["nics"]["eligible"])
planned = {x["key"]: x.get("write") for x in nics["v0"].get("xps") or []}
if len(planned) != 2 or not all(planned.values()):
    errors.append(f"v0: XPS not planned: {planned}")
live = {n["nic"]["name"]: n for n in after["nics"]["nics"]}
for x in live["v0"].get("xps") or []:
    if x.get("write"):
        errors.append(f"v0 {x['key']}: still not applied")
    if cpulist(x["live"]) != cpulist(planned.get(x["key"]) or ""):
        errors.append(f"v0 {x['key']}: live {x['live']}, planned {planned.get(x['key'])}")
s0 = {x["key"]: x for x in live["s0"].get("rps") or []}
if cpulist(s0.get("rx-0/rps_cpus", {}).get("live", "")) != eligible:
    errors.append(f"s0 rps_cpus {s0.get('rx-0/rps_cpus')}, eligible {sorted(eligible)}")
if int(s0.get("rx-0/rps_flow_cnt", {}).get("live", "0")) < 32768:
    errors.append(f"s0 rps_flow_cnt {s0.get('rx-0/rps_flow_cnt')}")
keys = {k["key"]: k for k in before["plan"]["sysctl"]}
if keys.get("net.core.rps_sock_flow_entries", {}).get("state") != "missing":
    errors.append(f"rps_sock_flow_entries: {keys.get('net.core.rps_sock_flow_entries')} (global: missing in a namespace)")
r = {n["nic"]["name"]: n for n in raised["nics"]["nics"]}["v0"]
xps4 = [cpulist(x["live"]) for x in r.get("xps") or []]
if r["queues"]["current"] != 4 or len(xps4) != 4 or any(x.get("write") for x in r["xps"]):
    errors.append(f"after the raise: {r['queues']}, xps {r.get('xps')}")
elif set().union(*xps4) != eligible or sum(len(x) for x in xps4) != len(eligible):
    errors.append(f"after the raise, XPS does not send every CPU on one queue: {xps4}")
orig, now = files("queues.before"), files("queues.reverted")
for f, v in orig.items():
    if now.get(f) != v:
        errors.append(f"revert: {f} is {now.get(f)}, was {v}")
for f, v in now.items():
    if f.endswith("xps_cpus") and f not in orig and mask(v):
        errors.append(f"revert: {f} (a raised queue) left at {v}")
print(f"netns (nic): XPS on v0 ({len(planned)} queues, then 4), RPS/RFS on s0, raise 2 -> 4 under the watchdog, revert")
if errors:
    print("\n".join("FAIL: " + e for e in errors))
    sys.exit(1)
PY
INNER
[[ $? -eq 0 ]] || rc=1
set -e

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
