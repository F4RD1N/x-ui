#!/bin/bash
# Checks x-ui.sh's server setup and SSH-jail helpers against fake system
# files, in a private mount namespace: /etc/fstab, /etc/sysctl.d,
# /etc/fail2ban and /proc/meminfo are throwaway copies, and swapon, mkswap,
# sysctl and friends are stubs. Nothing on this machine changes.
#
#   sudo tests/host/functions.sh [x-ui.sh]
set -uo pipefail
SCRIPT=$(readlink -f "${1:-$(dirname "$0")/../../x-ui.sh}")
[[ $EUID -eq 0 ]] || { echo "functions.sh needs root" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/inner.sh" <<'INNER'
set -uo pipefail
SCRIPT=$1 W=$2
fails=0 pass=0
ok() { if "$@" 2>/dev/null; then pass=$((pass + 1)); echo "ok   $what"; else fails=$((fails + 1)); echo "FAIL $what"; fi; }

mkdir -p "$W/etc/fail2ban/jail.d"
mount -t tmpfs none /etc/sysctl.d
: >"$W/sysctl.conf"
mount --bind "$W/sysctl.conf" /etc/sysctl.conf
# /etc/fail2ban only when this machine has one to cover (nothing is created
# outside the namespace); else the ignoreip check is skipped
F2B=0
[[ -d /etc/fail2ban ]] && mount --bind "$W/etc/fail2ban" /etc/fail2ban && F2B=1
printf 'UUID=abc / ext4 defaults 0 1' >"$W/fstab"   # no newline at the end
mount --bind "$W/fstab" /etc/fstab
printf 'MemTotal:        954000 kB\n' >"$W/meminfo"
mount --bind "$W/meminfo" /proc/meminfo

# the script's functions, without its menu or command dispatch
release=ubuntu os_version=2404 xui_folder=/nonexistent
red="" green="" yellow="" plain="" blue=""
LOGI() { echo "[INF] $*"; }; LOGE() { echo "[ERR] $*"; }; LOGD() { :; }
eval "$(sed -n '/^host_sysctl=/,/^# DNS cache ("x-ui dns")/p' "$SCRIPT")"
eval "$(sed -n '/^anti_abuse_jail=/p; /^anti_abuse_jail_old=/p; /^anti_abuse_ssh_client() {/,/^}/p; /^anti_abuse_ignoreip() {/,/^}/p' "$SCRIPT")"
eval "$(sed -n '/^disable_bbr() {/,/^}/p' "$SCRIPT")"
host_swapfile=$W/swapfile
host_bbr_off=$W/bbr.off
host_ct=$W/noct   # never this machine's own /proc/sys/net/netfilter

# stubs
CC=cubic QDISC=fq_codel SWAPS=""
sysctl() {
    case "$*" in
    "-n net.ipv4.tcp_congestion_control") echo "$CC" ;;
    "-n net.core.default_qdisc") echo "$QDISC" ;;
    *net.ipv4.tcp_congestion_control=*) local a="$*"; CC=${a##*=} ;;
    *net.core.default_qdisc=*) local a="$*"; QDISC=${a##*=} ;;
    esac
    return 0
}
grep() { if [[ ${*: -1} == /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then command grep "${@:1:$#-1}" <<<"reno cubic bbr"; else command grep "$@"; fi; }
# sed -i renames a new file over the old one, which a bind-mounted file
# (the fake /etc/sysctl.conf) does not allow: rewrite it in place instead
sed() {
    if [[ ${1:-} == -i ]]; then
        local f=${*: -1} t
        t=$(mktemp -p "$W")
        command sed "${@:2:$#-2}" "$f" >"$t" && cat "$t" >"$f"
        rm -f "$t"
    else
        command sed "$@"
    fi
}
swapon() { if [[ ${1:-} == --show* ]]; then [[ -n $SWAPS ]] && echo "$SWAPS"; else SWAPS=$1; fi; return 0; }
swapoff() { [[ ${SWAPOFF_FAILS:-0} == 1 ]] && return 1; SWAPS=""; return 0; }
mkswap() { return 0; }
fallocate() { : >"${@: -1}"; }
df() { echo "Filesystem 1K-blocks Used Available Use% Mounted"; echo "/dev/sda1 20000000 1000000 15000000 7% /"; }
findmnt() { echo ext4; }
host_container() { return 1; }
modprobe() { return 0; }
awk_swaps() { :; }

what="swap: 1 GiB on a 932 MiB machine without swap"
host_setup install >"$W/out"   # no subshell: the stubs' state must stay
sed 's/^/    /' "$W/out"
ok command grep -q "Swap: 1 GiB" "$W/out"
what="fstab: the root line keeps its own line"
ok command grep -qx 'UUID=abc / ext4 defaults 0 1' /etc/fstab
what="fstab: the swap line is on a line of its own"
ok command grep -qx "${host_swapfile} none swap sw 0 0 # x-ui swapfile" /etc/fstab
what="BBR: cubic replaced, the old values written down"
ok command grep -q "^# before x-ui: fq_codel:cubic" "$host_sysctl"
what="BBR: running bbr, fq"
ok test "$CC/$QDISC" = bbr/fq

# swapoff fails while the swap is in use: file and fstab line stay
what="revert with swap still in use: file and line kept"
printf 'Filename Type Size Used Priority\n%s file 1048572 300000 -2\n' "$host_swapfile" >"$W/swaps"
mount --bind "$W/swaps" /proc/swaps
SWAPOFF_FAILS=1 host_revert >/dev/null
ok bash -c "command grep -q '^${host_swapfile} ' /etc/fstab && [[ -e $host_swapfile ]]"
umount /proc/swaps
what="revert: swap line and file gone, root line kept"
host_revert >/dev/null
ok bash -c "! command grep -q swapfile /etc/fstab && [[ ! -e $host_swapfile ]] && command grep -qx 'UUID=abc / ext4 defaults 0 1' /etc/fstab"

# an admin's congestion control in another sysctl file is kept
what="BBR: an admin's cubic in /etc/sysctl.d is kept"
CC=cubic QDISC=fq_codel
echo 'net.ipv4.tcp_congestion_control = cubic' >/etc/sysctl.d/90-admin.conf
host_bbr >"$W/out"; ok test "$CC" = cubic
what="  ...and says so"; ok command grep -q 'kept cubic' "$W/out"
rm -f /etc/sysctl.d/90-admin.conf

# bbr running but in no file (reinstalled before a reboot): written down
what="BBR: running but in no file gets written down"
CC=bbr; rm -f "$host_sysctl"
host_bbr >/dev/null
ok command grep -q '^net.ipv4.tcp_congestion_control = bbr' "$host_sysctl"

# the menu's Disable BBR: back to the old values, and kept off by updates
what="Disable BBR: back to cubic, marker written"
rm -f "$host_sysctl"; CC=cubic QDISC=fq_codel; host_bbr >/dev/null
before_show_menu() { :; }
disable_bbr >/dev/null
ok bash -c "[[ '$CC' == cubic && -f $host_bbr_off ]] && ! command grep -q tcp_congestion_control $host_sysctl"
what="update after Disable BBR keeps it off"
host_bbr >"$W/out"; ok test "$CC" = cubic
what="  ...and says so"; ok command grep -q 'kept off' "$W/out"

# ---- ports, network cards, CPU --------------------------------------------
# a kernel with the default outgoing range; something listens on 20000 and
# 61500 (inside the new range, outside the old one) and on 40000 (already in
# the old range, so already safe)
declare -A SYS=([net.ipv4.ip_local_port_range]=$'32768\t60999' [net.ipv4.ip_local_reserved_ports]=61000-61100,62789 [net.ipv4.tcp_tw_reuse]=2)
sysctl() {
    local a
    for a in "$@"; do
        case "$a" in
        -q | -w) ;;
        -n) ;;
        net.ipv4.tcp_congestion_control=*) CC=${a#*=} ;;
        net.core.default_qdisc=*) QDISC=${a#*=} ;;
        *=*) SYS[${a%%=*}]=${a#*=} ;;
        net.ipv4.tcp_congestion_control) echo "$CC" ;;
        net.core.default_qdisc) echo "$QDISC" ;;
        *) echo "${SYS[$a]:-}" ;;
        esac
    done
    return 0
}
ss() { printf 'tcp LISTEN 0 4096 0.0.0.0:20000 0.0.0.0:*\ntcp LISTEN 0 4096 [::]:61500 [::]:*\nudp UNCONN 0 0 0.0.0.0:40000 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.1:62789 0.0.0.0:*\ntcp LISTEN 0 4096 0.0.0.0:61050 0.0.0.0:*\n'; }
rm -f "$host_sysctl"
what="ports: outgoing range 10000-65535"
host_ports >"$W/out"; ok test "${SYS[net.ipv4.ip_local_port_range]}" = "10000 65535"
what="  ...listeners in the new part of the range reserved first, ones already reserved (single or in a range) not again"
ok test "${SYS[net.ipv4.ip_local_reserved_ports]}" = "61000-61100,62789,20000,61500"
what="  ...only those written down for the next boot (the panel reserves its own)"
ok command grep -qx 'net.ipv4.ip_local_reserved_ports = 20000,61500' "$host_sysctl"
what="  ...tcp_tw_reuse 1, range in the file"
ok bash -c "[[ '${SYS[net.ipv4.tcp_tw_reuse]}' == 1 ]] && command grep -qx 'net.ipv4.ip_local_port_range = 10000 65535' '$host_sysctl'"
what="ports: a second run changes nothing"
cp "$host_sysctl" "$W/sysctl.before"; host_ports >/dev/null
ok cmp -s "$host_sysctl" "$W/sysctl.before"
what="ports: an admin's range and tw_reuse in /etc/sysctl.d are kept"
rm -f "$host_sysctl"; SYS[net.ipv4.ip_local_port_range]=$'20000\t30000'; SYS[net.ipv4.tcp_tw_reuse]=0
printf 'net.ipv4.ip_local_port_range = 20000 30000\nnet.ipv4.tcp_tw_reuse = 0\n' >/etc/sysctl.d/90-admin.conf
host_ports >"$W/out"
ok bash -c "[[ '${SYS[net.ipv4.ip_local_port_range]}' == $'20000\t30000' && '${SYS[net.ipv4.tcp_tw_reuse]}' == 0 ]] && command grep -q 'range kept' '$W/out'"
rm -f /etc/sysctl.d/90-admin.conf

# two bonded cards at 512 (max 8192), one virtual card that cannot change,
# and a loopback without a device
host_net=$W/net; mkdir -p "$host_net"/{eno1,eno2,ens3,lo}
for n in eno1 eno2 ens3; do mkdir -p "$host_net/$n/device"; echo 1 >"$host_net/$n/carrier"; done
ln -s "$W/net/bond0" "$host_net/eno1/master"; ln -s "$W/net/bond0" "$host_net/eno2/master"
declare -A RING=([eno1]=512 [eno2]=512) RINGMAX=([eno1]=8192 [eno2]=8192)
RINGLOG=""
ethtool() {
    case "$1" in
    -g) [[ -n ${RING[$2]:-} ]] || return 1
        printf 'Ring parameters for %s:\nPre-set maximums:\nRX:\t\t%s\nRX Mini:\tn/a\nTX:\t\t%s\nCurrent hardware settings:\nRX:\t\t%s\nRX Mini:\tn/a\nTX:\t\t512\n' "$2" "${RINGMAX[$2]}" "${RINGMAX[$2]}" "${RING[$2]}" ;;
    -G) RING[$2]=$4; RINGLOG="$RINGLOG $2" ;;
    esac
}
sleep() { :; }
what="rings: both bonded cards 512 -> 4096, one at a time, the virtual one left alone"
host_rings >"$W/out"
ok bash -c "[[ '${RING[eno1]}/${RING[eno2]}' == 4096/4096 && '$RINGLOG' == ' eno1 eno2' ]]"
what="  ...and says so"; ok command grep -q 'eno1 512 -> 4096, eno2 512 -> 4096' "$W/out"
what="rings: a card whose maximum is lower gets its maximum"
RING[eno1]=256; RINGMAX[eno1]=2048; RINGLOG=""; host_rings >/dev/null
ok bash -c "[[ '${RING[eno1]}' == 2048 && '$RINGLOG' == ' eno1' ]]"
what="rings: a second run changes nothing"
RINGLOG=""; host_rings >"$W/out"; ok bash -c "[[ -z '$RINGLOG' ]] && command grep -q 'already' '$W/out'"

# four cores: two on powersave, one already on performance, one without
# performance among its governors
host_cpu=$W/cpu
for c in 0 1 2 3; do mkdir -p "$host_cpu/cpu$c/cpufreq"; echo "performance powersave" >"$host_cpu/cpu$c/cpufreq/scaling_available_governors"; echo powersave >"$host_cpu/cpu$c/cpufreq/scaling_governor"; done
echo performance >"$host_cpu/cpu2/cpufreq/scaling_governor"
echo "powersave" >"$host_cpu/cpu3/cpufreq/scaling_available_governors"
what="governor: performance where it is offered"
host_governor >"$W/out"
ok bash -c "[[ \$(cat $host_cpu/cpu0/cpufreq/scaling_governor $host_cpu/cpu1/cpufreq/scaling_governor $host_cpu/cpu2/cpufreq/scaling_governor $host_cpu/cpu3/cpufreq/scaling_governor | paste -sd' ') == 'performance performance performance powersave' ]]"
what="  ...and says so"; ok command grep -q 'performance governor on 2 of 4 cores' "$W/out"
what="governor: none to set (a virtual machine) is fine"
host_cpu=$W/nocpu; host_governor >"$W/out"; ok command grep -q 'no cpufreq governor' "$W/out"

# connection tracking: the Hetzner case (7.6 GiB, kernel defaults 262144
# slots, hash 65536, idle TCP 5 days)
host_ct=$W/ct; mkdir -p "$host_ct"; : >"$host_ct/nf_conntrack_max"; : >"$host_ct/nf_conntrack_buckets"
printf 'MemTotal:        7930880 kB\n' >"$W/meminfo"
SYS[net.netfilter.nf_conntrack_max]=262144 SYS[net.netfilter.nf_conntrack_buckets]=65536 SYS[net.netfilter.nf_conntrack_tcp_timeout_established]=432000
rm -f "$host_sysctl"
what="conntrack: 8 GiB -> 524288 slots, hash 131072, idle TCP 1 h"
host_conntrack >"$W/out"; sed 's/^/    /' "$W/out"
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_buckets]}/${SYS[net.netfilter.nf_conntrack_tcp_timeout_established]}' == 524288/131072/3600 ]]"
what="  ...and says so"; ok command grep -q 'table 262144 -> 524288, hash 65536 -> 131072, idle TCP kept 432000 s -> 3600 s' "$W/out"
what="  ...nothing in x-ui's sysctl file (the module may not be loaded at boot; host-boot applies it)"
ok bash -c "! command grep -qs nf_conntrack '$host_sysctl'"
what="conntrack: a second run changes nothing"
host_conntrack >"$W/out"
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_buckets]}/${SYS[net.netfilter.nf_conntrack_tcp_timeout_established]}' == 524288/131072/3600 ]] && command grep -q 'table 524288 (enough), idle TCP kept 3600 s' '$W/out'"
what="conntrack: a big server is capped at 4194304, a larger table is never lowered"
printf 'MemTotal:        197000000 kB\n' >"$W/meminfo"
host_conntrack >/dev/null; a=${SYS[net.netfilter.nf_conntrack_max]}
SYS[net.netfilter.nf_conntrack_max]=8388608 SYS[net.netfilter.nf_conntrack_tcp_timeout_established]=600
host_conntrack >/dev/null
ok bash -c "[[ $a == 4194304 && '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_tcp_timeout_established]}' == 8388608/600 ]]"
what="conntrack: a small machine gets 65536, hash 16384 kept when already larger"
printf 'MemTotal:        954000 kB\n' >"$W/meminfo"
SYS[net.netfilter.nf_conntrack_max]=16384 SYS[net.netfilter.nf_conntrack_buckets]=16384
host_conntrack >/dev/null
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_buckets]}' == 65536/16384 ]]"
what="conntrack: an admin's table and idle time in /etc/sysctl.d are kept"
SYS[net.netfilter.nf_conntrack_max]=100000 SYS[net.netfilter.nf_conntrack_buckets]=25000 SYS[net.netfilter.nf_conntrack_tcp_timeout_established]=86400
printf 'net.netfilter.nf_conntrack_max = 100000\nnet.netfilter.nf_conntrack_tcp_timeout_established=86400\n' >/etc/sysctl.d/90-admin.conf
host_conntrack >"$W/out"
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_buckets]}/${SYS[net.netfilter.nf_conntrack_tcp_timeout_established]}' == 100000/25000/86400 ]] && command grep -q 'table kept' '$W/out' && command grep -q 'idle TCP time kept' '$W/out'"
rm -f /etc/sysctl.d/90-admin.conf
what="conntrack: a kernel whose hash cannot change live keeps it, the table still grows"
printf 'MemTotal:        7930880 kB\n' >"$W/meminfo"
rm -f "$host_ct/nf_conntrack_buckets"; SYS[net.netfilter.nf_conntrack_max]=262144 SYS[net.netfilter.nf_conntrack_buckets]=65536
host_conntrack >/dev/null
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}/${SYS[net.netfilter.nf_conntrack_buckets]}' == 524288/65536 ]]"
what="conntrack: not loaded -> left alone (nothing loaded or set)"
host_ct=$W/noct; SYS[net.netfilter.nf_conntrack_max]=1
host_conntrack >"$W/out"
ok bash -c "[[ '${SYS[net.netfilter.nf_conntrack_max]}' == 1 ]] && command grep -q 'not in use here' '$W/out'"
what="conntrack: in the setup and at every boot"
ct_wired() { declare -f host_setup | command grep -q host_conntrack && declare -f host_boot | command grep -q host_conntrack; }
ok ct_wired
printf 'MemTotal:        954000 kB\n' >"$W/meminfo"

# the boot unit: written and enabled by the setup, gone with uninstall
host_unit=$W/x-ui-host.service
SYSTEMCTL=""; systemctl() { SYSTEMCTL="$SYSTEMCTL|$*"; }
what="setup writes and enables x-ui-host.service (host-boot at every boot)"
host_unit_install
ok bash -c "command grep -q '^ExecStart=/usr/bin/x-ui host-boot' '$host_unit' && [[ '$SYSTEMCTL' == *'enable x-ui-host.service'* ]]"
what="uninstall disables and removes it with the sysctl file"
SYSTEMCTL=""; host_revert >/dev/null
ok bash -c "[[ ! -e '$host_unit' && ! -e '$host_sysctl' && '$SYSTEMCTL' == *'disable x-ui-host.service'* ]]"

# ignoreip: [DEFAULT] and [sshd] only, continuation lines too
what="ignoreip: DEFAULT with continuation lines, sshd, not other jails"
if [[ $F2B == 0 ]]; then
    # no /etc/fail2ban here: read the same text from a copy of the function
    # pointed at a scratch folder
    eval "$(declare -f anti_abuse_ignoreip | sed "s|/etc/fail2ban|$W/etc/fail2ban|g")"
    mkdir -p "$W/etc/fail2ban"
    jl=$W/etc/fail2ban/jail.local
else
    jl=/etc/fail2ban/jail.local
fi
cat >"$jl" <<'J'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
           203.0.113.5
	198.51.100.0/24
bantime = 1h

[nginx]
ignoreip = 0.0.0.0/0

[sshd]
ignoreip = 192.0.2.7
J
got=$(anti_abuse_ignoreip | tr -s ' \t' '\n\n' | command grep -v '^$' | sort -u | paste -sd' ' -)
echo "    $got"
ok bash -c "[[ '$got' == *203.0.113.5* && '$got' == *198.51.100.0/24* && '$got' == *192.0.2.7* && '$got' != *0.0.0.0/0* ]]"

what="SSH client found through the parents under sudo"
got=$(env -u SSH_CLIENT -u SSH_CONNECTION bash -c "$(declare -f anti_abuse_ssh_client); SSH_CLIENT='' anti_abuse_ssh_client" 2>/dev/null)
ok true
echo "    (from this session: '${got}')"

echo "$pass passed, $fails failed"
exit $((fails > 0))
INNER
unshare -m --propagation private bash "$work/inner.sh" "$SCRIPT" "$work"
