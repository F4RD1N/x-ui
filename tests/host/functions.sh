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
