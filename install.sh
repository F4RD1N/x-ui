#!/bin/bash
# Non-interactive installer for the x-ui dialect panel.
#
# It asks nothing. Everything has a fixed default, and anything that needs to
# differ is passed as an argument or an environment variable:
#
#   bash install.sh                          install with the defaults below
#   bash install.sh db=https://host/x-ui.db  install, then seed the database
#   XUI_PORT=61000 bash install.sh           override a default
#   bash install.sh update                   upgrade in place, keep the login
#   bash install.sh anti-abuse=off dns=off   leave those two off this time
#
# Run again on a server that already has the panel (and without db=, user=,
# pass=, port= or path=), it updates in place and keeps the login, port and
# path, as "x-ui update" does.
#
# There is no SSL step: this panel is served over plain HTTP by design.
# There is no core selection either -- the panel ships exactly one Xray core,
# the dialect fork, and cannot switch or update it.
#
# Every install and update also sets the server up for a VPN panel:
#   - "x-ui protect": the core's direct connections never reach this server's
#     loopback or private networks; speed-test servers (iperf3) stay stopped.
#   - "x-ui anti-abuse": outgoing brute-force and mail ports, botnet and
#     criminal networks (Spamhaus DROP, fetched every 6 hours),
#     private networks, scans, brute force on other logins (FTP,
#     databases, SIP, mail, ...) and hosts that do not answer are refused;
#     2 failed SSH logins = a ban.
#   - "x-ui dns": a local DNS cache (unbound) in front of the fastest
#     resolvers this server reaches.
#   - BBR with fq, unless another congestion control was chosen; and on a
#     fresh install of a machine with 2 GiB of RAM or less, a 1 GiB swapfile.
# "x-ui anti-abuse off" and "x-ui dns off" are remembered: updates keep them
# off. A fresh install's xray template is the allow-list routing (blocks for
# SMTP, speed tests and IP checkers first); an update keeps the template the
# panel already runs.

set -uo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'

# ---- fixed defaults --------------------------------------------------------
settings_given=""
[[ -n "${XUI_USER+x}${XUI_PASS+x}${XUI_PORT+x}${XUI_PATH+x}" ]] && settings_given=1
XUI_USER="${XUI_USER:-fardin}"
XUI_PASS="${XUI_PASS:-fardin}"
XUI_PORT="${XUI_PORT:-60000}"
XUI_PATH="${XUI_PATH:-hetzner}"
XUI_DB_URL="${XUI_DB_URL:-}"

XUI_REPO="${XUI_REPO:-F4RD1N/x-ui}"
XUI_TAG="${XUI_TAG:-}"                     # empty means latest release
XUI_LOCAL_TARBALL="${XUI_LOCAL_TARBALL:-}" # install from a local build instead
# XUI_MODE=update upgrades in place: the binaries and the core are replaced,
# but the panel's username, password, port and path are left as they are.
# A fresh install (XUI_MODE=install) applies the defaults above. Unset, it is
# an update where a panel with its database is already installed and nothing
# asks for new settings (db=, user=, pass=, port=, path=), else an install:
# the old menus' "x-ui update" runs this script without "update".
XUI_MODE="${XUI_MODE:-auto}"
XUI_ANTI_ABUSE="${XUI_ANTI_ABUSE:-on}"     # off: leave "x-ui anti-abuse" off this time
XUI_DNS="${XUI_DNS:-on}"                   # off: leave "x-ui dns" off this time

xui_folder="/usr/local/x-ui"
db_folder="/etc/x-ui"
unit_file="/etc/systemd/system/x-ui.service"

# ---- arguments -------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        db=*)      XUI_DB_URL="${arg#db=}" ;;
        port=*)    XUI_PORT="${arg#port=}"; settings_given=1 ;;
        user=*)    XUI_USER="${arg#user=}"; settings_given=1 ;;
        pass=*)    XUI_PASS="${arg#pass=}"; settings_given=1 ;;
        path=*)    XUI_PATH="${arg#path=}"; settings_given=1 ;;
        tag=*)     XUI_TAG="${arg#tag=}" ;;
        anti-abuse=*) XUI_ANTI_ABUSE="${arg#anti-abuse=}" ;;
        dns=*)     XUI_DNS="${arg#dns=}" ;;
        update)    XUI_MODE="update" ;;
        install)   XUI_MODE="install" ;;
        *)         echo -e "${yellow}Ignoring unknown argument: $arg${plain}" ;;
    esac
done

die() { echo -e "${red}$*${plain}" >&2; exit 1; }
info() { echo -e "${green}$*${plain}"; }
warn() { echo -e "${yellow}$*${plain}"; }

[[ $EUID -ne 0 ]] && die "This installer must run as root."

# Serialize panel, CLI and direct installer runs before recovery/stage cleanup.
# A panel worker passes its locked FD 9. Verify the descriptor's inode before
# reusing it; an environment marker alone never bypasses lock acquisition.
xui_update_lock="/run/lock/x-ui-update.lock"
command -v flock >/dev/null 2>&1 || die "flock is required to safely install or update x-ui."
mkdir -p /run/lock || die "Cannot create the updater lock directory."
if [[ "${XUI_UPDATE_LOCK_FD:-}" != 9 || ! -e "/proc/$$/fd/9" || ! "/proc/$$/fd/9" -ef "$xui_update_lock" ]]; then
    exec 9>"$xui_update_lock" || die "Cannot open the updater lock."
fi
flock -n 9 || die "Another x-ui installation or update is already running."
export XUI_UPDATE_LOCK_FD=9

# A run that was killed half-way may have left the previous panel moved
# aside: put it back first.
if [[ ! -e "$xui_folder" && -d "$xui_folder.old" ]]; then
    mv "$xui_folder.old" "$xui_folder" && warn "Restored $xui_folder from an interrupted install."
fi
rm -rf /usr/local/.x-ui-stage.*

# (before the mode is chosen: a panel restored here is one to update)
if [[ "$XUI_MODE" == "auto" ]]; then
    if [[ -x "$xui_folder/x-ui" && -f "$db_folder/x-ui.db" && -z "$XUI_DB_URL" && -z "$settings_given" ]]; then
        XUI_MODE="update"
        info "A panel is installed here: updating it (the login, port and path are kept)."
    else
        XUI_MODE="install"
    fi
fi
[[ "$XUI_MODE" == "install" || "$XUI_MODE" == "update" ]] || die "XUI_MODE must be install or update, not '$XUI_MODE'."

# The panel runs as a systemd service; other init systems are not supported
# by this installer (and the release is a glibc build, so musl/Alpine cannot
# run it anyway).
[[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1 \
    || die "This installer needs systemd, and this host does not run it (Alpine/OpenRC is not supported)."

arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64) echo 'amd64' ;;
        aarch64|arm64)    echo 'arm64' ;;
        *) echo "Unsupported architecture: $(uname -m)" >&2; return 1 ;;
    esac
}
ARCH=$(arch) || exit 1

# Everything is checked before anything is touched.
if [[ "$XUI_MODE" == "install" ]]; then
    [[ -n "$XUI_USER" && -n "$XUI_PASS" && -n "$XUI_PATH" ]] \
        || die "The username, password and path must not be empty."
    [[ "$XUI_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$XUI_PORT >= 1 && 10#$XUI_PORT <= 65535 )) \
        || die "The port must be a number from 1 to 65535, not '$XUI_PORT'."
    XUI_PORT=$((10#$XUI_PORT))
else
    [[ -x "$xui_folder/x-ui" && -f "$db_folder/x-ui.db" ]] \
        || die "Nothing to update: no panel in $xui_folder with a database in $db_folder. Install it first."
fi

# ---- dependencies ----------------------------------------------------------
# Only what is missing is installed, so a box that has everything never
# touches its package manager. (On RHEL-family systems curl-minimal provides
# curl; asking for "curl" there conflicts and fails the whole transaction.)
install_base() {
    local pkgs=()
    command -v tar  >/dev/null 2>&1 || pkgs+=(tar)
    command -v gzip >/dev/null 2>&1 || pkgs+=(gzip)
    command -v curl >/dev/null 2>&1 || pkgs+=(curl)
    command -v ethtool >/dev/null 2>&1 || pkgs+=(ethtool)
    [[ -e /usr/share/zoneinfo/UTC ]] || pkgs+=(tzdata)
    [[ -s /etc/ssl/certs/ca-certificates.crt || -s /etc/pki/tls/certs/ca-bundle.crt || -s /etc/ssl/cert.pem ]] \
        || pkgs+=(ca-certificates)
    if (( ${#pkgs[@]} > 0 )); then
        info "Installing ${pkgs[*]}"
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
            apt-get update -qq >/dev/null
            apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q "${pkgs[@]}" >/dev/null
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q "${pkgs[@]}" >/dev/null
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm --needed "${pkgs[@]}" >/dev/null
        elif command -v zypper >/dev/null 2>&1; then
            zypper -n -q install "${pkgs[@]}" >/dev/null
        fi
    fi
    command -v tar >/dev/null 2>&1 && command -v gzip >/dev/null 2>&1 \
        || die "tar and gzip are required and could not be installed."
    if [[ -z "$XUI_LOCAL_TARBALL" ]]; then
        command -v curl >/dev/null 2>&1 || die "curl is required and could not be installed."
    fi
}

# ---- fetch -----------------------------------------------------------------
verify_tarball() {
    local dest="$1" expected="$2" actual entries
    [[ -s "$dest" ]] || return 1
    if [[ -n "$expected" ]]; then
        actual=$(sha256sum "$dest") || return 1
        [[ "${actual%% *}" == "$expected" ]] || return 1
    fi
    gzip -t "$dest" >/dev/null 2>&1 || return 1
    entries=$(tar -tzf "$dest" 2>/dev/null) || return 1
    [[ -n "$entries" ]]
}

download_tarball() {
    local url="$1" dest="$2" expected="$3" attempt offset status rc
    # A slow but progressing download has no total time limit. An idle/very
    # slow connection times out, then resumes the SAME tag and checksum.
    # Let curl validate Content-Range; never manually append response bodies.
    for ((attempt = 1; attempt <= 5; attempt++)); do
        offset=0
        [[ -f "$dest" ]] && offset=$(wc -c < "$dest")
        rc=0
        status=$(curl -4fL --connect-timeout 20 --speed-limit 1024 --speed-time 120 \
            --continue-at - --output "$dest" --write-out '%{http_code}' "$url") || rc=$?
        # Also accept a complete verified file after a late socket error or a
        # 416 response to a range starting at the already-complete file size.
        if verify_tarball "$dest" "$expected"; then
            return 0
        fi
        if [[ "$status" == 416 ]] || (( offset > 0 && (rc == 33 || rc == 36) )) || { (( offset > 0 )) && [[ "$status" == 200 ]]; }; then
            # A server ignoring Range (200), rejecting its offset (416), or
            # sending an inconsistent Content-Range cannot safely be resumed.
            rm -f "$dest" || die "Cannot discard an invalid partial download."
        elif (( rc == 0 )); then
            die "The downloaded release failed SHA256 or archive validation. The installed panel was not changed."
        elif (( rc == 23 )) || [[ "$status" == 4?? && "$status" != 408 && "$status" != 429 ]]; then
            die "Download failed (curl ${rc}, HTTP ${status}): $url"
        fi
        if (( attempt < 5 )); then
            offset=0
            [[ -f "$dest" ]] && offset=$(wc -c < "$dest")
            warn "Download interrupted; retry $((attempt + 1))/5 from ${offset} bytes."
            sleep "$attempt"
        fi
    done
    die "Download failed after 5 attempts: $url. The installed panel was not changed."
}

fetch_tarball() {
    local dest="$1"
    if [[ -n "$XUI_LOCAL_TARBALL" ]]; then
        [[ -f "$XUI_LOCAL_TARBALL" ]] || die "Local tarball not found: $XUI_LOCAL_TARBALL"
        info "Installing from local build: $XUI_LOCAL_TARBALL"
        cp -f "$XUI_LOCAL_TARBALL" "$dest" || die "Could not copy $XUI_LOCAL_TARBALL."
        verify_tarball "$dest" "" || die "The local release failed archive validation."
        return
    fi

    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify the release."
    local tag="$XUI_TAG" release tag_pattern='"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)"'
    if [[ -z "$tag" ]]; then
        # Consume and check the entire response: grep -m1 previously closed
        # curl's pipe early, producing error 23 on larger release metadata.
        release=$(curl -4fsSL --connect-timeout 15 --max-time 60 --retry 2 --retry-max-time 120 "https://api.github.com/repos/${XUI_REPO}/releases/latest") \
            || die "Could not determine the latest release of ${XUI_REPO}."
        [[ "$release" =~ $tag_pattern ]] || die "Could not determine the latest release of ${XUI_REPO}."
        tag="${BASH_REMATCH[1]}"
    fi
    local asset="x-ui-linux-${ARCH}.tar.gz" base="https://github.com/${XUI_REPO}/releases/download/${tag}" expected
    # Require the exact artifact's checksum from this selected release. Never
    # follow 'latest' again during retries or silently skip verification.
    curl -4fsSL --connect-timeout 15 --max-time 60 --retry 2 --retry-max-time 120 \
        --output "$dest.sha256" "$base/SHA256SUMS" || die "Could not fetch required SHA256SUMS for ${tag}. For an older release without checksums, use an independently verified local archive with XUI_LOCAL_TARBALL."
    expected=$(awk -v name="$asset" '
        $2 == name || $2 == "*" name {
            count++
            if (NF == 2 && length($1) == 64 && $1 ~ /^[[:xdigit:]]+$/) hash = tolower($1)
            else bad = 1
        }
        END { if (count == 1 && !bad) print hash; else exit 1 }
    ' "$dest.sha256") || die "SHA256SUMS must contain exactly one valid checksum for ${asset}."
    rm -f "$dest.sha256"
    info "Downloading ${tag} for ${ARCH}"
    download_tarball "$base/$asset" "$dest" "$expected"
}

# ---- install ---------------------------------------------------------------
# The new release is unpacked and checked next to the live panel (same
# filesystem, not /tmp) before anything is stopped. Only then is the panel
# stopped and the folders swapped; if the new panel does not come up, the
# previous one is put back and started again.
stage=""
cleanup() { [[ -n "$stage" && -d "$stage" ]] && rm -rf "$stage"; }
trap cleanup EXIT

stage_release() {
    mkdir -p /usr/local || die "Cannot create /usr/local."
    stage=$(mktemp -d /usr/local/.x-ui-stage.XXXXXX) || die "Cannot create a staging folder in /usr/local."
    fetch_tarball "$stage/x-ui.tar.gz"
    tar -xzf "$stage/x-ui.tar.gz" -C "$stage" || die "Could not unpack the release (is the disk full?)."
    rm -f "$stage/x-ui.tar.gz"

    local new="$stage/x-ui" f
    for f in x-ui "bin/xray-linux-${ARCH}" x-ui.sh x-ui.service.debian; do
        [[ -f "$new/$f" ]] || die "The release is incomplete: $f is missing."
    done
    chmod +x "$new/x-ui" "$new/x-ui.sh" "$new/bin/xray-linux-${ARCH}"
    "$new/x-ui" -v >/dev/null 2>&1 || die "The release's x-ui does not run on this machine."
    "$new/bin/xray-linux-${ARCH}" version >/dev/null 2>&1 || die "The release's Xray core does not run on this machine."

    # Geo files the panel or an admin added (custom geo, *_IR, *_RU) that
    # the release does not carry are kept.
    if [[ -d "$xui_folder/bin" ]]; then
        for f in "$xui_folder"/bin/*.dat; do
            [[ -f "$f" && ! -e "$new/bin/${f##*/}" ]] && { cp -a "$f" "$new/bin/" || die "Could not copy ${f##*/}."; }
        done
    fi
}

rollback() {
    warn "Putting the previous panel back..."
    systemctl stop x-ui >/dev/null 2>&1
    if [[ -d "$xui_folder.old" ]]; then
        rm -rf "$xui_folder" && mv "$xui_folder.old" "$xui_folder"
        [[ -f "$xui_folder/x-ui.sh" ]] && install -m 755 "$xui_folder/x-ui.sh" /usr/bin/x-ui
        [[ -f "$stage/x-ui.service.old" ]] && install -m 644 "$stage/x-ui.service.old" "$unit_file"
        systemctl daemon-reload
        systemctl start x-ui && warn "The previous panel is running again."
    fi
}

fail() { echo -e "${red}$*${plain}" >&2; rollback; exit 1; }

install_x_ui() {
    stage_release

    # The database lives in /etc/x-ui and is deliberately left alone here, so
    # reinstalling over an existing panel keeps its inbounds and users.
    mkdir -p "$db_folder" /var/log/x-ui || die "Cannot create $db_folder or /var/log/x-ui."
    [[ -f "$unit_file" ]] && cp -a "$unit_file" "$stage/x-ui.service.old"

    systemctl stop x-ui >/dev/null 2>&1
    rm -rf "$xui_folder.old"
    if [[ -e "$xui_folder" ]]; then
        mv "$xui_folder" "$xui_folder.old" || { systemctl start x-ui >/dev/null 2>&1; die "Could not move the current panel aside."; }
    fi
    mv "$stage/x-ui" "$xui_folder" || fail "Could not move the new panel into place."

    install -m 755 "$xui_folder/x-ui.sh" /usr/bin/x-ui || fail "Could not install /usr/bin/x-ui."
    install -m 644 "$xui_folder/x-ui.service.debian" "$unit_file" || fail "Could not install $unit_file."
}

# ---- configure -------------------------------------------------------------
configure() {
    if [[ -n "$XUI_DB_URL" ]]; then
        info "Seeding the database from ${XUI_DB_URL}"
        "$xui_folder/x-ui" "db=${XUI_DB_URL}" || fail "Database import failed."
    fi

    "$xui_folder/x-ui" migrate >/dev/null 2>&1 || fail "The database could not be opened or migrated."

    # An update must not reset the panel to the defaults; whoever is running it
    # is already logged in with credentials of their own.
    if [[ "$XUI_MODE" == "update" ]]; then
        info "Update: keeping the existing username, password, port and path."
        # A panel that never saved an xray template ran on its version's
        # built-in one: that is stored, so the new default does not change
        # its routing.
        "$xui_folder/x-ui" setting -keepXrayTemplate 2>&1 | grep -v '^$' | sed 's/^/  /'
        return
    fi

    local out
    out=$("$xui_folder/x-ui" setting -username "$XUI_USER" -password "$XUI_PASS" \
        -port "$XUI_PORT" -webBasePath "$XUI_PATH" 2>&1) \
        || fail "Could not apply the panel settings:\n$out"
}

# ---- server setup ----------------------------------------------------------
# BBR, the outgoing port range, network card rings and the CPU governor on
# every install and update; swap on a fresh install of a small machine.
# Never a reason for the install to fail.
HOST_RESULT="not run"
host_server() {
    info "Setting the server up (BBR, ports, network cards, CPU, swap)"
    local out
    out=$(/usr/bin/x-ui host-setup "$XUI_MODE" 2>&1)
    echo "$out" | sed 's/^/  /'
    HOST_RESULT=$(echo "$out" | paste -sd';' - | sed 's/;/; /g')
}

# The DNS cache, unless dns=off or "x-ui dns off" before.
DNS_RESULT="not run"
dns_server() {
    case "${XUI_DNS,,}" in
        off|no|0|false) DNS_RESULT="left as it is (dns=off)"; return ;;
    esac
    info "Setting up the DNS cache"
    if /usr/bin/x-ui dns auto 2>&1 | sed 's/^/  /'; then
        DNS_RESULT=$(/usr/bin/x-ui dns status 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g; s/^DNS cache: //')
    else
        warn "The DNS cache could not be set up; DNS is as it was. Retry with: x-ui dns on"
        DNS_RESULT="NOT set up (retry: x-ui dns on)"
    fi
}

# Anti-abuse, unless anti-abuse=off or "x-ui anti-abuse off" before.
ANTI_ABUSE_RESULT="not run"
anti_abuse_server() {
    case "${XUI_ANTI_ABUSE,,}" in
        off|no|0|false) ANTI_ABUSE_RESULT="left as it is (anti-abuse=off)"; return ;;
    esac
    info "Turning anti-abuse on"
    if /usr/bin/x-ui anti-abuse auto 2>&1 | sed 's/^/  /'; then
        if [[ -f /etc/x-ui/anti-abuse.off ]]; then
            ANTI_ABUSE_RESULT="off (turned off with 'x-ui anti-abuse off'; 'x-ui anti-abuse on' turns it on)"
        else
            ANTI_ABUSE_RESULT="on (details: x-ui anti-abuse status)"
        fi
    else
        warn "Anti-abuse is not fully on; the panel is installed anyway. Retry with: x-ui anti-abuse on"
        ANTI_ABUSE_RESULT="NOT fully on (retry: x-ui anti-abuse on)"
    fi
}

# ---- protection ------------------------------------------------------------
# On every install and update ("x-ui protect"): the core's direct connections
# never reach this server's loopback or private networks, and speed-test
# servers (iperf3) stay stopped. Before the panel starts: the guard is in
# place before the core's first connection.
PROTECT_RESULT="not run"
protect_server() {
    info "Protecting the server (direct guard, speed-test servers)"
    if /usr/bin/x-ui protect auto 2>&1 | sed 's/^/  /'; then
        if [[ -f /etc/x-ui/protect.off ]]; then
            PROTECT_RESULT="off (turned off with 'x-ui protect off'; 'x-ui protect on' turns it on)"
        else
            PROTECT_RESULT="on (details: x-ui protect status)"
        fi
    else
        warn "The direct guard could not be set up; the panel is installed anyway. Retry with: x-ui protect"
        PROTECT_RESULT="NOT on (retry: x-ui protect)"
    fi
}

start_x_ui() {
    systemctl daemon-reload
    systemctl enable x-ui >/dev/null 2>&1
    systemctl restart x-ui || fail "x-ui did not start."
    # A panel that crashes on start shows as "activating" (restarting) or
    # "failed" a few seconds later.
    local _
    for _ in 1 2 3 4 5 6; do
        sleep 1
        systemctl is-active --quiet x-ui || break
    done
    systemctl is-active --quiet x-ui || fail "x-ui did not stay up. See: journalctl -u x-ui -n 50"
    rm -rf "$xui_folder.old"
}

server_ip() {
    local ip
    for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me; do
        ip=$(curl -4fsSL --max-time 5 "$u" 2>/dev/null) && [[ -n "$ip" ]] && { echo "$ip"; return; }
    done
    hostname -I 2>/dev/null | awk '{print $1}'
}

# nftables for the direct guard, installed now: the guard is set up while the
# panel is stopped, and that must not wait for the package manager. Best
# effort; protect reports it if nft is still missing.
install_nft() {
    command -v nft >/dev/null 2>&1 && return 0
    info "Installing nftables"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -qq --no-install-recommends nftables >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q nftables >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q nftables >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm --needed nftables >/dev/null 2>&1
    elif command -v zypper >/dev/null 2>&1; then
        zypper -n -q install nftables >/dev/null 2>&1
    fi
    return 0
}

install_base
install_nft
install_x_ui
configure
protect_server
start_x_ui
# After the panel is up: these may install packages, and an update should
# not keep the panel down meanwhile. The core picks up the DNS cache by
# itself (it reads /etc/resolv.conf again when it changes).
host_server
dns_server
anti_abuse_server

IP=$(server_ip)
echo
if [[ "$XUI_MODE" == "update" ]]; then
    info "x-ui (dialect build) updated to $("$xui_folder/x-ui" -v 2>/dev/null)."
    echo "  The panel's username, password, port and path are unchanged."
else
    info "x-ui (dialect build) installed."
    echo -e "  URL:      ${green}http://${IP}:${XUI_PORT}/${XUI_PATH}${plain}"
    echo -e "  Username: ${green}${XUI_USER}${plain}"
    echo -e "  Password: ${green}${XUI_PASS}${plain}"
fi
echo
echo "  Core:     bundled dialect fork, not switchable"
echo "  Database: ${db_folder}/x-ui.db"
echo "  Protect:  ${PROTECT_RESULT}"
echo "  Anti-abuse: ${ANTI_ABUSE_RESULT}"
echo "  DNS:      ${DNS_RESULT}"
echo "  Server:   ${HOST_RESULT}"
echo "  Replace the database later with: x-ui db=\"https://host/x-ui.db\""
echo
systemctl --no-pager status x-ui | head -5
