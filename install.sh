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
#   bash install.sh tune=off                 skip the server tuning this time
#
# There is no SSL step: this panel is served over plain HTTP by design.
# There is no core selection either -- the panel ships exactly one Xray core,
# the dialect fork, and cannot switch or update it.
#
# The server is tuned for x-ui on every install and update ("x-ui tune": open
# file limits, kernel network limits, BBR). A fresh install also sets up time
# sync, irqbalance and swap on tiny VMs; an update leaves those alone. It
# only raises limits, never lowers one set elsewhere, and "x-ui tune revert"
# undoes it and keeps it off for later updates.

set -uo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'

# ---- fixed defaults --------------------------------------------------------
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
# A fresh install applies the defaults above.
XUI_MODE="${XUI_MODE:-install}"
XUI_TUNE="${XUI_TUNE:-on}"                 # off: skip "x-ui tune apply"

xui_folder="/usr/local/x-ui"
db_folder="/etc/x-ui"
unit_file="/etc/systemd/system/x-ui.service"
tune_dropin="/etc/systemd/system/x-ui.service.d/20-x-ui-tuning.conf"

# ---- arguments -------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        db=*)      XUI_DB_URL="${arg#db=}" ;;
        port=*)    XUI_PORT="${arg#port=}" ;;
        user=*)    XUI_USER="${arg#user=}" ;;
        pass=*)    XUI_PASS="${arg#pass=}" ;;
        path=*)    XUI_PATH="${arg#path=}" ;;
        tag=*)     XUI_TAG="${arg#tag=}" ;;
        tune=*)    XUI_TUNE="${arg#tune=}" ;;
        update)    XUI_MODE="update" ;;
        *)         echo -e "${yellow}Ignoring unknown argument: $arg${plain}" ;;
    esac
done

die() { echo -e "${red}$*${plain}" >&2; exit 1; }
info() { echo -e "${green}$*${plain}"; }
warn() { echo -e "${yellow}$*${plain}"; }

[[ $EUID -ne 0 ]] && die "This installer must run as root."
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

# A run that was killed half-way may have left the previous panel moved
# aside: put it back first.
if [[ ! -e "$xui_folder" && -d "$xui_folder.old" ]]; then
    mv "$xui_folder.old" "$xui_folder" && warn "Restored $xui_folder from an interrupted install."
fi
rm -rf /usr/local/.x-ui-stage.*

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
fetch_tarball() {
    local dest="$1"
    if [[ -n "$XUI_LOCAL_TARBALL" ]]; then
        [[ -f "$XUI_LOCAL_TARBALL" ]] || die "Local tarball not found: $XUI_LOCAL_TARBALL"
        info "Installing from local build: $XUI_LOCAL_TARBALL"
        cp -f "$XUI_LOCAL_TARBALL" "$dest" || die "Could not copy $XUI_LOCAL_TARBALL."
        return
    fi

    local tag="$XUI_TAG"
    if [[ -z "$tag" ]]; then
        tag=$(curl -4fsSL "https://api.github.com/repos/${XUI_REPO}/releases/latest" \
              | grep -m1 '"tag_name"' | cut -d '"' -f 4)
        [[ -z "$tag" ]] && die "Could not determine the latest release of ${XUI_REPO}."
    fi
    local url="https://github.com/${XUI_REPO}/releases/download/${tag}/x-ui-linux-${ARCH}.tar.gz"
    info "Downloading ${tag} for ${ARCH}"
    curl -4fL --retry 3 -o "$dest" "$url" || die "Download failed: $url"
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
        # The service settings tuning wrote this run go back too.
        if [[ -f "$stage/dropin.old" ]]; then
            install -m 644 "$stage/dropin.old" "$tune_dropin"
        elif [[ -f "$stage/dropin.none" ]]; then
            rm -f "$tune_dropin"
        fi
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
        return
    fi

    local out
    out=$("$xui_folder/x-ui" setting -username "$XUI_USER" -password "$XUI_PASS" \
        -port "$XUI_PORT" -webBasePath "$XUI_PATH" 2>&1) \
        || fail "Could not apply the panel settings:\n$out"
}

# ---- tune ------------------------------------------------------------------
TUNE_RESULT="not run"
tune_server() {
    case "${XUI_TUNE,,}" in
        off|no|0|false) TUNE_RESULT="skipped (tune=off)"; return ;;
    esac
    info "Tuning the server for x-ui"
    if [[ -f "$tune_dropin" ]]; then
        cp -a "$tune_dropin" "$stage/dropin.old"
    else
        : > "$stage/dropin.none"
    fi
    # Host services (time sync, irqbalance, swap) only on a fresh install: an
    # update leaves the machine's services as its admin set them up.
    local args=(apply --auto)
    [[ "$XUI_MODE" == "install" ]] && args+=(--host)
    if "$xui_folder/x-ui" tune "${args[@]}" 2>&1 | sed 's/^/  /'; then
        if grep -q '"disabled": true' /var/lib/x-ui/tune/state.json 2>/dev/null; then
            TUNE_RESULT="off (turned off by 'x-ui tune revert'; 'x-ui tune apply' turns it on)"
        else
            TUNE_RESULT="applied (details: x-ui tune status)"
        fi
    else
        warn "Server tuning failed; the panel is installed anyway. Retry with: x-ui tune apply"
        TUNE_RESULT="failed (retry: x-ui tune apply)"
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

install_base
install_x_ui
configure
tune_server
start_x_ui

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
echo "  Tuning:   ${TUNE_RESULT}"
echo "  Replace the database later with: x-ui db=\"https://host/x-ui.db\""
echo
systemctl --no-pager status x-ui | head -5
