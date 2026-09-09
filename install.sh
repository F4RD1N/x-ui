#!/bin/bash
# Non-interactive installer for the x-ui dialect panel.
#
# It asks nothing. Everything has a fixed default, and anything that needs to
# differ is passed as an argument or an environment variable:
#
#   bash install.sh                          install with the defaults below
#   bash install.sh db=https://host/x-ui.db  install, then seed the database
#   XUI_PORT=61000 bash install.sh           override a default
#
# There is no SSL step: this panel is served over plain HTTP by design.
# There is no core selection either -- the panel ships exactly one Xray core,
# the dialect fork, and cannot switch or update it.

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

xui_folder="/usr/local/x-ui"
db_folder="/etc/x-ui"

# ---- arguments -------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        db=*)      XUI_DB_URL="${arg#db=}" ;;
        port=*)    XUI_PORT="${arg#port=}" ;;
        user=*)    XUI_USER="${arg#user=}" ;;
        pass=*)    XUI_PASS="${arg#pass=}" ;;
        path=*)    XUI_PATH="${arg#path=}" ;;
        tag=*)     XUI_TAG="${arg#tag=}" ;;
        *)         echo -e "${yellow}Ignoring unknown argument: $arg${plain}" ;;
    esac
done

die() { echo -e "${red}$*${plain}"; exit 1; }
info() { echo -e "${green}$*${plain}"; }

[[ $EUID -ne 0 ]] && die "This installer must run as root."

arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64) echo 'amd64' ;;
        aarch64|arm64)    echo 'arm64' ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
}
ARCH=$(arch)

# ---- dependencies ----------------------------------------------------------
install_base() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq wget curl tar tzdata ca-certificates >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q wget curl tar tzdata ca-certificates >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q wget curl tar tzdata ca-certificates >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache wget curl tar tzdata ca-certificates >/dev/null
    fi
}

# ---- fetch -----------------------------------------------------------------
fetch_tarball() {
    local dest="$1"
    if [[ -n "$XUI_LOCAL_TARBALL" ]]; then
        [[ -f "$XUI_LOCAL_TARBALL" ]] || die "Local tarball not found: $XUI_LOCAL_TARBALL"
        info "Installing from local build: $XUI_LOCAL_TARBALL"
        cp -f "$XUI_LOCAL_TARBALL" "$dest"
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
install_x_ui() {
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    fetch_tarball "$tmp/x-ui.tar.gz"

    systemctl stop x-ui >/dev/null 2>&1

    # The database lives in /etc/x-ui and is deliberately left alone here, so
    # reinstalling over an existing panel keeps its inbounds and users.
    rm -rf "$xui_folder"
    mkdir -p "$xui_folder" "$db_folder" /var/log/x-ui

    tar -xzf "$tmp/x-ui.tar.gz" -C "$tmp" || die "Could not unpack the release."
    cp -a "$tmp/x-ui/." "$xui_folder/"

    chmod +x "$xui_folder/x-ui" "$xui_folder/bin/xray-linux-${ARCH}"
    [[ -f "$xui_folder/x-ui.sh" ]] && install -m 755 "$xui_folder/x-ui.sh" /usr/bin/x-ui

    install -m 644 "$xui_folder/x-ui.service.debian" /etc/systemd/system/x-ui.service \
        2>/dev/null || die "Release is missing its service unit."
}

# ---- configure -------------------------------------------------------------
configure() {
    if [[ -n "$XUI_DB_URL" ]]; then
        info "Seeding the database from ${XUI_DB_URL}"
        "$xui_folder/x-ui" "db=${XUI_DB_URL}" || die "Database import failed."
    fi

    "$xui_folder/x-ui" migrate >/dev/null 2>&1

    "$xui_folder/x-ui" setting -username "$XUI_USER" -password "$XUI_PASS" \
        -port "$XUI_PORT" -webBasePath "$XUI_PATH" >/dev/null \
        || die "Could not apply the panel settings."
}

start_x_ui() {
    systemctl daemon-reload
    systemctl enable x-ui >/dev/null 2>&1
    systemctl restart x-ui
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
start_x_ui

IP=$(server_ip)
echo
info "x-ui (dialect build) installed."
echo -e "  URL:      ${green}http://${IP}:${XUI_PORT}/${XUI_PATH}${plain}"
echo -e "  Username: ${green}${XUI_USER}${plain}"
echo -e "  Password: ${green}${XUI_PASS}${plain}"
echo
echo "  Core:     bundled dialect fork, not switchable"
echo "  Database: ${db_folder}/x-ui.db"
echo "  Replace the database later with: x-ui db=\"https://host/x-ui.db\""
echo
systemctl --no-pager status x-ui | head -5
