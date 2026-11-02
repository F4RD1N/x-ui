#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

#Add some basic function here
function LOGD() {
    echo -e "${yellow}[DEG] $* ${plain}"
}

function LOGE() {
    echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
    echo -e "${green}[INF] $* ${plain}"
}

function LOGW() {
    echo -e "${yellow}[WRN] $* ${plain}"
}

# Port helpers: detect listener and owning process (best effort)
is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk -v p=":${port} " '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:${port} -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

# Simple helpers for domain/IP validation
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]] && return 0 || return 1
}

# check root
[[ $EUID -ne 0 ]] && LOGE "ERROR: You must be root to run this script! \n" && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
# Only the menu says it: subcommands print just their own output.
[[ $# -eq 0 ]] && echo "The OS release is: $release"

os_version=""
os_version=$(grep "^VERSION_ID" /etc/os-release | cut -d '=' -f2 | tr -d '"' | tr -d '.')

# Declare Variables
xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"
log_folder="${XUI_LOG_FOLDER:=/var/log/x-ui}"
mkdir -p "${log_folder}"
iplimit_log_path="${log_folder}/3xipl.log"
iplimit_banned_log_path="${log_folder}/3xipl-banned.log"

confirm() {
    if [[ $# -gt 1 ]]; then
        echo && read -rp "$1 [Default $2]: " temp
        if [[ "${temp}" == "" ]]; then
            temp=$2
        fi
    else
        read -rp "$1 [y/n]: " temp
    fi
    if [[ "${temp}" == "y" || "${temp}" == "Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "Restart the panel, Attention: Restarting the panel will also restart xray" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press enter to return to the main menu: ${plain}" && read -r temp
    show_menu
}

# run_installer downloads the fork's install.sh and runs it with the given
# arguments. The script is saved first: piping a failed download into bash
# would run an error page, or nothing at all and report success.
run_installer() {
    local script rc
    script=$(mktemp) || return 1
    if ! curl -4fsSL -o "$script" https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh; then
        rm -f "$script"
        LOGE "Could not download install.sh from GitHub."
        return 1
    fi
    bash "$script" "$@"
    rc=$?
    rm -f "$script"
    return $rc
}

install() {
    if run_installer; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    local current latest
    current=$(${xui_folder}/x-ui -v 2>/dev/null)
    latest=$(curl -4fsSL --max-time 10 https://api.github.com/repos/F4RD1N/x-ui/releases/latest 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d '"' -f 4)
    echo -e "Installed: ${green}${current:-unknown}${plain}   latest release: ${green}${latest:-unknown}${plain}"
    if [[ -n "$latest" && "${latest#v}" == "${current#v}" ]]; then
        # The same version string can still be a different build (a branch
        # build installed by hand): reinstalling would replace it.
        LOGI "This is already the latest release."
        confirm "Reinstall the release build anyway? The login, port, path and data are kept." "n"
    else
        confirm "Update x-ui to the latest release? The login, port, path and data are kept." "y"
    fi
    if [[ $? != 0 ]]; then
        LOGE "Cancelled"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi
    # Update mode keeps the username, password, port and path; the install
    # mode would reset them to the defaults.
    if XUI_MODE=update run_installer update; then
        LOGI "Update is complete, Panel has automatically restarted "
    else
        LOGE "The update failed; see the messages above."
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

# fetch_menu_script replaces /usr/bin/x-ui with the latest x-ui.sh. It is
# downloaded beside it, checked, and moved over it: writing into the file
# bash is running from would corrupt this very run, and a dropped download
# would leave a broken menu.
fetch_menu_script() {
    local tmp=/usr/bin/x-ui.new
    if ! curl -4fsSL -o "$tmp" https://raw.githubusercontent.com/F4RD1N/x-ui/main/x-ui.sh || ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    chmod +x "$tmp" && mv -f "$tmp" /usr/bin/x-ui
}

update_menu() {
    echo -e "${yellow}Updating Menu${plain}"
    confirm "This function will update the menu to the latest changes." "y"
    if [[ $? != 0 ]]; then
        LOGE "Cancelled"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi

    if fetch_menu_script; then
        echo -e "${green}The menu is updated. Run x-ui again to use it.${plain}"
        exit 0
    else
        echo -e "${red}Failed to update the menu.${plain}"
        return 1
    fi
}

legacy_version() {
    echo -e "${red}Installing another panel version is not supported by this build.${plain}"
    echo -e "${yellow}This panel ships one Xray core, the dialect fork. An upstream${plain}"
    echo -e "${yellow}release would bring a stock core and every dialect inbound would${plain}"
    echo -e "${yellow}stop accepting its clients.${plain}"
}

# Function to handle the deletion of the script file
delete_script() {
    rm "$0" # Remove the script file itself
    exit 1
}

uninstall() {
    confirm "Are you sure you want to uninstall the panel? xray will also uninstalled!" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi

    # Undo what install set up on the server: the DNS cache, anti-abuse
    # (and, once the panel and its core are stopped, BBR's sysctl file and
    # the swapfile).
    dns_off keep
    if [[ -f $anti_abuse_unit || -f $anti_abuse_jail || -f $anti_abuse_jail_old ]]; then
        anti_abuse_off keep
    fi

    if [[ $release == "alpine" ]]; then
        rc-service x-ui stop
        rc-update del x-ui
        rm /etc/init.d/x-ui -f
    else
        systemctl stop x-ui
        systemctl disable x-ui
        rm ${xui_service}/x-ui.service -f
        rmdir ${xui_service}/x-ui.service.d 2>/dev/null
        systemctl daemon-reload
        systemctl reset-failed
    fi
    # Only now that the cores are gone: until then the guard is still needed.
    if [[ -f $protect_unit ]]; then
        protect_off keep
    fi
    host_revert

    rm /etc/x-ui/ -rf
    rm ${xui_folder}/ -rf

    echo ""
    echo -e "Uninstalled Successfully.\n"
    echo "If you need to install this panel again, you can use below command:"
    echo -e "${green}bash <(curl -Ls https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh)${plain}"
    echo ""
    # Trap the SIGTERM signal
    trap delete_script SIGTERM
    delete_script
}

reset_user() {
    confirm "Are you sure to reset the username and password of the panel?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    
    read -rp "Please set the login username [default is a random username]: " config_account
    [[ -z $config_account ]] && config_account=$(gen_random_string 10)
    read -rp "Please set the login password [default is a random password]: " config_password
    [[ -z $config_password ]] && config_password=$(gen_random_string 18)

    read -rp "Do you want to disable currently configured two-factor authentication? (y/n): " twoFactorConfirm
    if [[ $twoFactorConfirm != "y" && $twoFactorConfirm != "Y" ]]; then
        ${xui_folder}/x-ui setting -username "${config_account}" -password "${config_password}" -resetTwoFactor false >/dev/null 2>&1
    else
        ${xui_folder}/x-ui setting -username "${config_account}" -password "${config_password}" -resetTwoFactor true >/dev/null 2>&1
        echo -e "Two factor authentication has been disabled."
    fi
    
    echo -e "Panel login username has been reset to: ${green} ${config_account} ${plain}"
    echo -e "Panel login password has been reset to: ${green} ${config_password} ${plain}"
    echo -e "${green} Please use the new login username and password to access the X-UI panel. Also remember them! ${plain}"
    confirm_restart
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $(( length * 2 )) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

reset_webbasepath() {
    echo -e "${yellow}Resetting Web Base Path${plain}"

    read -rp "Are you sure you want to reset the web base path? (y/n): " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo -e "${yellow}Operation canceled.${plain}"
        return
    fi

    config_webBasePath=$(gen_random_string 18)

    # Apply the new web base path setting
    ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}" >/dev/null 2>&1

    echo -e "Web base path has been reset to: ${green}${config_webBasePath}${plain}"
    echo -e "${green}Please use the new web base path to access the panel.${plain}"
    restart
}

reset_config() {
    confirm "Are you sure you want to reset all panel settings, Account data will not be lost, Username and password will not change" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    ${xui_folder}/x-ui setting -reset
    echo -e "All panel settings have been reset to default."
    restart
}

check_config() {
    local info=$(${xui_folder}/x-ui setting -show true)
    if [[ $? != 0 ]]; then
        LOGE "get current settings error, please check logs"
        show_menu
        return
    fi
    LOGI "${info}"

    local existing_webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    local server_ip=$(curl -s --max-time 3 https://api.ipify.org)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s --max-time 3 https://4.ident.me)
    fi

    if [[ -n "$existing_cert" ]]; then
        local domain=$(basename "$(dirname "$existing_cert")")

        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${green}Access URL: https://${domain}:${existing_port}${existing_webBasePath}${plain}"
        else
            echo -e "${green}Access URL: https://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
        fi
    else
        echo -e "${green}Access URL: http://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
    fi
}

set_port() {
    echo -n "Enter port number[1-65535]: "
    read -r port
    if [[ -z "${port}" ]]; then
        LOGD "Cancelled"
        before_show_menu
    elif ${xui_folder}/x-ui setting -port ${port}; then
        # the direct guard keeps the VPN off the panel's new port
        [[ -f $protect_unit ]] && protect_on >/dev/null 2>&1
        echo -e "The port is set, Please restart the panel now, and use the new port ${green}${port}${plain} to access web panel"
        confirm_restart
    else
        LOGE "The port was not changed."
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        LOGI "Panel is running, No need to start again, If you need to restart, please select restart"
    else
        if [[ $release == "alpine" ]]; then
            rc-service x-ui start
        else
            systemctl start x-ui
        fi
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            LOGI "x-ui Started Successfully"
        else
            LOGE "panel Failed to start, Probably because it takes longer than two seconds to start, Please check the log information later"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    check_status
    if [[ $? == 1 ]]; then
        echo ""
        LOGI "Panel stopped, No need to stop again!"
    else
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        sleep 2
        check_status
        if [[ $? == 1 ]]; then
            LOGI "x-ui and xray stopped successfully"
        else
            LOGE "Panel stop failed, Probably because the stop time exceeds two seconds, Please check the log information later"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    if [[ $release == "alpine" ]]; then
        rc-service x-ui restart
    else
        systemctl restart x-ui
    fi
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        LOGI "x-ui and xray Restarted successfully"
    else
        LOGE "Panel restart failed, Probably because it takes longer than two seconds to start, Please check the log information later"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart_xray() {
    systemctl reload x-ui
    LOGI "xray-core Restart signal sent successfully, Please check the log information to confirm whether xray restarted successfully"
    sleep 2
    show_xray_status
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    if [[ $release == "alpine" ]]; then
        rc-service x-ui status
    else
        systemctl status x-ui -l
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    if [[ $release == "alpine" ]]; then
        rc-update add x-ui default
    else
        systemctl enable x-ui
    fi
    if [[ $? == 0 ]]; then
        LOGI "x-ui Set to boot automatically on startup successfully"
    else
        LOGE "x-ui Failed to set Autostart"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    if [[ $release == "alpine" ]]; then
        rc-update del x-ui
    else
        systemctl disable x-ui
    fi
    if [[ $? == 0 ]]; then
        LOGI "x-ui Autostart Cancelled successfully"
    else
        LOGE "x-ui Failed to cancel autostart"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    if [[ $release == "alpine" ]]; then
        echo -e "${green}\t1.${plain} Debug Log"
        echo -e "${green}\t0.${plain} Back to Main Menu"
        read -rp "Choose an option: " choice

        case "$choice" in
        0)
            show_menu
            ;;
        1)
            grep -F 'x-ui[' /var/log/messages
            if [[ $# == 0 ]]; then
                before_show_menu
            fi
            ;;
        *)
            echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
            show_log
            ;;
        esac
    else
        echo -e "${green}\t1.${plain} Debug Log"
        echo -e "${green}\t2.${plain} Clear All logs"
        echo -e "${green}\t0.${plain} Back to Main Menu"
        read -rp "Choose an option: " choice

        case "$choice" in
        0)
            show_menu
            ;;
        1)
            journalctl -u x-ui -e --no-pager -f -p debug
            if [[ $# == 0 ]]; then
                before_show_menu
            fi
            ;;
        2)
            sudo journalctl --rotate
            sudo journalctl --vacuum-time=1s
            echo "All Logs cleared."
            restart
            ;;
        *)
            echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
            show_log
            ;;
        esac
    fi
}

bbr_menu() {
    echo -e "${green}\t1.${plain} Enable BBR"
    echo -e "${green}\t2.${plain} Disable BBR"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        enable_bbr
        bbr_menu
        ;;
    2)
        disable_bbr
        bbr_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        bbr_menu
        ;;
    esac
}
disable_bbr() {

    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) != "bbr" ]] || [[ ! $(sysctl -n net.core.default_qdisc) =~ ^(fq|cake)$ ]]; then
        echo -e "${yellow}BBR is not currently enabled.${plain}"
        before_show_menu
    fi

    # Installs and updates leave BBR off from now on.
    mkdir -p "$(dirname "$host_bbr_off")" && : >"$host_bbr_off"
    if grep -qs '^net.ipv4.tcp_congestion_control' "$host_sysctl"; then
        # Set by the installer (host_bbr): back to what it was before.
        old_settings=$(sed -n 's/^# before x-ui: //p' "$host_sysctl" | head -1)
        [[ -n $old_settings ]] || old_settings="fq_codel:cubic"
        sed -i '/^net.core.default_qdisc/d; /^net.ipv4.tcp_congestion_control/d; /^# before x-ui:/d' "$host_sysctl"
        sysctl -w net.core.default_qdisc="${old_settings%:*}" >/dev/null 2>&1
        sysctl -w net.ipv4.tcp_congestion_control="${old_settings#*:}"
    fi
    if [ -f "/etc/sysctl.d/99-bbr-x-ui.conf" ]; then
        old_settings=$(head -1 /etc/sysctl.d/99-bbr-x-ui.conf | tr -d '#')
        sysctl -w net.core.default_qdisc="${old_settings%:*}"
        sysctl -w net.ipv4.tcp_congestion_control="${old_settings#*:}"
        rm /etc/sysctl.d/99-bbr-x-ui.conf
        sysctl --system
    else
        # Replace BBR with CUBIC configurations
        if [ -f "/etc/sysctl.conf" ]; then
            sed -i 's/net.core.default_qdisc=fq/net.core.default_qdisc=pfifo_fast/' /etc/sysctl.conf
            sed -i 's/net.ipv4.tcp_congestion_control=bbr/net.ipv4.tcp_congestion_control=cubic/' /etc/sysctl.conf
            sysctl -p
        fi
    fi

    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) != "bbr" ]]; then
        echo -e "${green}BBR has been replaced with CUBIC successfully.${plain}"
    else
        echo -e "${red}Failed to replace BBR with CUBIC. Please check your system configuration.${plain}"
    fi
}
enable_bbr() {
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "bbr" ]] && [[ $(sysctl -n net.core.default_qdisc) =~ ^(fq|cake)$ ]]; then
        echo -e "${green}BBR is already enabled!${plain}"
        before_show_menu
    fi

    rm -f "$host_bbr_off"
    # Enable BBR
    if [ -d "/etc/sysctl.d/" ]; then
        {
            echo "#$(sysctl -n net.core.default_qdisc):$(sysctl -n net.ipv4.tcp_congestion_control)"
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        } > "/etc/sysctl.d/99-bbr-x-ui.conf"
        if [ -f "/etc/sysctl.conf" ]; then
            # Backup old settings from sysctl.conf, if any
            sed -i 's/^net.core.default_qdisc/# &/'          /etc/sysctl.conf
            sed -i 's/^net.ipv4.tcp_congestion_control/# &/' /etc/sysctl.conf
        fi
        sysctl --system
    else
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf
        sysctl -p
    fi

    # Verify that BBR is enabled
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "bbr" ]]; then
        echo -e "${green}BBR has been enabled successfully.${plain}"
    else
        echo -e "${red}Failed to enable BBR. Please check your system configuration.${plain}"
    fi
}

# Server setup run by every install ("x-ui host-setup install|update", from
# install.sh): BBR with fq, unless the admin chose another congestion
# control; on a fresh install of a small machine (2 GiB of RAM or less) with
# no swap, a 1 GiB swapfile. Uninstall takes both away again.
host_sysctl="/etc/sysctl.d/60-x-ui.conf"
host_swapfile="/swapfile"
host_fstab_tag="# x-ui swapfile"

# host_container says whether this runs in a container, where the host's
# kernel settings and swap belong to the host.
host_container() {
    systemd-detect-virt --container --quiet 2>/dev/null
}

# host_sysctl_set KEY VALUE writes KEY into x-ui's sysctl file and applies it.
host_sysctl_set() {
    local key=$1 value=$2
    [[ -f $host_sysctl ]] || printf '# Written by x-ui (install and update); uninstall removes it.\n' >"$host_sysctl"
    sed -i "/^${key//./\\.}[[:space:]]*=/d" "$host_sysctl"
    echo "${key} = ${value}" >>"$host_sysctl"
    sysctl -q -w "${key}=${value}" >/dev/null 2>&1
}

# host_sysctl_admin KEY says whether a sysctl file other than x-ui's sets
# KEY: then it is the admin's (or the menu's "Enable BBR") choice.
host_sysctl_admin() {
    local key=${1//./\\.} f
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do
        [[ -f $f && $f != "$host_sysctl" ]] || continue
        grep -qsE "^[[:space:]]*${key}[[:space:]]*=" "$f" && return 0
    done
    return 1
}

# host_bbr turns on BBR with fq where the congestion control is still the
# kernel's default (cubic or reno) and no sysctl file chose it; the menu's
# "Disable BBR" turns it off for good (host_bbr_off).
host_bbr_off="/etc/x-ui/bbr.off"
host_bbr() {
    local cc qdisc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ -f $host_bbr_off ]]; then
        echo "BBR: kept off (turned off in the menu; Enable BBR turns it on)"
        return 0
    fi
    if host_sysctl_admin net.ipv4.tcp_congestion_control; then
        echo "BBR: kept ${cc:-as it is} (chosen in this server's sysctl files)"
        return 0
    fi
    case "$cc" in
    bbr)
        # on, but maybe only until the next boot (x-ui was uninstalled and
        # installed again): written down here.
        grep -qs '^net.ipv4.tcp_congestion_control = bbr' "$host_sysctl" ||
            host_sysctl_set net.ipv4.tcp_congestion_control bbr
        echo "BBR: already on"
        return 0
        ;;
    cubic | reno) ;;
    "") echo "BBR: no congestion control setting here, left alone"; return 0 ;;
    *) echo "BBR: kept ${cc} (chosen on this server)"; return 0 ;;
    esac
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        modprobe tcp_bbr >/dev/null 2>&1
        if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo "BBR: this kernel has no BBR, kept ${cc}"
            return 0
        fi
    fi
    # What it was, for "Disable BBR".
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if ! grep -qs '^# before x-ui:' "$host_sysctl"; then
        [[ -f $host_sysctl ]] || printf '# Written by x-ui (install and update); uninstall removes it.\n' >"$host_sysctl"
        echo "# before x-ui: ${qdisc:-fq_codel}:${cc}" >>"$host_sysctl"
    fi
    # fq paces BBR's packets; a container cannot set the host's qdisc, and
    # one an admin chose stays.
    if [[ -w /proc/sys/net/core/default_qdisc ]] && ! host_sysctl_admin net.core.default_qdisc; then
        host_sysctl_set net.core.default_qdisc fq
    fi
    host_sysctl_set net.ipv4.tcp_congestion_control bbr
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) == bbr ]]; then
        echo "BBR: on (was ${cc})"
    else
        echo "BBR: could not be turned on here, kept ${cc}"
    fi
}

# host_swap adds a 1 GiB swapfile to a small machine that has no swap, so a
# burst of connections does not get the panel or its core killed for memory.
host_swap() {
    local mem_kb free_kb fstype
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q .; then
        echo "Swap: already there"
        return 0
    fi
    mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
    if [[ -z $mem_kb || $mem_kb -gt 2306867 ]]; then
        echo "Swap: not needed ($((${mem_kb:-0} / 1024)) MiB of RAM)"
        return 0
    fi
    free_kb=$(df -Pk / | awk 'NR == 2 { print $4 }')
    fstype=$(findmnt -no FSTYPE / 2>/dev/null)
    if [[ -e $host_swapfile || ${free_kb:-0} -lt 3145728 || $fstype == btrfs || $fstype == zfs ]]; then
        echo "Swap: none added (${host_swapfile} exists, under 3 GiB free, or ${fstype:-unknown} filesystem)"
        return 0
    fi
    if ! { fallocate -l 1G "$host_swapfile" 2>/dev/null || dd if=/dev/zero of="$host_swapfile" bs=1M count=1024 status=none 2>/dev/null; }; then
        rm -f "$host_swapfile"
        echo "Swap: could not create ${host_swapfile}"
        return 1
    fi
    chmod 600 "$host_swapfile"
    if ! mkswap "$host_swapfile" >/dev/null 2>&1 || ! swapon "$host_swapfile" 2>/dev/null; then
        rm -f "$host_swapfile"
        echo "Swap: could not turn on ${host_swapfile}"
        return 1
    fi
    if ! grep -q "^${host_swapfile}[[:space:]]" /etc/fstab 2>/dev/null; then
        # a last line without its newline would swallow this one
        [[ -s /etc/fstab && -n $(tail -c1 /etc/fstab) ]] && echo >>/etc/fstab
        echo "${host_swapfile} none swap sw 0 0 ${host_fstab_tag}" >>/etc/fstab
    fi
    # Swap only when memory is really short: the core's latency comes first.
    host_sysctl_set vm.swappiness 10
    echo "Swap: 1 GiB at ${host_swapfile} ($((mem_kb / 1024)) MiB of RAM)"
}

# host_setup runs the server setup: "install" (BBR and swap) or "update"
# (BBR only; swap is a fresh install's).
host_setup() {
    # (XUI_HOST_SETUP_IN_CONTAINER=1: the tests run it in a container.)
    if host_container && [[ ${XUI_HOST_SETUP_IN_CONTAINER:-} != 1 ]]; then
        echo "Server setup: skipped in a container (its kernel and swap are the host's)"
        return 0
    fi
    host_bbr
    [[ ${1:-} == install ]] && host_swap
    return 0
}

# host_revert takes x-ui's server setup away: its sysctl file and the
# swapfile it added. The kernel keeps the running values until a reboot.
host_revert() {
    rm -f "$host_sysctl" "$host_bbr_off"
    local line="^${host_swapfile}[[:space:]].*${host_fstab_tag}\$"
    if grep -q "$line" /etc/fstab 2>/dev/null; then
        swapoff "$host_swapfile" 2>/dev/null
        if awk 'NR > 1 { print $1 }' /proc/swaps 2>/dev/null | grep -qxF "$host_swapfile"; then
            echo "Swap: ${host_swapfile} is still in use; it and its fstab line stay (swapoff it later, or reboot and delete them)"
        else
            # rewritten in place (its inode, owner and SELinux label stay;
            # sed -i would rename a new file over it)
            local tmp
            tmp=$(mktemp) && grep -v "$line" /etc/fstab >"$tmp"
            [[ -n $tmp ]] && cat "$tmp" >/etc/fstab && rm -f "$tmp"
            rm -f "$host_swapfile"
        fi
    fi
}

# DNS cache ("x-ui dns"). Nearly every new connection through the server
# needs a lookup -- freedom dials the names users visit, and REALITY dials
# its target -- and without a cache each one waits for a resolver across the
# network. unbound answers at 127.0.0.1 from its cache and forwards misses to
# the fastest resolvers this server reaches (measured at setup: often its
# provider's own, in the same datacenter). /etc/resolv.conf names 127.0.0.1
# first and two of those resolvers after it, used only if unbound does not
# answer. Every install and update sets it up unless "x-ui dns off" turned
# it off; it is left alone where something else manages DNS.
dns_conf_name="x-ui.conf"
dns_dropin="/etc/systemd/system/unbound.service.d/90-x-ui.conf"
dns_state="/etc/x-ui/dns"            # resolv.conf as it was, and what x-ui installed
dns_off_marker="/etc/x-ui/dns.off"
dns_header="# Written by \"x-ui dns\""
dns_public4="1.1.1.1 8.8.8.8 9.9.9.9"
dns_public6="2606:4700:4700::1111 2001:4860:4860::8888 2620:fe::fe"

# dns_conf_dir prints the directory unbound.conf includes *.conf files from.
dns_conf_dir() {
    local d
    # An include-toplevel line, else the last include (RHEL's first one is
    # inside its server: clause; conf.d comes at the end).
    d=$(sed -n 's/^[[:space:]]*include-toplevel:[[:space:]]*"\{0,1\}\([^"]*\)\/\*\.conf"\{0,1\}[[:space:]]*$/\1/p' /etc/unbound/unbound.conf 2>/dev/null | head -1)
    [[ -n $d ]] || d=$(sed -n 's/^[[:space:]]*include:[[:space:]]*"\{0,1\}\([^"]*\)\/\*\.conf"\{0,1\}[[:space:]]*$/\1/p' /etc/unbound/unbound.conf 2>/dev/null | tail -1)
    if [[ -n $d ]]; then
        echo "$d"
        return 0
    fi
    for d in /etc/unbound/unbound.conf.d /etc/unbound/conf.d; do
        [[ -d $d ]] && grep -qs "$d" /etc/unbound/unbound.conf && { echo "$d"; return 0; }
    done
    return 1
}

dns_conf() {
    local d
    d=$(dns_conf_dir) || d=/etc/unbound/unbound.conf.d
    echo "$d/$dns_conf_name"
}

# dns_ours says whether /etc/resolv.conf is the one "x-ui dns" wrote.
dns_ours() {
    [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]] && grep -qF "$dns_header" /etc/resolv.conf
}

# dns_nameservers FILE... prints the usable nameservers named in the files.
dns_nameservers() {
    awk '$1 == "nameserver" { sub(/%.*/, "", $2); print $2 }' "$@" 2>/dev/null |
        grep -vE '^(127\.|0\.0\.0\.0$|::1?$|fe80:)' | awk '!seen[$0]++'
}

# dns_candidates prints every resolver worth timing: the ones this server
# uses now or was given by DHCP, then well-known public ones.
dns_candidates() {
    local leases=()
    [[ -d /run/systemd/netif/leases ]] && leases=(/run/systemd/netif/leases/*)
    {
        if dns_ours && [[ -f $dns_state/resolv.conf ]]; then
            dns_nameservers "$dns_state/resolv.conf"
        else
            dns_nameservers /etc/resolv.conf
        fi
        dns_nameservers /run/systemd/resolve/resolv.conf
        ((${#leases[@]})) && sed -n 's/^DNS=//p' "${leases[@]}" 2>/dev/null | tr ' ' '\n'
        sed -n 's/^[[:space:]]*option domain-name-servers[[:space:]]*\([^;]*\);.*/\1/p' /var/lib/dhcp/dhclient*.leases 2>/dev/null | tr ', ' '\n\n'
        if ip -4 route show default 2>/dev/null | grep -q .; then
            printf '%s\n' $dns_public4
        fi
        if ip -6 route show default 2>/dev/null | grep -q .; then
            printf '%s\n' $dns_public6
        fi
    } | grep -vE '^(127\.|0\.0\.0\.0$|::1?$|fe80:|$)' | awk '!seen[$0]++'
}

# dns_query NAME prints a DNS query for NAME's A record (printf escapes). The
# ID's first byte is ASCII and never 0: dns_time reads one byte, bash skips
# NULs, and under a UTF-8 locale a lead byte would wait for more.
dns_query() {
    local label q
    q=$(printf '\\x%02x\\x%02x' $((RANDOM % 127 + 1)) $((RANDOM % 256)))
    q+='\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for label in ${1//./ }; do
        q+=$(printf '\\x%02x' ${#label})$label
    done
    printf '%s' "$q"'\x00\x00\x01\x00\x01'
}

# dns_clock sets now to the time in microseconds (no subshell on bash 5).
dns_clock() {
    if [[ -n ${EPOCHREALTIME:-} ]]; then
        now=${EPOCHREALTIME/[.,]/}
    else
        now=$(($(date +%s%N) / 1000))
    fi
}

# dns_send FD QUERY sends the query (printf escapes) as one datagram. bash
# writes its output line by line, and a query with a 0x0a byte (a label of
# 10 letters, an ID byte) would leave as two packets: a resolver gets a
# broken query and never answers, and an IDS sees junk on port 53. dd puts
# the pieces back together into one write.
dns_send() {
    printf "$2" | dd bs=512 count=1 iflag=fullblock status=none 1>&"$1" 2>/dev/null
}

# dns_answers SERVER says whether SERVER answers a recursive query with
# NOERROR (a resolver that refuses outsiders answers fast too).
dns_answers() {
    local fd h
    exec {fd}<>"/dev/udp/$1/53" 2>/dev/null || return 1
    dns_send "$fd" "$(dns_query www.google.com)"
    h=$(timeout 2 head -c 4 <&$fd 2>/dev/null | od -An -tx1 | tr -d ' \n')
    exec {fd}>&-
    # flags: QR set, RA set, RCODE 0
    [[ ${#h} -eq 8 ]] && (((0x${h:4:2} & 0x80) && (0x${h:6:2} & 0x8f) == 0x80))
}

# dns_time SERVER prints the median time in microseconds of five lookups of
# names any resolver has cached, or nothing if it does not answer. The clock
# starts once the query is out: starting dd costs more than a nearby
# resolver takes to answer.
dns_time() {
    local server=$1 name q t0 now fd times=() b LC_ALL=C
    for name in www.google.com www.youtube.com www.microsoft.com www.wikipedia.org www.google.com www.youtube.com; do
        q=$(dns_query "$name")
        exec {fd}<>"/dev/udp/${server}/53" 2>/dev/null || return 1
        dns_send "$fd" "$q"
        dns_clock
        t0=$now
        if read -r -t 1 -N 1 -u $fd b 2>/dev/null; then
            dns_clock
            times+=($((now - t0)))
        fi
        exec {fd}>&-
    done
    # the first lookup only warms the path up
    ((${#times[@]} >= 4)) || return 1
    printf '%s\n' "${times[@]:1}" | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'
}

# dns_pick prints "server microseconds" for the resolvers unbound forwards to:
# the fastest, those close to it (at most three), and the fastest public one
# when none of those is public, so one provider's outage is not the end.
dns_pick() {
    local s t timed=()
    for s in $(dns_candidates); do
        dns_answers "$s" || continue
        t=$(dns_time "$s") || continue
        [[ -n $t ]] && timed+=("$t $s")
    done
    ((${#timed[@]})) || return 1
    printf '%s\n' "${timed[@]}" | sort -n | awk -v pub="$dns_public4 $dns_public6" '
        BEGIN { n = split(pub, p, " "); for (i = 1; i <= n; i++) public[p[i]] = 1 }
        NR == 1 { best = $1 }
        {
            near = ($1 <= 3 * best || $1 <= best + 5000)
            if (kept < 3 && (NR == 1 || near || kept < 2)) { print $2, $1; kept++; if ($2 in public) havepub = 1; next }
            if (!havepub && ($2 in public)) { print $2, $1; havepub = 1 }
        }'
}

# dns_install installs unbound with the system's package manager.
dns_install() {
    case "${release}" in
    ubuntu | debian | armbian)
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -q unbound >/dev/null 2>&1 ||
            { apt-get -o DPkg::Lock::Timeout=180 update -q >/dev/null 2>&1 &&
                DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -q unbound >/dev/null 2>&1; }
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol | centos)
        dnf -y -q install unbound >/dev/null 2>&1 || yum -y -q install unbound >/dev/null 2>&1
        ;;
    arch | manjaro | parch)
        pacman -S --noconfirm --needed unbound >/dev/null 2>&1
        ;;
    opensuse-tumbleweed | opensuse-leap | sles)
        zypper -n -q install unbound >/dev/null 2>&1
        ;;
    *)
        return 1
        ;;
    esac
    command -v unbound >/dev/null 2>&1
}

# dns_trust_anchor writes the DNSSEC root key a distribution's own unbound
# config names (Debian and Ubuntu: /var/lib/unbound/root.key) where it does
# not exist yet: the service writes it on its first start, and until then
# unbound-checkconf rejects every config.
dns_trust_anchor() {
    local f
    for f in $(grep -rhoE '^[[:space:]]*auto-trust-anchor-file:[[:space:]]*"?[^"[:space:]]+' /etc/unbound 2>/dev/null | sed -E 's/^[^:]*:[[:space:]]*"?//'); do
        [[ -s $f ]] && continue
        mkdir -p "$(dirname "$f")"
        if [[ -x /usr/libexec/unbound-helper ]]; then
            /usr/libexec/unbound-helper root_trust_anchor_update >/dev/null 2>&1
        elif [[ -x /usr/lib/unbound/package-helper ]]; then
            /usr/lib/unbound/package-helper root_trust_anchor_update >/dev/null 2>&1
        fi
        [[ -s $f ]] && continue
        if [[ -s /usr/share/dns/root.key ]]; then
            cp /usr/share/dns/root.key "$f"
        else
            unbound-anchor -a "$f" >/dev/null 2>&1
        fi
        id unbound >/dev/null 2>&1 && chown unbound: "$(dirname "$f")" "$f" 2>/dev/null
    done
    return 0
}

# dns_render UPSTREAM... prints unbound's config. FAST=1 adds the options
# that send most misses to the fastest two (unbound 1.11 and later).
dns_render() {
    local cpus mem_mb threads slabs msg u
    cpus=$(nproc 2>/dev/null || echo 1)
    mem_mb=$(($(awk '/^MemTotal:/ { print $2 }' /proc/meminfo) / 1024))
    # a memory limit smaller than the machine (a container, a slice) counts
    local limit
    limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)
    [[ $limit =~ ^[0-9]+$ ]] && ((limit / 1048576 < mem_mb)) && mem_mb=$((limit / 1048576))
    threads=$((cpus / 8))
    ((threads < 1)) && threads=1
    ((threads > 8)) && threads=8
    slabs=1
    while ((slabs < threads)); do slabs=$((slabs * 2)); done
    msg=$((mem_mb / 64))
    ((msg < 8)) && msg=8
    ((msg > 256)) && msg=256
    cat <<EOF
${dns_header}; "x-ui dns off" removes it.
# A DNS cache for xray: answers at 127.0.0.1, forwards misses to the
# fastest resolvers this server reaches (timed when it was set up).
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    num-threads: ${threads}
    so-reuseport: yes
    so-rcvbuf: 8m
    so-sndbuf: 8m
    msg-cache-slabs: ${slabs}
    rrset-cache-slabs: ${slabs}
    infra-cache-slabs: ${slabs}
    key-cache-slabs: ${slabs}
    msg-cache-size: ${msg}m
    rrset-cache-size: $((2 * msg))m
    outgoing-range: 4096
    num-queries-per-thread: 2048
    prefetch: yes
    serve-expired: yes
    serve-expired-ttl: 3600
    # No DNSSEC validation, like the resolvers it replaces.
    module-config: "iterator"
    edns-buffer-size: 1232
    hide-identity: yes
    hide-version: yes
EOF
    if [[ ${FAST:-0} == 1 ]]; then
        cat <<EOF
    # An expired answer at once if the resolver is slow (unbound 1.11+).
    serve-expired-client-timeout: 1500
    # Nine misses in ten go to the two fastest; the rest keep the others'
    # times current.
    fast-server-num: 2
    fast-server-permil: 900
EOF
    fi
    printf 'forward-zone:\n    name: "."\n'
    for u in "$@"; do
        printf '    forward-addr: %s\n' "$u"
    done
    # Back in server: for whatever follows where the distribution includes
    # this file (RHEL includes it inside its own server: clause).
    printf 'server:\n'
}

# dns_resolv FALLBACK... prints resolv.conf: unbound, then the fallbacks.
dns_resolv() {
    local s
    echo "${dns_header}; \"x-ui dns off\" puts back the previous file."
    echo "# The local cache first; the resolvers after it only if it does not answer."
    echo "nameserver 127.0.0.1"
    for s in "$@"; do
        echo "nameserver $s"
    done
    echo "options timeout:2 attempts:2"
}

# dns_skip_reason prints why this server's DNS is left alone, if it is.
dns_skip_reason() {
    local s mine=0
    # x-ui's own unbound (its config carries the header) is not someone
    # else's DNS server.
    grep -qsF "$dns_header" "$(dns_conf)" && mine=1
    if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
        echo "not a systemd server"
        return 0
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q /etc/resolv.conf 2>/dev/null; then
        echo "/etc/resolv.conf is mounted from outside (a container)"
        return 0
    fi
    dns_ours && return 1
    if [[ -L /etc/resolv.conf ]]; then
        case "$(readlink -f /etc/resolv.conf)" in
        /run/systemd/resolve/stub-resolv.conf | /run/systemd/resolve/resolv.conf) ;;
        *) echo "/etc/resolv.conf is managed by $(readlink -f /etc/resolv.conf)"; return 0 ;;
        esac
    elif grep -qiE 'NetworkManager|resolvconf' /etc/resolv.conf 2>/dev/null; then
        echo "/etc/resolv.conf is written by NetworkManager or resolvconf"
        return 0
    fi
    for s in $(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null); do
        [[ $mine == 1 && $s == 127.0.0.1 ]] && continue
        if [[ $s == 127.* && $s != 127.0.0.53 || $s == ::1 ]]; then
            echo "a DNS server of its own already answers at $s"
            return 0
        fi
    done
    if [[ $mine == 0 ]] && ss -Hlnu 'sport = :53' 2>/dev/null | awk '{ print $4 }' | grep -qE '^(127\.0\.0\.1|0\.0\.0\.0|\*|\[::\]|\[::1\]):53$'; then
        echo "another DNS server listens on port 53"
        return 0
    fi
    if [[ $mine == 0 ]] && command -v unbound >/dev/null 2>&1 && [[ ! -f $dns_state/installed ]] &&
        { systemctl is-enabled --quiet unbound 2>/dev/null || systemctl is-active --quiet unbound 2>/dev/null; }; then
        echo "unbound is already set up here by someone else"
        return 0
    fi
    return 1
}

# dns_rollback undoes a dns_on that failed half-way, /etc/resolv.conf being
# untouched: a cache that already ran gets its previous config back
# ($conf.prev); otherwise x-ui's files go and unbound is stopped (the skip
# rules let dns_on near an unbound only when it was x-ui's, or off).
dns_rollback() {
    local conf
    conf=$(dns_conf)
    rm -f "$conf.new" /etc/resolv.conf.x-ui.new
    if [[ -f $conf.prev ]]; then
        mv -f "$conf.prev" "$conf"
        systemctl restart unbound >/dev/null 2>&1
        return 0
    fi
    rm -f "$conf"
    if grep -qsF "$dns_header" "$dns_dropin"; then
        rm -f "$dns_dropin"
        rmdir "$(dirname "$dns_dropin")" 2>/dev/null
    fi
    systemctl daemon-reload 2>/dev/null
    systemctl disable --now unbound >/dev/null 2>&1
}

dns_on() {
    local why picks servers=() s t fallbacks=() conf rc=0
    rm -f "$dns_off_marker"
    if why=$(dns_skip_reason); then
        LOGI "DNS cache not set up: ${why}."
        return 0
    fi
    echo "Timing the resolvers this server can use..."
    picks=$(dns_pick)
    if [[ -z $picks ]]; then
        LOGE "No resolver answers from here; DNS is left as it was."
        return 1
    fi
    while read -r s t; do
        servers+=("$s")
        printf '  %-24s %s ms\n' "$s" "$(awk -v t="$t" 'BEGIN { printf "%.1f", t / 1000 }')"
    done <<<"$picks"
    fallbacks=("${servers[@]:0:2}")

    mkdir -p "$dns_state"
    if ! command -v unbound >/dev/null 2>&1; then
        echo "Installing unbound..."
        dns_install || { LOGE "Could not install unbound; DNS is left as it was."; return 1; }
        : >"$dns_state/installed"
    fi
    dns_trust_anchor
    conf=$(dns_conf)
    mkdir -p "$(dirname "$conf")"
    rm -f "$conf.prev"
    grep -qsF "$dns_header" "$conf" && cp -p "$conf" "$conf.prev"
    FAST=1 dns_render "${servers[@]}" >"$conf.new"
    if ! unbound-checkconf "$conf.new" >/dev/null 2>&1; then
        # Older unbound has no fast-server options.
        dns_render "${servers[@]}" >"$conf.new"
    fi
    mv -f "$conf.new" "$conf"
    if ! unbound-checkconf >/dev/null 2>&1; then
        LOGE "unbound rejects its configuration: $(unbound-checkconf 2>&1 | tail -1); DNS is left as it was."
        dns_rollback
        return 1
    fi
    mkdir -p "$(dirname "$dns_dropin")"
    cat >"$dns_dropin" <<EOF
${dns_header}; "x-ui dns off" removes it.
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=2
EOF
    systemctl daemon-reload
    systemctl enable unbound >/dev/null 2>&1
    systemctl restart unbound
    for t in 1 2 3 4 5 6 7 8 9 10; do
        dns_answers 127.0.0.1 && break
        sleep 1
    done
    if ! dns_answers 127.0.0.1; then
        LOGE "unbound does not answer at 127.0.0.1 (see: journalctl -u unbound); DNS is left as it was."
        dns_rollback
        return 1
    fi
    # The previous resolv.conf (a file or a link) is kept once, for "off".
    if ! dns_ours; then
        rm -rf "$dns_state/resolv.conf"
        cp -P /etc/resolv.conf "$dns_state/resolv.conf" 2>/dev/null
    fi
    if ! { dns_resolv "${fallbacks[@]}" >/etc/resolv.conf.x-ui.new && chmod 644 /etc/resolv.conf.x-ui.new &&
        mv -f /etc/resolv.conf.x-ui.new /etc/resolv.conf; }; then
        LOGE "Could not write /etc/resolv.conf (immutable? lsattr /etc/resolv.conf); DNS is left as it was."
        dns_rollback
        return 1
    fi
    # Debian's unbound would otherwise hand itself to resolvconf.
    if [[ -f /etc/default/unbound ]] && grep -q '^RESOLVCONF=' /etc/default/unbound; then
        sed -i 's/^RESOLVCONF=.*/RESOLVCONF=false/' /etc/default/unbound
    elif [[ -d /etc/default ]]; then
        echo 'RESOLVCONF=false' >>/etc/default/unbound
    fi
    systemctl disable --now unbound-resolvconf.service >/dev/null 2>&1
    # Anti-abuse lets the resolvers through when they are private addresses.
    [[ -f $anti_abuse_unit && -f $anti_abuse_nft ]] && anti_abuse_reload
    rm -f "$conf.prev"
    LOGI "DNS cache on: unbound at 127.0.0.1, forwarding to ${servers[*]}."
    return $rc
}

# dns_auto is the installer's: on, unless "x-ui dns off" turned it off or it
# is already on.
dns_auto() {
    if [[ -f $dns_off_marker ]]; then
        echo "DNS cache: kept off (x-ui dns on turns it on)"
        return 0
    fi
    if dns_ours && systemctl is-active --quiet unbound; then
        echo "DNS cache: already on"
        return 0
    fi
    if grep -qsF "$dns_header" "$(dns_conf)" && ! dns_ours && [[ -e $dns_state/resolv.conf || -L $dns_state/resolv.conf ]]; then
        echo "DNS cache: kept as it is (/etc/resolv.conf was changed after x-ui set it up)"
        return 0
    fi
    dns_on
}

dns_status() {
    local conf
    conf=$(dns_conf)
    if [[ -f $dns_off_marker ]]; then
        echo -e "DNS cache: ${red}off${plain} (turned off; on: x-ui dns on)"
        return 1
    fi
    if ! grep -qsF "$dns_header" "$conf"; then
        local why
        why=$(dns_skip_reason) && { echo -e "DNS cache: ${yellow}not set up${plain} (${why})"; return 1; }
        echo -e "DNS cache: ${red}off${plain} (on: x-ui dns on)"
        return 1
    fi
    if systemctl is-active --quiet unbound && dns_answers 127.0.0.1; then
        if dns_ours; then
            echo -e "DNS cache: ${green}on${plain} (unbound at 127.0.0.1)"
        else
            echo -e "DNS cache: ${yellow}running but not used${plain} (/etc/resolv.conf was changed after x-ui set it up; use it again: x-ui dns on)"
        fi
    else
        echo -e "DNS cache: ${red}not answering${plain} (unbound $(systemctl is-active unbound 2>/dev/null); see: systemctl status unbound)"
    fi
    echo "  Forwards to: $(awk '$1 == "forward-addr:" { printf "%s%s", sep, $2; sep = ", " }' "$conf")"
    if dns_ours; then
        echo "  resolv.conf: $(awk '$1 == "nameserver" { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf)"
    else
        echo -e "  resolv.conf: ${yellow}changed since x-ui wrote it${plain} ($(awk '$1 == "nameserver" { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf 2>/dev/null))"
    fi
    if command -v unbound-control >/dev/null 2>&1; then
        unbound-control stats_noreset 2>/dev/null | awk -F= '
            $1 == "total.num.queries" { q = $2 } $1 == "total.num.cachehits" { h = $2 }
            END { if (q != "") printf "  Lookups: %d, %d%% from the cache\n", q, (q ? 100 * h / q : 0) }'
    fi
}

# dns_off puts back the previous resolv.conf (unless it was changed since)
# and stops x-ui's unbound. With "keep" it is not remembered as turned off
# (uninstall).
dns_off() {
    local conf
    conf=$(dns_conf)
    if dns_ours; then
        if [[ -e $dns_state/resolv.conf || -L $dns_state/resolv.conf ]]; then
            rm -f /etc/resolv.conf && cp -P "$dns_state/resolv.conf" /etc/resolv.conf
        else
            printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' >/etc/resolv.conf
        fi
    fi
    if grep -qsF "$dns_header" "$conf"; then
        rm -f "$conf"
        systemctl disable --now unbound >/dev/null 2>&1
    fi
    if grep -qsF "$dns_header" "$dns_dropin"; then
        rm -f "$dns_dropin"
        rmdir "$(dirname "$dns_dropin")" 2>/dev/null
    fi
    systemctl daemon-reload 2>/dev/null
    rm -rf "$dns_state"
    if [[ ${1:-} != keep ]]; then
        mkdir -p "$(dirname "$dns_off_marker")" && : >"$dns_off_marker"
    fi
    # Anti-abuse lets through the private resolvers resolv.conf names again.
    [[ -f $anti_abuse_unit && -f $anti_abuse_nft ]] && anti_abuse_reload
    LOGI "DNS cache off; /etc/resolv.conf: $(awk '$1 == "nameserver" { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf 2>/dev/null)."
}

# dns runs "x-ui dns [on|status|off]" (auto is the installer's).
dns() {
    case "${1:-status}" in
    on) dns_on ;;
    status) dns_status ;;
    off) dns_off ;;
    auto) dns_auto ;;
    *)
        echo "Usage: x-ui dns [on|status|off]"
        return 1
        ;;
    esac
}

dns_menu() {
    echo -e "${green}\t1.${plain} Show status"
    echo -e "${green}\t2.${plain} Turn on (times the resolvers again)"
    echo -e "${green}\t3.${plain} Turn off"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        dns_status
        before_show_menu
        ;;
    2)
        dns_on
        before_show_menu
        ;;
    3)
        dns_off
        before_show_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        dns_menu
        ;;
    esac
}

# Anti-abuse keeps the server's IPs out of abuse reports. An nftables table
# refuses outgoing connections to the ports brute-force bots and spammers
# use, to private networks through the uplink (a hoster's "netscan"), and to
# new destinations faster than real users reach them (port and net scans),
# and, for a while, to hosts that do not answer this server at all. fail2ban
# bans an IP after 2 failed SSH logins. Nothing here uses conntrack, so it
# costs nothing on a busy server. Every install and update turns it on;
# "x-ui anti-abuse off" undoes it all, and later updates keep it off.
anti_abuse_nft="/etc/x-ui/anti-abuse.nft"
anti_abuse_unit="/etc/systemd/system/x-ui-anti-abuse.service"
anti_abuse_check_unit="/etc/systemd/system/x-ui-anti-abuse-check.service"
anti_abuse_check_timer="/etc/systemd/system/x-ui-anti-abuse-check.timer"
# 00-: read first, so an admin's own jail.d settings for sshd win.
anti_abuse_jail="/etc/fail2ban/jail.d/00-x-ui-anti-abuse.conf"
anti_abuse_jail_old="/etc/fail2ban/jail.d/x-ui-anti-abuse.conf"
anti_abuse_table="xui_anti_abuse"
# SSH, Telnet, SMTP, MS-RPC, NetBIOS, SMB, MSSQL, Telnet, RDP, VNC, and mail
# submission (465, 587, 2525), which spam bots log in to with stolen accounts
anti_abuse_tcp_ports="22, 23, 25, 135, 139, 445, 465, 587, 1433, 2323, 2525, 3389, 5900"
# NetBIOS, SNMP, SSDP, memcached
anti_abuse_udp_ports="137, 138, 161, 1900, 11211"
# New destinations per second: hosts per outgoing IP and port, and ports
# per host (TCP). Measured on busy servers, real users peak at about 5 and 2.
# A scan uses up the allowance for everyone on its IP and port, so it is
# kept at ten times what users need: only fast scanners reach it.
anti_abuse_wide="50/second burst 1000 packets"
anti_abuse_deep="30/second burst 300 packets"
# A host with this many connection attempts waiting and not one working
# connection is refused for a while (checked every minute): users' apps fail
# at once and try another address instead of waiting out a timeout, and a
# flood at an unanswering target stops. Busy hosts keep working connections
# (Telegram's had 700 waiting and 3,900 working), so they are never refused.
anti_abuse_dead_waiting=100
anti_abuse_dead_for="10m"
# Written by "x-ui anti-abuse off": installs and updates then leave it off.
anti_abuse_off_marker="/etc/x-ui/anti-abuse.off"
# Networks that serve nothing but abuse: Spamhaus DROP (hijacked networks and
# ones run by criminals, botnet command servers among them). What connects to
# them is malware on a user's device calling home, and that gets the server's
# IP onto blocklists (Spamhaus XBL). New connections to them are refused from
# boot on (the last copy is kept here); the lists are fetched every 6 hours.
anti_abuse_lists_dir="${XUI_THREAT_DIR:-/etc/x-ui/anti-abuse-lists}"
anti_abuse_threats="${anti_abuse_lists_dir}/threats.nft"
anti_abuse_lists_unit="/etc/systemd/system/x-ui-anti-abuse-lists.service"
anti_abuse_lists_timer="/etc/systemd/system/x-ui-anti-abuse-lists.timer"
# Name, URL, and the fewest entries a good copy has (one with fewer is not
# taken: the last copy stays).
anti_abuse_sources="${XUI_THREAT_SOURCES:-drop4 https://www.spamhaus.org/drop/drop_v4.json 500
drop6 https://www.spamhaus.org/drop/drop_v6.json 10}"

# anti_abuse_uplinks prints the interfaces the default routes leave through.
anti_abuse_uplinks() {
    { ip -4 route show default; ip -6 route show default; } 2>/dev/null |
        awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }' | sort -u
}

# anti_abuse_allowed prints what stays reachable among private addresses
# (family 4 or 6): the uplinks' own subnets and routes, and the DNS servers.
anti_abuse_allowed() {
    local fam=$1 dev re
    if [[ $fam == 4 ]]; then
        re='^(0|10|172\.(1[6-9]|2[0-9]|3[01])|192\.168|192\.0\.[02]|198\.1[89]|198\.51\.100|203\.0\.113|2(4[0-9]|5[0-5]))\.[0-9.]+(/([89]|[1-3][0-9]))?$'
        echo "255.255.255.255"
    else
        re='^(f[cd][0-9a-f]{2}|fe[c-f][0-9a-f]|2001:0?db8):[0-9a-f:]*(/([89]|[1-9][0-9]|1[0-2][0-9]))?$'
    fi
    {
        for dev in $(anti_abuse_uplinks); do
            ip -"$fam" route show table all dev "$dev" 2>/dev/null |
                awk '{ d = $1; if (d ~ /^(unicast|local|broadcast|multicast|anycast|throw|unreachable|prohibit|blackhole|nat)$/) d = $2; print d }'
        done
        awk '$1 == "nameserver" { sub(/%.*/, "", $2); print $2 }' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null
        # the resolvers x-ui's DNS cache forwards to
        awk '$1 == "forward-addr:" { sub(/@.*/, "", $2); print $2 }' "$(dns_conf)" 2>/dev/null
    } | tr 'A-F' 'a-f' | grep -E "$re" | sort -u
}

# anti_abuse_rules prints the nftables rules "x-ui anti-abuse" loads.
anti_abuse_rules() {
    local uplinks allowed4 allowed6 private=""
    uplinks=$(anti_abuse_uplinks | awk '{ printf "%s\"%s\"", (NR > 1 ? ", " : ""), $1 }')
    allowed4=$(anti_abuse_allowed 4 | paste -sd, - | sed 's/,/, /g')
    allowed6=$(anti_abuse_allowed 6 | paste -sd, - | sed 's/,/, /g')
    if [[ -n $uplinks ]]; then
        uplinks="elements = { ${uplinks} }"
        private="
		oifname @uplinks ip daddr @private4 ip daddr != @allowed4 counter name private_nets reject with icmpx admin-prohibited
		oifname @uplinks ip6 daddr @private6 ip6 daddr != @allowed6 counter name private_nets reject with icmpx admin-prohibited"
    fi
    [[ -n $allowed6 ]] && allowed6="elements = { ${allowed6} }"
    cat <<EOF
#!/usr/sbin/nft -f
# Written by "x-ui anti-abuse"; "x-ui anti-abuse off" removes it.

table inet ${anti_abuse_table}
delete table inet ${anti_abuse_table}

table inet ${anti_abuse_table} {
	set tcp_ports {
		type inet_service
		counter
		elements = { ${anti_abuse_tcp_ports} }
	}
	set udp_ports {
		type inet_service
		counter
		elements = { ${anti_abuse_udp_ports} }
	}
	set uplinks {
		type ifname
		${uplinks}
	}
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16,
			     198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4 }
	}
	set private6 {
		type ipv6_addr
		flags interval
		elements = { 2001:db8::/32, fc00::/7, fec0::/10 }
	}
	set allowed4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { ${allowed4} }
	}
	set allowed6 {
		type ipv6_addr
		flags interval
		auto-merge
		${allowed6}
	}
	set seen4 { type ipv4_addr . inet_service; flags dynamic, timeout; timeout 10m; size 262144; }
	set seen6 { type ipv6_addr . inet_service; flags dynamic, timeout; timeout 10m; size 262144; }
	set wide4 { type ipv4_addr . inet_service; flags dynamic, timeout; timeout 5m; size 65536; }
	set wide6 { type ipv6_addr . inet_service; flags dynamic, timeout; timeout 5m; size 65536; }
	set deep4 { type ipv4_addr; flags dynamic, timeout; timeout 5m; size 65536; }
	set deep6 { type ipv6_addr; flags dynamic, timeout; timeout 5m; size 65536; }
	set dead4 { type ipv4_addr; flags timeout; timeout ${anti_abuse_dead_for}; size 65536; }
	set dead6 { type ipv6_addr; flags timeout; timeout ${anti_abuse_dead_for}; size 65536; }
	# filled from ${anti_abuse_threats}
	set threats4 { type ipv4_addr; flags interval; auto-merge; }
	set threats6 { type ipv6_addr; flags interval; auto-merge; }
	counter private_nets { }
	counter scan_wide { }
	counter scan_deep { }
	counter dead_hosts { }
	counter threats { }

	chain output {
		type filter hook output priority filter; policy accept;
		oifname "lo" accept
		tcp flags & (syn | ack) == syn ip daddr @threats4 counter name threats reject with tcp reset
		tcp flags & (syn | ack) == syn ip6 daddr @threats6 counter name threats reject with tcp reset
		meta l4proto udp ip daddr @threats4 counter name threats reject
		meta l4proto udp ip6 daddr @threats6 counter name threats reject
		tcp flags & (syn | ack) == syn ip daddr @dead4 counter name dead_hosts reject with tcp reset
		tcp flags & (syn | ack) == syn ip6 daddr @dead6 counter name dead_hosts reject with tcp reset
		tcp flags & (syn | ack) == syn tcp dport @tcp_ports reject with tcp reset
		udp dport @udp_ports reject${private}
		tcp flags & (syn | ack) == syn tcp dport != { 80, 443 } jump scan
		udp dport 1-1023 udp dport != 443 jump scan
	}
	# A destination (address and port) seen in the last 10 minutes passes;
	# a new one counts against the scan limits.
	chain scan {
		meta nfproto ipv4 goto scan4
		meta nfproto ipv6 goto scan6
	}
	chain scan4 {
		ip daddr . th dport @seen4 update @seen4 { ip daddr . th dport } return
		update @wide4 { ip saddr . th dport limit rate over ${anti_abuse_wide} } counter name scan_wide goto refuse
		meta l4proto tcp update @deep4 { ip daddr limit rate over ${anti_abuse_deep} } counter name scan_deep goto refuse
		add @seen4 { ip daddr . th dport }
	}
	chain scan6 {
		ip6 daddr . th dport @seen6 update @seen6 { ip6 daddr . th dport } return
		update @wide6 { ip6 saddr . th dport limit rate over ${anti_abuse_wide} } counter name scan_wide goto refuse
		meta l4proto tcp update @deep6 { ip6 daddr limit rate over ${anti_abuse_deep} } counter name scan_deep goto refuse
		add @seen6 { ip6 daddr . th dport }
	}
	chain refuse {
		meta l4proto tcp reject with tcp reset
		reject
	}
}
EOF
}

# anti_abuse_install installs a package with the system's package manager.
anti_abuse_install() {
    case "${release}" in
    ubuntu | debian | armbian)
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -q "$1" >/dev/null 2>&1 ||
            { apt-get -o DPkg::Lock::Timeout=180 update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y -q "$1" >/dev/null; }
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol | centos)
        dnf -y install "$1" || yum -y install "$1"
        ;;
    arch | manjaro | parch)
        pacman -S --noconfirm "$1"
        ;;
    opensuse-tumbleweed | opensuse-leap | sles)
        zypper -n install "$1"
        ;;
    *)
        return 1
        ;;
    esac
}

# anti_abuse_ssh_jail bans an IP after 2 failed SSH logins in 10 minutes:
# for 1 hour, longer each time it comes back (up to a week). The address
# this is run from is never banned.
# anti_abuse_ssh_client prints the address of the SSH session this runs in,
# also under sudo (which drops SSH_CLIENT): from the parents' environment.
anti_abuse_ssh_client() {
    local pid=$$ e
    e=${SSH_CLIENT:-${SSH_CONNECTION:-}}
    while [[ -z $e && $pid -gt 1 ]]; do
        e=$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CLIENT=//p; s/^SSH_CONNECTION=//p' | head -1)
        pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        [[ -n $pid ]] || break
    done
    [[ -n $e ]] && echo "${e%% *}"
}

# anti_abuse_ignoreip prints the ignoreip values of the [DEFAULT] and [sshd]
# sections (continuation lines too) of fail2ban's config, x-ui's own jail
# included: the SSH jail's own list replaces [DEFAULT]'s, so it carries those.
anti_abuse_ignoreip() {
    local f
    for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local; do
        [[ -f $f ]] || continue
        awk '
            /^[[:space:]]*\[/ { sec = $0; gsub(/[][[:space:]]/, "", sec); cont = 0; next }
            /^[[:space:]]*[#;]/ { next }
            cont && /^[[:space:]]+[^[:space:]]/ { print; next }
            { cont = 0 }
            (sec == "DEFAULT" || sec == "sshd") && /^[[:space:]]*ignoreip[[:space:]]*=/ { sub(/^[^=]*=/, ""); print; cont = 1 }
        ' "$f"
    done
}

anti_abuse_ssh_jail() {
    local ports unit client="" ignore backend="" had=0
    if ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then
        LOGI "No SSH server here, so no SSH ban is needed."
        return 0
    fi
    command -v fail2ban-client >/dev/null 2>&1 && had=1
    # An install or update leaves a fail2ban the admin turned off alone.
    if [[ ${ANTI_ABUSE_AUTO:-0} == 1 && $had == 1 ]]; then
        case "$(systemctl is-enabled fail2ban 2>/dev/null)" in
        disabled | masked)
            LOGI "SSH bans left off: fail2ban is turned off here (x-ui anti-abuse on turns them on)."
            return 0
            ;;
        esac
    fi
    install_fail2ban || return 1
    ports=$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk '$1 == "port" { print $2 }' | sort -un | paste -sd, -)
    [[ -n $ports ]] || ports=ssh
    # Never banned: loopback, what the admin lists for all jails or for SSH
    # (and what was added to this jail by hand), and the address this is run
    # from.
    client=$(anti_abuse_ssh_client)
    ignore=$(
        {
            echo "127.0.0.1/8 ::1 ${client}"
            anti_abuse_ignoreip
        } | tr ' ,' '\n\n' | grep -v '^$' | grep -vF '%(' | awk '!seen[$0]++' | paste -sd' ' -
    )
    # Without a log file sshd only logs to the journal, as sshd or (OpenSSH
    # 9.8+) sshd-session.
    if command -v journalctl >/dev/null 2>&1 && [[ ! -s /var/log/auth.log && ! -s /var/log/secure ]]; then
        unit=sshd
        systemctl cat ssh.service >/dev/null 2>&1 && unit=ssh
        backend="backend = systemd
journalmatch = _SYSTEMD_UNIT=${unit}.service + _COMM=sshd + _COMM=sshd-session"
    fi
    mkdir -p "$(dirname "$anti_abuse_jail")"
    rm -f "$anti_abuse_jail_old"
    cat >"$anti_abuse_jail" <<EOF
# Written by "x-ui anti-abuse"; "x-ui anti-abuse off" removes it. Addresses
# added to ignoreip here stay through updates; settings for [sshd] in other
# jail.d files or jail.local win over these.
[sshd]
enabled = true
port = ${ports}
maxretry = 2
findtime = 10m
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
ignoreip = ${ignore}
${backend}
EOF
    if ! fail2ban-client -t >/dev/null 2>&1; then
        rm -f "$anti_abuse_jail"
        LOGE "fail2ban rejected the SSH jail (see: fail2ban-client -t); SSH bans are not on."
        return 1
    fi
    systemctl enable fail2ban >/dev/null 2>&1
    if systemctl is-active --quiet fail2ban; then
        if ! fail2ban-client reload >/dev/null 2>&1; then
            rm -f "$anti_abuse_jail"
            fail2ban-client reload >/dev/null 2>&1
            LOGE "fail2ban could not load the SSH jail; SSH bans are not on."
            return 1
        fi
    else
        systemctl restart fail2ban
    fi
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        fail2ban-client status sshd >/dev/null 2>&1 && return 0
        sleep 1
    done
    LOGE "fail2ban's SSH jail did not start (see: journalctl -u fail2ban)."
    return 1
}

anti_abuse_on() {
    local nft rc=0
    rm -f "$anti_abuse_off_marker"
    if ! command -v systemctl >/dev/null 2>&1; then
        LOGE "Anti-abuse needs systemd."
        return 1
    fi
    if ! command -v nft >/dev/null 2>&1; then
        anti_abuse_install nftables
    fi
    nft=$(command -v nft) || { LOGE "Could not install nftables."; return 1; }
    mkdir -p "$(dirname "$anti_abuse_nft")"
    anti_abuse_rules >"${anti_abuse_nft}.new"
    if ! "$nft" -c -f "${anti_abuse_nft}.new"; then
        rm -f "${anti_abuse_nft}.new"
        LOGE "nftables rejected the rules; nothing changed."
        return 1
    fi
    mv -f "${anti_abuse_nft}.new" "$anti_abuse_nft"
    # After nftables.service and firewalld, whose start may flush the
    # ruleset; before the network and x-ui come up.
    cat >"$anti_abuse_unit" <<EOF
[Unit]
Description=x-ui anti-abuse (outgoing brute-force ports, private networks, scans)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target x-ui.service
After=local-fs.target nftables.service firewalld.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${nft} -f ${anti_abuse_nft}
ExecStart=-/bin/sh -c '[ ! -f ${anti_abuse_threats} ] || ${nft} -f ${anti_abuse_threats}'
ExecReload=${nft} -f ${anti_abuse_nft}
ExecReload=-/bin/sh -c '[ ! -f ${anti_abuse_threats} ] || ${nft} -f ${anti_abuse_threats}'
ExecStop=${nft} delete table inet ${anti_abuse_table}

[Install]
WantedBy=sysinit.target
EOF
    # The check for hosts that do not answer, every minute.
    cat >"$anti_abuse_check_unit" <<EOF
[Unit]
Description=x-ui anti-abuse: refuse hosts that do not answer for a while
After=x-ui-anti-abuse.service

[Service]
Type=oneshot
Nice=10
ExecStart=$(command -v x-ui || echo /usr/bin/x-ui) anti-abuse check
EOF
    cat >"$anti_abuse_check_timer" <<EOF
[Unit]
Description=x-ui anti-abuse: look for hosts that do not answer, every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
    # The threat lists, every 6 hours.
    cat >"$anti_abuse_lists_unit" <<EOF
[Unit]
Description=x-ui anti-abuse: fetch the threat lists again, check Spamhaus
After=x-ui-anti-abuse.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart=$(command -v x-ui || echo /usr/bin/x-ui) anti-abuse lists timer
EOF
    cat >"$anti_abuse_lists_timer" <<EOF
[Unit]
Description=x-ui anti-abuse: fetch the threat lists again, every 6 hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=30min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable x-ui-anti-abuse >/dev/null 2>&1
    systemctl restart x-ui-anti-abuse || { LOGE "x-ui-anti-abuse did not start (see: systemctl status x-ui-anti-abuse)."; return 1; }
    systemctl enable --now x-ui-anti-abuse-check.timer >/dev/null 2>&1 || rc=1
    anti_abuse_lists fetch || LOGE "Could not load the threat lists (see: journalctl -t x-ui-anti-abuse)."
    systemctl enable --now x-ui-anti-abuse-lists.timer >/dev/null 2>&1 || rc=1
    # dig asks Spamhaus whether it lists the server (x-ui anti-abuse status).
    if ! command -v dig >/dev/null 2>&1; then
        anti_abuse_install dnsutils >/dev/null 2>&1 || anti_abuse_install bind-utils >/dev/null 2>&1 || anti_abuse_install bind >/dev/null 2>&1
    fi
    anti_abuse_ssh_jail || rc=1

    echo -e "${green}Anti-abuse is on:${plain}
  Refused: outgoing TCP ${anti_abuse_tcp_ports} and UDP ${anti_abuse_udp_ports}
  Refused: $(anti_abuse_threat_count) botnet and criminal networks (Spamhaus DROP), fetched again every 6 hours
  Refused: private networks through $(anti_abuse_uplinks | paste -sd, -)
  Scans refused: over ${anti_abuse_wide%%/*} new hosts/s on a port, ${anti_abuse_deep%%/*} new ports/s on a host
  Dead hosts: refused for ${anti_abuse_dead_for} when ${anti_abuse_dead_waiting}+ connection attempts wait and none works
  SSH: 2 failed logins in 10 minutes = 1 hour ban, longer when the IP comes back
  Status: x-ui anti-abuse status   Off: x-ui anti-abuse off"
    return $rc
}

# anti_abuse_check refuses, for anti_abuse_dead_for, each host with at
# least anti_abuse_dead_waiting connection attempts waiting (SYN sent, no
# answer) and not one established connection. It runs every minute from
# x-ui-anti-abuse-check.timer; ss asks the kernel by state, so it is quick
# with hundreds of thousands of connections.
anti_abuse_check() {
    nft list set inet "$anti_abuse_table" dead4 >/dev/null 2>&1 || return 0
    local waiting ip set q out
    ss -Htn state syn-sent 2>/dev/null | awk '{ print $4 }' |
        sed -E 's/:[0-9]+$//; s/^\[(::ffff:)?//; s/\]$//' | sort | uniq -c |
        awk -v n="$anti_abuse_dead_waiting" '$1 >= n { print $1, $2 }' |
        while read -r waiting ip; do
            # One working connection means it answers: busy, not dead. (ss
            # takes IPv6 in brackets; when it fails, nothing is refused.)
            q=$ip
            [[ $ip == *:* ]] && q="[$ip]"
            out=$(ss -Htn state established dst "$q" 2>/dev/null) || continue
            [[ -n $out ]] && continue
            set=dead4
            [[ $ip == *:* ]] && set=dead6
            if nft add element inet "$anti_abuse_table" "$set" "{ $ip }" 2>/dev/null; then
                logger -t x-ui-anti-abuse "refusing $ip for ${anti_abuse_dead_for}: $waiting connection attempts waiting, none working"
            fi
        done
    return 0
}

# anti_abuse_entries prints the addresses and networks of a threat list, one
# per line: the "cidr" values of Spamhaus's JSON, or the lines of a plain
# list. Private, reserved and multicast addresses, and networks too wide to
# be real (shorter than /8, or /16 for IPv6), are left out.
anti_abuse_entries() {
    local list
    list=$(cat "$1" 2>/dev/null) || return 0
    {
        grep -oE '"cidr" *: *"[^"]+"' <<<"$list" | sed -E 's/.*"([^"]+)"$/\1/'
        grep -vE '^[[:space:]]*([#;{]|$)' <<<"$list" | awk '{ print $1 }'
    } | tr -d '\r' | tr 'A-F' 'a-f' |
        grep -E '^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|[0-9a-f]{1,4}:[0-9a-f:]*(/[0-9]{1,3})?)$' |
        awk -F'[./]' '
            /:/ {
                n = split($0, p, "/")
                if (n > 1 && (p[2] < 16 || p[2] > 128)) next
                if (p[1] ~ /^(f[c-f]|ff|2001:0?db8:)/) next
                print; next
            }
            $1 > 255 || $2 > 255 || $3 > 255 || $4 > 255 { next }
            NF > 4 && ($5 < 8 || $5 > 32) { next }
            $1 == 0 || $1 == 10 || $1 == 127 || $1 >= 224 { next }
            ($1 == 100 && $2 >= 64 && $2 < 128) || ($1 == 169 && $2 == 254) { next }
            ($1 == 172 && $2 >= 16 && $2 < 32) || ($1 == 192 && $2 == 168) { next }
            { print }'
}

# anti_abuse_threat_count prints how many networks the threat lists refuse.
anti_abuse_threat_count() {
    sed -n 's/^# networks: //p' "$anti_abuse_threats" 2>/dev/null | grep . || echo 0
}

# anti_abuse_lists [fetch|timer|load] fetches the threat lists again and
# loads them into the running rules ("load" only loads the copies kept). A
# source that cannot be fetched, or sends fewer entries than a good copy
# has, keeps its last copy. The timer's run (every 6 hours) also checks
# Spamhaus and logs a listing.
anti_abuse_lists() {
    nft list set inet "$anti_abuse_table" threats4 >/dev/null 2>&1 || return 0
    local name url least got entries v4 v6 n4 n6 listed
    mkdir -p "$anti_abuse_lists_dir" || return 1
    if [[ ${1:-fetch} != load ]]; then
        while read -r name url least; do
            [[ -n $name && -n $url ]] || continue
            if curl -fsSL --connect-timeout 10 --max-time 60 -o "${anti_abuse_lists_dir}/${name}.new" "$url" 2>/dev/null &&
                got=$(anti_abuse_entries "${anti_abuse_lists_dir}/${name}.new" | wc -l) && ((got >= ${least:-0})); then
                mv -f "${anti_abuse_lists_dir}/${name}.new" "${anti_abuse_lists_dir}/${name}"
            else
                rm -f "${anti_abuse_lists_dir}/${name}.new"
                logger -t x-ui-anti-abuse "threat list ${name}: could not fetch a good copy of ${url}; the last copy stays"
            fi
        done <<<"$anti_abuse_sources"
    fi
    entries=$(while read -r name _; do
        [[ -n $name && -f ${anti_abuse_lists_dir}/${name} ]] && anti_abuse_entries "${anti_abuse_lists_dir}/${name}"
    done <<<"$anti_abuse_sources" | sort -u)
    v4=$(grep -v : <<<"$entries" | grep . | paste -sd, - | sed 's/,/, /g')
    v6=$(grep : <<<"$entries" | paste -sd, - | sed 's/,/, /g')
    n4=$(grep -vc : <<<"$entries")
    n6=$(grep -c : <<<"$entries")
    [[ -n $v4 ]] || n4=0
    {
        echo "# Written by \"x-ui anti-abuse lists\" from the copies next to it; loaded after ${anti_abuse_nft}."
        echo "# networks: $((n4 + n6))"
        echo "flush set inet ${anti_abuse_table} threats4"
        echo "flush set inet ${anti_abuse_table} threats6"
        [[ -n $v4 ]] && echo "add element inet ${anti_abuse_table} threats4 { ${v4} }"
        [[ -n $v6 ]] && echo "add element inet ${anti_abuse_table} threats6 { ${v6} }"
    } >"${anti_abuse_threats}.new"
    if ! nft -f "${anti_abuse_threats}.new" 2>/dev/null; then
        rm -f "${anti_abuse_threats}.new"
        logger -t x-ui-anti-abuse "nftables rejected the threat lists; the ones loaded before stay"
        return 1
    fi
    mv -f "${anti_abuse_threats}.new" "$anti_abuse_threats"
    if [[ ${1:-} == timer ]]; then
        anti_abuse_spamhaus | while read -r ip listed; do
            logger -t x-ui-anti-abuse "${ip} is on Spamhaus ${listed}: https://check.spamhaus.org/results/?query=${ip}"
        done
    fi
    return 0
}

# anti_abuse_spamhaus prints the address the server's traffic leaves from
# (the default route's) with the Spamhaus lists it is on ("2.29.134.171
# XBL"), or nothing when it is on none. It asks Spamhaus's own name servers,
# which do not answer through big public resolvers. Without dig it returns 1;
# when Spamhaus does not answer, 2.
anti_abuse_spamhaus() {
    command -v dig >/dev/null 2>&1 || return 1
    local ip q codes lists
    for ip in $(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1) }'); do
        [[ -n $(anti_abuse_entries <(echo "$ip")) ]] || continue
        q="$(awk -F. '{ print $4"."$3"."$2"."$1 }' <<<"$ip").zen.spamhaus.org"
        codes=$(dig -4 +short +time=3 +tries=1 "$q" A @a.gns.spamhaus.org 2>/dev/null) ||
            codes=$(dig -4 +short +time=3 +tries=1 "$q" A @b.gns.spamhaus.org 2>/dev/null) || return 2
        lists=$(grep -E '^127\.0\.0\.[0-9]+$' <<<"$codes" | awk -F. '
            { n = $4; print (n == 2 ? "SBL" : n == 3 ? "CSS" : n >= 4 && n <= 7 ? "XBL" : n == 9 ? "DROP" : "PBL") }' |
            sort -u | paste -sd, -)
        [[ -n $lists ]] && echo "$ip $lists"
    done
    return 0
}

# anti_abuse_counter prints a named counter's packets.
anti_abuse_counter() {
    nft list counter inet "$anti_abuse_table" "$1" 2>/dev/null | awk '/packets/ { print $2 }'
}

# anti_abuse_hits prints "tcp/22 15, tcp/3389 2" for a port set's elements hit.
anti_abuse_hits() {
    nft list set inet "$anti_abuse_table" "$1" 2>/dev/null | grep -oE '[0-9]+ counter packets [0-9]+' |
        awk -v p="$2" '$4 > 0 { printf "%s%s/%s %s", (n++ ? ", " : ""), p, $1, $4 }'
}

anti_abuse_status() {
    if [[ ! -f $anti_abuse_unit ]]; then
        if [[ -f $anti_abuse_off_marker ]]; then
            echo -e "Anti-abuse: ${red}off${plain} (turned off; updates keep it off; on: x-ui anti-abuse on)"
        else
            echo -e "Anti-abuse: ${red}off${plain} (turn it on: x-ui anti-abuse)"
        fi
        return 1
    fi
    local state ports
    state=$(systemctl is-active x-ui-anti-abuse 2>/dev/null)
    if [[ $state != active ]] || ! nft list table inet "$anti_abuse_table" >/dev/null 2>&1; then
        echo -e "Anti-abuse: ${red}not loaded${plain} (${state}; load it again: x-ui anti-abuse)"
        return 1
    fi
    ports=$(printf '%s, %s' "$(anti_abuse_hits tcp_ports tcp)" "$(anti_abuse_hits udp_ports udp)" | sed 's/^, //; s/, $//')
    echo -e "Anti-abuse: ${green}on${plain} since $(systemctl show -p ActiveEnterTimestamp --value x-ui-anti-abuse)"
    echo "  Refused ports:    ${ports:-none yet}"
    echo "  Private networks: $(anti_abuse_counter private_nets)"
    echo "  Scans refused:    $(anti_abuse_counter scan_wide) wide, $(anti_abuse_counter scan_deep) deep"
    local dead
    dead=$({ nft list set inet "$anti_abuse_table" dead4; nft list set inet "$anti_abuse_table" dead6; } 2>/dev/null |
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f]*:[0-9a-f:]+' | paste -sd' ' -)
    echo "  Dead hosts:       $(anti_abuse_counter dead_hosts) attempts refused; now: ${dead:-none}"
    echo "  Threat lists:     $(anti_abuse_threat_count) networks ($(date -r "$anti_abuse_threats" '+%F %R' 2>/dev/null || echo "not fetched yet")); $(anti_abuse_counter threats) packets refused"
    local listed src
    listed=$(anti_abuse_spamhaus)
    case $? in
    0)
        if [[ -n $listed ]]; then
            echo -e "  Spamhaus:         ${red}listed${plain}: ${listed}"
            echo "                    see https://check.spamhaus.org/results/?query=${listed%% *} (XBL: malware on a user's device; ask for removal there)"
        else
            src=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1) }')
            echo "  Spamhaus:         ${src:-the server} not listed"
        fi
        ;;
    1) echo "  Spamhaus:         not checked (needs dig: dnsutils or bind-utils)" ;;
    *) echo "  Spamhaus:         not checked (Spamhaus's name servers did not answer)" ;;
    esac
    if [[ -f $anti_abuse_jail || -f $anti_abuse_jail_old ]] && command -v fail2ban-client >/dev/null 2>&1; then
        fail2ban-client status sshd 2>/dev/null | awk -F':\t' '
            /Currently banned/ { now = $2 } /Total banned/ { total = $2 } /Total failed/ { failed = $2 }
            END { printf "  SSH bans:         %s now, %s in total (%s failed logins)\n", now, total, failed }'
    else
        echo "  SSH bans:         off"
    fi
}

# anti_abuse_reload writes the rules again (the uplinks or the resolvers
# may have changed) and loads them in one go.
anti_abuse_reload() {
    local nft
    nft=$(command -v nft) || return 1
    anti_abuse_rules >"${anti_abuse_nft}.new"
    if ! "$nft" -c -f "${anti_abuse_nft}.new" >/dev/null 2>&1; then
        rm -f "${anti_abuse_nft}.new"
        return 1
    fi
    mv -f "${anti_abuse_nft}.new" "$anti_abuse_nft"
    systemctl reload-or-restart x-ui-anti-abuse >/dev/null 2>&1
}

# anti_abuse_auto is the installer's: on, unless "x-ui anti-abuse off"
# turned it off.
anti_abuse_auto() {
    if [[ -f $anti_abuse_off_marker ]]; then
        echo "Anti-abuse: kept off (x-ui anti-abuse on turns it on)"
        return 0
    fi
    ANTI_ABUSE_AUTO=1 anti_abuse_on
}

# anti_abuse_off takes it all away. With "keep" it is not remembered as
# turned off (uninstall).
anti_abuse_off() {
    if [[ ${1:-} != keep ]]; then
        mkdir -p "$(dirname "$anti_abuse_off_marker")" && : >"$anti_abuse_off_marker"
    fi
    if [[ -f $anti_abuse_check_timer ]]; then
        systemctl disable --now x-ui-anti-abuse-check.timer >/dev/null 2>&1
        rm -f "$anti_abuse_check_timer" "$anti_abuse_check_unit"
    fi
    if [[ -f $anti_abuse_lists_timer ]]; then
        systemctl disable --now x-ui-anti-abuse-lists.timer >/dev/null 2>&1
        rm -f "$anti_abuse_lists_timer" "$anti_abuse_lists_unit"
    fi
    rm -rf "$anti_abuse_lists_dir"
    if [[ -f $anti_abuse_unit ]]; then
        systemctl disable --now x-ui-anti-abuse >/dev/null 2>&1
        rm -f "$anti_abuse_unit"
    fi
    systemctl daemon-reload 2>/dev/null
    command -v nft >/dev/null 2>&1 && nft delete table inet "$anti_abuse_table" 2>/dev/null
    rm -f "$anti_abuse_nft"
    if [[ -f $anti_abuse_jail || -f $anti_abuse_jail_old ]]; then
        rm -f "$anti_abuse_jail" "$anti_abuse_jail_old"
        if systemctl is-active --quiet fail2ban; then
            # Without this jail's journal settings the distribution's own SSH
            # jail may find no log file (Debian 12 has none): fail2ban would
            # then fail on every start. It is stopped instead.
            if ! fail2ban-client -t >/dev/null 2>&1; then
                systemctl disable --now fail2ban >/dev/null 2>&1
                LOGI "fail2ban stopped: its remaining configuration does not load here."
            else
                fail2ban-client reload >/dev/null
            fi
        fi
    fi
    LOGI "Anti-abuse is off."
}

# anti_abuse runs "x-ui anti-abuse [on|status|off|rules|lists|check]"
# (check and "lists timer" are the timers').
anti_abuse() {
    case "${1:-on}" in
    on) anti_abuse_on ;;
    status) anti_abuse_status ;;
    off) anti_abuse_off ;;
    rules) anti_abuse_rules ;;
    lists) anti_abuse_lists "${2:-fetch}" ;;
    check) anti_abuse_check ;;
    auto) anti_abuse_auto ;;
    *)
        echo "Usage: x-ui anti-abuse [on|status|off|rules|lists]"
        return 1
        ;;
    esac
}

anti_abuse_menu() {
    echo -e "${green}\t1.${plain} Show status"
    echo -e "${green}\t2.${plain} Turn on (or apply again)"
    echo -e "${green}\t3.${plain} Turn off"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        anti_abuse_status
        before_show_menu
        ;;
    2)
        anti_abuse_on
        before_show_menu
        ;;
    3)
        anti_abuse_off
        before_show_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        anti_abuse_menu
        ;;
    esac
}

# Protection is set up by every install and update ("x-ui protect off" is
# remembered: updates then leave the guard off):
#  - The direct guard. The panel marks every connection the cores' freedom
#    ("direct") outbounds make (web/service/xray_direct_mark.go, directMark),
#    and an nftables table refuses marked packets to this server's loopback
#    and to private networks. Freedom resolves an allowed name itself and
#    dials whatever comes back, which routing never sees: a name pointing at
#    127.0.0.1 would reach what listens only there -- the cores' API takes
#    commands without a password. The server's public addresses stay open:
#    what listens there is open to the internet anyway, and VPN apps test the
#    configs of the server they are connected to through it -- all but its
#    SSH and panel ports.
#  - Speed-test servers (iperf3) are stopped and kept from starting: they let
#    anyone on the internet pull the uplink's whole bandwidth.
# "x-ui protect off" takes the guard away; speed-test servers stay stopped.
protect_nft="/etc/x-ui/direct-guard.nft"
protect_unit="/etc/systemd/system/x-ui-direct-guard.service"
protect_table="xui_direct_guard"
protect_mark=4242
protect_speedtest_units="iperf3.service iperf.service"
protect_dropin="x-ui-protect.conf"
# Written by "x-ui protect off": installs and updates then leave the guard off.
protect_off_marker="/etc/x-ui/protect.off"

# protect_own_ports prints this server's SSH and panel ports: reached
# through the VPN they would come from the server itself, where fail2ban
# never bans and an admin's "only my IP" firewall rules do not apply.
protect_own_ports() {
    {
        echo 22
        (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk '$1 == "port" { print $2 }'
        [[ -x ${xui_folder}/x-ui ]] && ${xui_folder}/x-ui setting -show true 2>/dev/null | grep -Eo 'port: [0-9]+' | awk '{ print $2 }' | head -1
    } | grep -E '^[0-9]+$' | sort -un | paste -sd, - | sed 's/,/, /g'
}

# protect_rules prints the direct guard's nftables rules.
protect_rules() {
    local own
    own=$(protect_own_ports)
    cat <<EOF
#!/usr/sbin/nft -f
# Written by "x-ui protect"; "x-ui protect off" removes it.

table inet ${protect_table}
delete table inet ${protect_table}

table inet ${protect_table} {
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12,
			     192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 }
	}
	set private6 {
		type ipv6_addr
		flags interval
		elements = { ::/128, fc00::/7, fe80::/10, ff00::/8 }
	}
	counter local { }
	counter private { }
	counter self { }

	chain output {
		type filter hook output priority filter - 1; policy accept;
		meta mark != ${protect_mark} return
		ip daddr 127.0.0.0/8 counter name local goto refuse
		ip6 daddr ::1 counter name local goto refuse
		ip daddr @private4 counter name private goto refuse
		ip6 daddr @private6 counter name private goto refuse
		# This server's own public addresses: open, counted -- but for its
		# SSH and panel ports.
		oifname "lo" tcp dport { ${own:-22} } counter name local goto refuse
		oifname "lo" counter name self
	}
	chain refuse {
		meta l4proto tcp reject with tcp reset
		reject with icmpx admin-prohibited
	}
}
EOF
}

# protect_speedtest_held says whether a speed-test server is kept from
# starting for good: masked, or (a unit file in /etc/systemd/system cannot be
# masked) held back by our drop-in. A runtime mask goes at the next boot.
protect_speedtest_held() {
    [[ $(systemctl is-enabled "$1" 2>/dev/null) == masked ]] || [[ -f /etc/systemd/system/$1.d/$protect_dropin ]]
}

# protect_speedtest_stopped says whether a speed-test server is held and not
# running: a plain "systemctl mask" leaves a running one running.
protect_speedtest_stopped() {
    protect_speedtest_held "$1" || return 1
    case "$(systemctl is-active "$1" 2>/dev/null)" in
    active | activating | reloading | deactivating) return 1 ;;
    esac
    return 0
}

# protect_speedtest_stop stops the speed-test servers and keeps them from
# starting again.
protect_speedtest_stop() {
    local u en
    for u in $protect_speedtest_units; do
        en=$(systemctl is-enabled "$u" 2>/dev/null) || true
        [[ -z $en || $en == not-found ]] && continue
        protect_speedtest_stopped "$u" && continue
        systemctl disable --now "$u" >/dev/null 2>&1 || true
        systemctl stop "$u" >/dev/null 2>&1 || true
        systemctl unmask --runtime "$u" >/dev/null 2>&1 || true
        systemctl mask "$u" >/dev/null 2>&1 || true
        if ! protect_speedtest_held "$u"; then
            mkdir -p "/etc/systemd/system/$u.d"
            cat >"/etc/systemd/system/$u.d/$protect_dropin" <<EOF
# Written by "x-ui protect": speed-test servers stay off. To start it again:
# delete this file, then systemctl daemon-reload && systemctl enable --now $u
[Unit]
ConditionPathExists=/nonexistent/x-ui-protect
EOF
            systemctl daemon-reload
        fi
        LOGI "Stopped the speed-test server ${u%.service}; it stays off."
    done
    return 0
}

# protect_speedtest_summary prints what became of the speed-test servers.
protect_speedtest_summary() {
    local u out=""
    for u in $protect_speedtest_units; do
        case "$(systemctl is-enabled "$u" 2>/dev/null)" in
        "" | not-found) continue ;;
        esac
        if protect_speedtest_stopped "$u"; then
            out+="${out:+, }${u%.service} stopped"
        elif protect_speedtest_held "$u"; then
            out+="${out:+, }${u%.service} held but RUNNING"
        else
            out+="${out:+, }${u%.service} $(systemctl is-active "$u" 2>/dev/null)"
        fi
    done
    echo "${out:-none here}"
}

protect_on() {
    local nft rc=0
    rm -f "$protect_off_marker"
    if ! command -v systemctl >/dev/null 2>&1; then
        LOGE "Protection needs systemd; it is not set up."
        return 1
    fi
    protect_speedtest_stop
    if ! command -v nft >/dev/null 2>&1; then
        anti_abuse_install nftables >/dev/null 2>&1
    fi
    nft=$(command -v nft) || { LOGE "Could not install nftables; the direct guard is not set up."; return 1; }
    mkdir -p "$(dirname "$protect_nft")"
    protect_rules >"${protect_nft}.new"
    if ! "$nft" -c -f "${protect_nft}.new"; then
        rm -f "${protect_nft}.new"
        LOGE "nftables rejected the direct guard (no permission here?); it is not set up."
        return 1
    fi
    mv -f "${protect_nft}.new" "$protect_nft"
    cat >"$protect_unit" <<EOF
[Unit]
Description=x-ui direct guard (the cores' direct connections never reach this server's loopback or private networks)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target x-ui.service
After=local-fs.target nftables.service firewalld.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${nft} -f ${protect_nft}
ExecReload=${nft} -f ${protect_nft}
ExecStop=${nft} delete table inet ${protect_table}

[Install]
WantedBy=sysinit.target
EOF
    systemctl daemon-reload
    systemctl enable x-ui-direct-guard >/dev/null 2>&1
    # A reload swaps the table in one go: no moment without the guard.
    systemctl reload-or-restart x-ui-direct-guard || { LOGE "x-ui-direct-guard did not start (see: systemctl status x-ui-direct-guard)."; rc=1; }
    nft list table inet "$protect_table" >/dev/null 2>&1 || rc=1
    [[ $rc == 0 ]] && LOGI "Direct guard on; speed-test servers: $(protect_speedtest_summary)."
    return $rc
}

protect_counter() {
    nft list counter inet "$protect_table" "$1" 2>/dev/null | awk '/packets/ { print $2 }'
}

protect_status() {
    if nft list table inet "$protect_table" >/dev/null 2>&1; then
        echo -e "Direct guard: ${green}on${plain}"
        echo "  Refused: $(protect_counter local) packets to this server's loopback, $(protect_counter private) to private networks"
        echo "  Passed:  $(protect_counter self) packets to this server's public addresses"
    else
        echo -e "Direct guard: ${red}off${plain} (turn it on: x-ui protect)"
    fi
    echo "Speed-test servers: $(protect_speedtest_summary)"
}

# protect_auto is the installer's: speed-test servers stopped, and the guard
# on unless "x-ui protect off" turned it off.
protect_auto() {
    if [[ -f $protect_off_marker ]]; then
        protect_speedtest_stop
        echo "Direct guard: kept off (x-ui protect on turns it on); speed-test servers: $(protect_speedtest_summary)."
        return 0
    fi
    protect_on
}

# protect_off takes the guard away. With "keep" it is not remembered as
# turned off (uninstall).
protect_off() {
    if [[ ${1:-} != keep ]]; then
        mkdir -p "$(dirname "$protect_off_marker")" && : >"$protect_off_marker"
    fi
    if [[ -f $protect_unit ]]; then
        systemctl disable --now x-ui-direct-guard >/dev/null 2>&1
        rm -f "$protect_unit"
        systemctl daemon-reload 2>/dev/null
    fi
    command -v nft >/dev/null 2>&1 && nft delete table inet "$protect_table" 2>/dev/null
    rm -f "$protect_nft"
    LOGI "Direct guard off (updates keep it off; x-ui protect on turns it on). Speed-test servers stay stopped; to start iperf3 again: systemctl unmask iperf3 && systemctl enable --now iperf3 (if it was held by /etc/systemd/system/iperf3.service.d/${protect_dropin}: delete that, systemctl daemon-reload, then enable --now)."
}

# protect runs "x-ui protect [on|status|off|rules]".
protect() {
    case "${1:-on}" in
    on) protect_on ;;
    status) protect_status ;;
    off) protect_off ;;
    rules) protect_rules ;;
    auto) protect_auto ;;
    *)
        echo "Usage: x-ui protect [on|status|off|rules]"
        return 1
        ;;
    esac
}

update_shell() {
    if ! fetch_menu_script; then
        echo ""
        LOGE "Failed to download script, Please check whether the machine can connect Github"
        before_show_menu
    else
        LOGI "Upgrade script succeeded, Please rerun the script"
        before_show_menu
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ $release == "alpine" ]]; then
        if [[ ! -f /etc/init.d/x-ui ]]; then
            return 2
        fi
        if [[ $(rc-service x-ui status | grep -F 'status: started' -c) == 1 ]]; then
            return 0
        else
            return 1
        fi
    else
        if [[ ! -f ${xui_service}/x-ui.service ]]; then
            return 2
        fi
        temp=$(systemctl status x-ui | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ "${temp}" == "running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

check_enabled() {
    if [[ $release == "alpine" ]]; then
        if [[ $(rc-update show | grep -F 'x-ui' | grep default -c) == 1 ]]; then
            return 0
        else
            return 1
        fi
    else
        temp=$(systemctl is-enabled x-ui)
        if [[ "${temp}" == "enabled" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        LOGE "Panel installed, Please do not reinstall"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        LOGE "Please install the panel first"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
    0)
        echo -e "Panel state: ${green}Running${plain}"
        show_enable_status
        ;;
    1)
        echo -e "Panel state: ${yellow}Not Running${plain}"
        show_enable_status
        ;;
    2)
        echo -e "Panel state: ${red}Not Installed${plain}"
        ;;
    esac
    show_xray_status
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Start automatically: ${green}Yes${plain}"
    else
        echo -e "Start automatically: ${red}No${plain}"
    fi
}

check_xray_status() {
    count=$(ps -ef | grep "xray-linux" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_xray_status() {
    check_xray_status
    if [[ $? == 0 ]]; then
        echo -e "xray state: ${green}Running${plain}"
    else
        echo -e "xray state: ${red}Not Running${plain}"
    fi
}

firewall_menu() {
    echo -e "${green}\t1.${plain} ${green}Install${plain} Firewall"
    echo -e "${green}\t2.${plain} Port List [numbered]"
    echo -e "${green}\t3.${plain} ${green}Open${plain} Ports"
    echo -e "${green}\t4.${plain} ${red}Delete${plain} Ports from List"
    echo -e "${green}\t5.${plain} ${green}Enable${plain} Firewall"
    echo -e "${green}\t6.${plain} ${red}Disable${plain} Firewall"
    echo -e "${green}\t7.${plain} Firewall Status"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        install_firewall
        firewall_menu
        ;;
    2)
        ufw status numbered
        firewall_menu
        ;;
    3)
        open_ports
        firewall_menu
        ;;
    4)
        delete_ports
        firewall_menu
        ;;
    5)
        ufw enable
        firewall_menu
        ;;
    6)
        ufw disable
        firewall_menu
        ;;
    7)
        ufw status verbose
        firewall_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        firewall_menu
        ;;
    esac
}

# panel_ports lists the TCP ports the panel and its cores listen on (the web
# and subscription ports, every inbound and sub-inbound), plus sshd's; ports
# bound to loopback only (the cores' API) need no rule.
panel_ports() {
    local ports=() p
    if command -v ss >/dev/null 2>&1; then
        while read -r p; do
            [[ -n "$p" ]] && ports+=("$p")
        done < <(ss -Hltnp 2>/dev/null | grep -E '"(x-ui|xray-linux-[a-z0-9]+|sshd)"' \
            | awk '$4 !~ /^(127\.|\[::1\]:)/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un)
    fi
    p=$(${xui_folder}/x-ui setting -show true 2>/dev/null | grep -Eo 'port: [0-9]+' | awk '{print $2}' | head -1)
    [[ -n "$p" ]] && ports+=("$p")
    printf '%s\n' "${ports[@]}" | sort -un
}

install_firewall() {
    if ! command -v ufw &>/dev/null; then
        echo "ufw firewall is not installed. Installing now..."
        apt-get update
        apt-get install -y ufw
    else
        echo "ufw firewall is already installed"
    fi

    # Check if the firewall is inactive
    if ufw status | grep -q "Status: active"; then
        echo "Firewall is already active"
    else
        # Everything this server listens on for the panel, its inbounds
        # and SSH stays reachable; enabling ufw blocks all other ports.
        local ports p
        ports=$(panel_ports)
        echo "These TCP ports stay open (panel, inbounds, SSH): $(echo $ports | tr ' ' ',')"
        echo "UDP inbounds and ports of other programs must be opened with option 3."
        confirm "Enable the firewall now?" "n" || return 0
        ufw allow ssh
        for p in $ports; do
            ufw allow "$p"
        done

        # Enable the firewall
        ufw --force enable
    fi
}

open_ports() {
    # Prompt the user to enter the ports they want to open
    read -rp "Enter the ports you want to open (e.g. 80,443,2053 or range 400-500): " ports

    # Check if the input is valid
    if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
        echo "Error: Invalid input. Please enter a comma-separated list of ports or a range of ports (e.g. 80,443,2053 or 400-500)." >&2
        exit 1
    fi

    # Open the specified ports using ufw
    IFS=',' read -ra PORT_LIST <<<"$ports"
    for port in "${PORT_LIST[@]}"; do
        if [[ $port == *-* ]]; then
            # Split the range into start and end ports
            start_port=$(echo $port | cut -d'-' -f1)
            end_port=$(echo $port | cut -d'-' -f2)
            # Open the port range
            ufw allow $start_port:$end_port/tcp
            ufw allow $start_port:$end_port/udp
        else
            # Open the single port
            ufw allow "$port"
        fi
    done

    # Confirm that the ports are opened
    echo "Opened the specified ports:"
    for port in "${PORT_LIST[@]}"; do
        if [[ $port == *-* ]]; then
            start_port=$(echo $port | cut -d'-' -f1)
            end_port=$(echo $port | cut -d'-' -f2)
            # Check if the port range has been successfully opened
            (ufw status | grep -q "$start_port:$end_port") && echo "$start_port-$end_port"
        else
            # Check if the individual port has been successfully opened
            (ufw status | grep -q "$port") && echo "$port"
        fi
    done
}

delete_ports() {
    # Display current rules with numbers
    echo "Current UFW rules:"
    ufw status numbered

    # Ask the user how they want to delete rules
    echo "Do you want to delete rules by:"
    echo "1) Rule numbers"
    echo "2) Ports"
    read -rp "Enter your choice (1 or 2): " choice

    if [[ $choice -eq 1 ]]; then
        # Deleting by rule numbers
        read -rp "Enter the rule numbers you want to delete (1, 2, etc.): " rule_numbers

        # Validate the input
        if ! [[ $rule_numbers =~ ^([0-9]+)(,[0-9]+)*$ ]]; then
            echo "Error: Invalid input. Please enter a comma-separated list of rule numbers." >&2
            exit 1
        fi

        # Split numbers into an array
        IFS=',' read -ra RULE_NUMBERS <<<"$rule_numbers"
        for rule_number in "${RULE_NUMBERS[@]}"; do
            # Delete the rule by number
            ufw delete "$rule_number" || echo "Failed to delete rule number $rule_number"
        done

        echo "Selected rules have been deleted."

    elif [[ $choice -eq 2 ]]; then
        # Deleting by ports
        read -rp "Enter the ports you want to delete (e.g. 80,443,2053 or range 400-500): " ports

        # Validate the input
        if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
            echo "Error: Invalid input. Please enter a comma-separated list of ports or a range of ports (e.g. 80,443,2053 or 400-500)." >&2
            exit 1
        fi

        # Split ports into an array
        IFS=',' read -ra PORT_LIST <<<"$ports"
        for port in "${PORT_LIST[@]}"; do
            if [[ $port == *-* ]]; then
                # Split the port range
                start_port=$(echo $port | cut -d'-' -f1)
                end_port=$(echo $port | cut -d'-' -f2)
                # Delete the port range
                ufw delete allow $start_port:$end_port/tcp
                ufw delete allow $start_port:$end_port/udp
            else
                # Delete a single port
                ufw delete allow "$port"
            fi
        done

        # Confirmation of deletion
        echo "Deleted the specified ports:"
        for port in "${PORT_LIST[@]}"; do
            if [[ $port == *-* ]]; then
                start_port=$(echo $port | cut -d'-' -f1)
                end_port=$(echo $port | cut -d'-' -f2)
                # Check if the port range has been deleted
                (ufw status | grep -q "$start_port:$end_port") || echo "$start_port-$end_port"
            else
                # Check if the individual port has been deleted
                (ufw status | grep -q "$port") || echo "$port"
            fi
        done
    else
        echo "${red}Error:${plain} Invalid choice. Please enter 1 or 2." >&2
        exit 1
    fi
}

# update_geofiles downloads one set of geo files. Each file is fetched next
# to the live one and only moved over it when the download completed, so a
# dropped connection cannot leave a truncated file for the cores to load.
# It sets geo_changed when a file was replaced, and returns 1 if any failed.
geo_changed=0
update_geofiles() {
    local dat_files dat_source dat remote_file live tmp failed=0
    case "${1}" in
      "main") dat_files=(geoip geosite); dat_source="Loyalsoldier/v2ray-rules-dat";;
        "IR") dat_files=(geoip_IR geosite_IR); dat_source="chocolate4u/Iran-v2ray-rules" ;;
        "RU") dat_files=(geoip_RU geosite_RU); dat_source="runetfreedom/russia-v2ray-rules-dat";;
    esac
    for dat in "${dat_files[@]}"; do
        # Remove suffix for remote filename (e.g., geoip_IR -> geoip)
        remote_file="${dat%%_*}"
        live="${xui_folder}/bin/${dat}.dat"
        tmp="${live}.download"
        rm -f "$tmp"
        if [[ -f "$live" ]]; then
            curl -fsSLR -o "$tmp" -z "$live" "https://github.com/${dat_source}/releases/latest/download/${remote_file}.dat"
        else
            curl -fsSLR -o "$tmp" "https://github.com/${dat_source}/releases/latest/download/${remote_file}.dat"
        fi
        if [[ $? -ne 0 ]]; then
            rm -f "$tmp"
            LOGE "Download of ${dat}.dat failed; the current file is kept."
            failed=1
        elif [[ -s "$tmp" ]]; then
            mv -f "$tmp" "$live" && geo_changed=1 && echo "Updated ${dat}.dat"
        else
            rm -f "$tmp" # not modified since the last download
            echo "${dat}.dat is up to date"
        fi
    done
    return $failed
}

update_all_geofiles() {
    local failed=0
    update_geofiles "main" || failed=1
    update_geofiles "IR" || failed=1
    update_geofiles "RU" || failed=1
    return $failed
}

# geo_done reports the outcome and restarts the panel only when a file was
# actually replaced.
geo_done() {
    local failed=$1
    if [[ $failed -ne 0 ]]; then
        LOGE "Some geo files could not be updated."
    fi
    if [[ $geo_changed -eq 1 ]]; then
        LOGI "Geo files updated; restarting the panel."
        restart 0
    elif [[ $failed -eq 0 ]]; then
        LOGI "Geo files are already up to date."
    fi
}

update_geo() {
    echo -e "${green}\t1.${plain} Loyalsoldier (geoip.dat, geosite.dat)"
    echo -e "${green}\t2.${plain} chocolate4u (geoip_IR.dat, geosite_IR.dat)"
    echo -e "${green}\t3.${plain} runetfreedom (geoip_RU.dat, geosite_RU.dat)"
    echo -e "${green}\t4.${plain} All"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice

    geo_changed=0
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        update_geofiles "main"
        geo_done $?
        ;;
    2)
        update_geofiles "IR"
        geo_done $?
        ;;
    3)
        update_geofiles "RU"
        geo_done $?
        ;;
    4)
        update_all_geofiles
        geo_done $?
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        update_geo
        ;;
    esac

    before_show_menu
}

install_acme() {
    # Check if acme.sh is already installed
    if command -v ~/.acme.sh/acme.sh &>/dev/null; then
        LOGI "acme.sh is already installed."
        return 0
    fi

    LOGI "Installing acme.sh..."
    cd ~ || return 1 # Ensure you can change to the home directory

    curl -s https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        LOGE "Installation of acme.sh failed."
        return 1
    else
        LOGI "Installation of acme.sh succeeded."
    fi

    return 0
}

ssl_cert_issue_main() {
    echo -e "${green}\t1.${plain} Get SSL (Domain)"
    echo -e "${green}\t2.${plain} Revoke"
    echo -e "${green}\t3.${plain} Force Renew"
    echo -e "${green}\t4.${plain} Show Existing Domains"
    echo -e "${green}\t5.${plain} Set Cert paths for the panel"
    echo -e "${green}\t6.${plain} Get SSL for IP Address (6-day cert, auto-renews)"
    echo -e "${green}\t0.${plain} Back to Main Menu"

    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        ssl_cert_issue
        ssl_cert_issue_main
        ;;
    2)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "No certificates found to revoke."
        else
            echo "Existing domains:"
            echo "$domains"
            read -rp "Please enter a domain from the list to revoke the certificate: " domain
            if echo "$domains" | grep -qw "$domain"; then
                ~/.acme.sh/acme.sh --revoke -d ${domain}
                LOGI "Certificate revoked for domain: $domain"
            else
                echo "Invalid domain entered."
            fi
        fi
        ssl_cert_issue_main
        ;;
    3)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "No certificates found to renew."
        else
            echo "Existing domains:"
            echo "$domains"
            read -rp "Please enter a domain from the list to renew the SSL certificate: " domain
            if echo "$domains" | grep -qw "$domain"; then
                ~/.acme.sh/acme.sh --renew -d ${domain} --force
                LOGI "Certificate forcefully renewed for domain: $domain"
            else
                echo "Invalid domain entered."
            fi
        fi
        ssl_cert_issue_main
        ;;
    4)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "No certificates found."
        else
            echo "Existing domains and their paths:"
            for domain in $domains; do
                local cert_path="/root/cert/${domain}/fullchain.pem"
                local key_path="/root/cert/${domain}/privkey.pem"
                if [[ -f "${cert_path}" && -f "${key_path}" ]]; then
                    echo -e "Domain: ${domain}"
                    echo -e "\tCertificate Path: ${cert_path}"
                    echo -e "\tPrivate Key Path: ${key_path}"
                else
                    echo -e "Domain: ${domain} - Certificate or Key missing."
                fi
            done
        fi
        ssl_cert_issue_main
        ;;
    5)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "No certificates found."
        else
            echo "Available domains:"
            echo "$domains"
            read -rp "Please choose a domain to set the panel paths: " domain

            if echo "$domains" | grep -qw "$domain"; then
                local webCertFile="/root/cert/${domain}/fullchain.pem"
                local webKeyFile="/root/cert/${domain}/privkey.pem"

                if [[ -f "${webCertFile}" && -f "${webKeyFile}" ]]; then
                    ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
                    echo "Panel paths set for domain: $domain"
                    echo "  - Certificate File: $webCertFile"
                    echo "  - Private Key File: $webKeyFile"
                    restart
                else
                    echo "Certificate or private key not found for domain: $domain."
                fi
            else
                echo "Invalid domain entered."
            fi
        fi
        ssl_cert_issue_main
        ;;
    6)
        echo -e "${yellow}Let's Encrypt SSL Certificate for IP Address${plain}"
        echo -e "This will obtain a certificate for your server's IP using the shortlived profile."
        echo -e "${yellow}Certificate valid for ~6 days, auto-renews via acme.sh cron job.${plain}"
        echo -e "${yellow}Port 80 must be open and accessible from the internet.${plain}"
        confirm "Do you want to proceed?" "y"
        if [[ $? == 0 ]]; then
            ssl_cert_issue_for_ip
        fi
        ssl_cert_issue_main
        ;;

    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        ssl_cert_issue_main
        ;;
    esac
}

ssl_cert_issue_for_ip() {
    LOGI "Starting automatic SSL certificate generation for server IP..."
    LOGI "Using Let's Encrypt shortlived profile (~6 days validity, auto-renews)"
    
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    
    # Get server IP
    local server_ip=$(curl -s --max-time 3 https://api.ipify.org)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s --max-time 3 https://4.ident.me)
    fi
    
    if [ -z "$server_ip" ]; then
        LOGE "Failed to get server IP address"
        return 1
    fi
    
    LOGI "Server IP detected: ${server_ip}"
    
    # Ask for optional IPv6
    local ipv6_addr=""
    read -rp "Do you have an IPv6 address to include? (leave empty to skip): " ipv6_addr
    ipv6_addr="${ipv6_addr// /}"  # Trim whitespace
    
    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        LOGI "acme.sh not found, installing..."
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "Failed to install acme.sh"
            return 1
        fi
    fi
    
    # install socat
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update >/dev/null 2>&1 && apt-get install socat -y >/dev/null 2>&1
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum -y update >/dev/null 2>&1 && yum -y install socat >/dev/null 2>&1
        else
            dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        fi
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm socat >/dev/null 2>&1
        ;;
    opensuse-tumbleweed | opensuse-leap)
        zypper refresh >/dev/null 2>&1 && zypper -q install -y socat >/dev/null 2>&1
        ;;
    alpine)
        apk add socat curl openssl >/dev/null 2>&1
        ;;
    *)
        LOGW "Unsupported OS for automatic socat installation"
        ;;
    esac
    
    # Create certificate directory
    certPath="/root/cert/ip"
    mkdir -p "$certPath"
    
    # Build domain arguments
    local domain_args="-d ${server_ip}"
    if [[ -n "$ipv6_addr" ]] && is_ipv6 "$ipv6_addr"; then
        domain_args="${domain_args} -d ${ipv6_addr}"
        LOGI "Including IPv6 address: ${ipv6_addr}"
    fi
    
    # Choose port for HTTP-01 listener (default 80, allow override)
    local WebPort=""
    read -rp "Port to use for ACME HTTP-01 listener (default 80): " WebPort
    WebPort="${WebPort:-80}"
    if ! [[ "${WebPort}" =~ ^[0-9]+$ ]] || ((WebPort < 1 || WebPort > 65535)); then
        LOGE "Invalid port provided. Falling back to 80."
        WebPort=80
    fi
    LOGI "Using port ${WebPort} to issue certificate for IP: ${server_ip}"
    if [[ "${WebPort}" -ne 80 ]]; then
        LOGI "Reminder: Let's Encrypt still reaches port 80; forward external port 80 to ${WebPort} for validation."
    fi

    while true; do
        if is_port_in_use "${WebPort}"; then
            LOGI "Port ${WebPort} is currently in use."

            local alt_port=""
            read -rp "Enter another port for acme.sh standalone listener (leave empty to abort): " alt_port
            alt_port="${alt_port// /}"
            if [[ -z "${alt_port}" ]]; then
                LOGE "Port ${WebPort} is busy; cannot proceed with issuance."
                return 1
            fi
            if ! [[ "${alt_port}" =~ ^[0-9]+$ ]] || ((alt_port < 1 || alt_port > 65535)); then
                LOGE "Invalid port provided."
                return 1
            fi
            WebPort="${alt_port}"
            continue
        else
            LOGI "Port ${WebPort} is free and ready for standalone validation."
            break
        fi
    done
    
    # Reload command - restarts panel after renewal
    local reloadCmd="systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null"
    
    # issue the certificate for IP with shortlived profile
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
    ~/.acme.sh/acme.sh --issue \
        ${domain_args} \
        --standalone \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport ${WebPort} \
        --force
    
    if [ $? -ne 0 ]; then
        LOGE "Failed to issue certificate for IP: ${server_ip}"
        LOGE "Make sure port ${WebPort} is open and the server is accessible from the internet"
        # Cleanup acme.sh data for both IPv4 and IPv6 if specified
        rm -rf ~/.acme.sh/${server_ip} 2>/dev/null
        [[ -n "$ipv6_addr" ]] && rm -rf ~/.acme.sh/${ipv6_addr} 2>/dev/null
        rm -rf ${certPath} 2>/dev/null
        return 1
    else
        LOGI "Certificate issued successfully for IP: ${server_ip}"
    fi
    
    # Install the certificate
    # Note: acme.sh may report "Reload error" and exit non-zero if reloadcmd fails,
    # but the cert files are still installed. We check for files instead of exit code.
    ~/.acme.sh/acme.sh --installcert -d ${server_ip} \
        --key-file "${certPath}/privkey.pem" \
        --fullchain-file "${certPath}/fullchain.pem" \
        --reloadcmd "${reloadCmd}" 2>&1 || true
    
    # Verify certificate files exist (don't rely on exit code - reloadcmd failure causes non-zero)
    if [[ ! -f "${certPath}/fullchain.pem" || ! -f "${certPath}/privkey.pem" ]]; then
        LOGE "Certificate files not found after installation"
        # Cleanup acme.sh data for both IPv4 and IPv6 if specified
        rm -rf ~/.acme.sh/${server_ip} 2>/dev/null
        [[ -n "$ipv6_addr" ]] && rm -rf ~/.acme.sh/${ipv6_addr} 2>/dev/null
        rm -rf ${certPath} 2>/dev/null
        return 1
    fi
    
    LOGI "Certificate files installed successfully"
    
    # enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    chmod 600 $certPath/privkey.pem 2>/dev/null
    chmod 644 $certPath/fullchain.pem 2>/dev/null
    
    # Set certificate paths for the panel
    local webCertFile="${certPath}/fullchain.pem"
    local webKeyFile="${certPath}/privkey.pem"
    
    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
        LOGI "Certificate configured for panel"
        LOGI "  - Certificate File: $webCertFile"
        LOGI "  - Private Key File: $webKeyFile"
        LOGI "  - Validity: ~6 days (auto-renews via acme.sh cron)"
        echo -e "${green}Access URL: https://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
        LOGI "Panel will restart to apply SSL certificate..."
        restart
        return 0
    else
        LOGE "Certificate files not found after installation"
        return 1
    fi
}

ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "acme.sh could not be found. we will install it"
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "install acme failed, please check logs"
            exit 1
        fi
    fi

    # install socat
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update >/dev/null 2>&1 && apt-get install socat -y >/dev/null 2>&1
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum -y update >/dev/null 2>&1 && yum -y install socat >/dev/null 2>&1
        else
            dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        fi
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm socat >/dev/null 2>&1
        ;;
    opensuse-tumbleweed | opensuse-leap)
        zypper refresh >/dev/null 2>&1 && zypper -q install -y socat >/dev/null 2>&1
        ;;
    alpine)
        apk add socat curl openssl >/dev/null 2>&1
        ;;
    *)
        LOGW "Unsupported OS for automatic socat installation"
        ;;
    esac
    if [ $? -ne 0 ]; then
        LOGE "install socat failed, please check logs"
        exit 1
    else
        LOGI "install socat succeed..."
    fi

    # get the domain here, and we need to verify it
    local domain=""
    while true; do
        read -rp "Please enter your domain name: " domain
        domain="${domain// /}"  # Trim whitespace
        
        if [[ -z "$domain" ]]; then
            LOGE "Domain name cannot be empty. Please try again."
            continue
        fi
        
        if ! is_domain "$domain"; then
            LOGE "Invalid domain format: ${domain}. Please enter a valid domain name."
            continue
        fi
        
        break
    done
    LOGD "Your domain is: ${domain}, checking it..."
    SSL_ISSUED_DOMAIN="${domain}"

    # detect existing certificate and reuse it if present
    local cert_exists=0
    if ~/.acme.sh/acme.sh --list 2>/dev/null | awk '{print $1}' | grep -Fxq "${domain}"; then
        cert_exists=1
        local certInfo=$(~/.acme.sh/acme.sh --list 2>/dev/null | grep -F "${domain}")
        LOGI "Existing certificate found for ${domain}, will reuse it."
        [[ -n "${certInfo}" ]] && LOGI "${certInfo}"
    else
        LOGI "Your domain is ready for issuing certificates now..."
    fi

    # create a directory for the certificate
    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    # get the port number for the standalone server
    local WebPort=80
    read -rp "Please choose which port to use (default is 80): " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        LOGE "Your input ${WebPort} is invalid, will use default port 80."
        WebPort=80
    fi
    LOGI "Will use port: ${WebPort} to issue certificates. Please make sure this port is open."

    if [[ ${cert_exists} -eq 0 ]]; then
        # issue the certificate
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
        ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport ${WebPort} --force
        if [ $? -ne 0 ]; then
            LOGE "Issuing certificate failed, please check logs."
            rm -rf ~/.acme.sh/${domain}
            exit 1
        else
            LOGE "Issuing certificate succeeded, installing certificates..."
        fi
    else
        LOGI "Using existing certificate, installing certificates..."
    fi

    reloadCmd="x-ui restart"

    LOGI "Default --reloadcmd for ACME is: ${yellow}x-ui restart"
    LOGI "This command will run on every certificate issue and renew."
    read -rp "Would you like to modify --reloadcmd for ACME? (y/n): " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} Preset: systemctl reload nginx ; x-ui restart"
        echo -e "${green}\t2.${plain} Input your own command"
        echo -e "${green}\t0.${plain} Keep default reloadcmd"
        read -rp "Choose an option: " choice
        case "$choice" in
        1)
            LOGI "Reloadcmd is: systemctl reload nginx ; x-ui restart"
            reloadCmd="systemctl reload nginx ; x-ui restart"
            ;;
        2)  
            LOGD "It's recommended to put x-ui restart at the end, so it won't raise an error if other services fails"
            read -rp "Please enter your reloadcmd (example: systemctl reload nginx ; x-ui restart): " reloadCmd
            LOGI "Your reloadcmd is: ${reloadCmd}"
            ;;
        *)
            LOGI "Keep default reloadcmd"
            ;;
        esac
    fi

    # install the certificate
    local installOutput=""
    installOutput=$(~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}" 2>&1)
    local installRc=$?
    echo "${installOutput}"

    local installWroteFiles=0
    if echo "${installOutput}" | grep -q "Installing key to:" && echo "${installOutput}" | grep -q "Installing full chain to:"; then
        installWroteFiles=1
    fi

    if [[ -f "/root/cert/${domain}/privkey.pem" && -f "/root/cert/${domain}/fullchain.pem" && ( ${installRc} -eq 0 || ${installWroteFiles} -eq 1 ) ]]; then
        LOGI "Installing certificate succeeded, enabling auto renew..."
    else
        LOGE "Installing certificate failed, exiting."
        if [[ ${cert_exists} -eq 0 ]]; then
            rm -rf ~/.acme.sh/${domain}
        fi
        exit 1
    fi

    # enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        LOGE "Auto renew failed, certificate details:"
        ls -lah cert/*
        chmod 600 $certPath/privkey.pem
        chmod 644 $certPath/fullchain.pem
        exit 1
    else
        LOGI "Auto renew succeeded, certificate details:"
        ls -lah cert/*
        chmod 600 $certPath/privkey.pem
        chmod 644 $certPath/fullchain.pem
    fi

    # Prompt user to set panel paths after successful certificate installation
    read -rp "Would you like to set this certificate for the panel? (y/n): " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            LOGI "Panel paths set for domain: $domain"
            LOGI "  - Certificate File: $webCertFile"
            LOGI "  - Private Key File: $webKeyFile"
            echo -e "${green}Access URL: https://${domain}:${existing_port}${existing_webBasePath}${plain}"
            restart
        else
            LOGE "Error: Certificate or private key file not found for domain: $domain."
        fi
    else
        LOGI "Skipping panel path setting."
    fi
}

ssl_cert_issue_CF() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    LOGI "****** Instructions for Use ******"
    LOGI "Follow the steps below to complete the process:"
    LOGI "1. Cloudflare Registered E-mail."
    LOGI "2. Cloudflare Global API Key."
    LOGI "3. The Domain Name."
    LOGI "4. Once the certificate is issued, you will be prompted to set the certificate for the panel (optional)."
    LOGI "5. The script also supports automatic renewal of the SSL certificate after installation."

    confirm "Do you confirm the information and wish to proceed? [y/n]" "y"

    if [ $? -eq 0 ]; then
        # Check for acme.sh first
        if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
            echo "acme.sh could not be found. We will install it."
            install_acme
            if [ $? -ne 0 ]; then
                LOGE "Install acme failed, please check logs."
                exit 1
            fi
        fi

        CF_Domain=""

        LOGD "Please set a domain name:"
        read -rp "Input your domain here: " CF_Domain
        LOGD "Your domain name is set to: ${CF_Domain}"

        # Set up Cloudflare API details
        CF_GlobalKey=""
        CF_AccountEmail=""
        LOGD "Please set the API key:"
        read -rp "Input your key here: " CF_GlobalKey
        LOGD "Your API key is: ${CF_GlobalKey}"

        LOGD "Please set up registered email:"
        read -rp "Input your email here: " CF_AccountEmail
        LOGD "Your registered email address is: ${CF_AccountEmail}"

        # Set the default CA to Let's Encrypt
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
        if [ $? -ne 0 ]; then
            LOGE "Default CA, Let'sEncrypt fail, script exiting..."
            exit 1
        fi

        export CF_Key="${CF_GlobalKey}"
        export CF_Email="${CF_AccountEmail}"

        # Issue the certificate using Cloudflare DNS
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${CF_Domain} -d *.${CF_Domain} --log --force
        if [ $? -ne 0 ]; then
            LOGE "Certificate issuance failed, script exiting..."
            exit 1
        else
            LOGI "Certificate issued successfully, Installing..."
        fi

         # Install the certificate
        certPath="/root/cert/${CF_Domain}"
        if [ -d "$certPath" ]; then
            rm -rf ${certPath}
        fi

        mkdir -p ${certPath}
        if [ $? -ne 0 ]; then
            LOGE "Failed to create directory: ${certPath}"
            exit 1
        fi

        reloadCmd="x-ui restart"

        LOGI "Default --reloadcmd for ACME is: ${yellow}x-ui restart"
        LOGI "This command will run on every certificate issue and renew."
        read -rp "Would you like to modify --reloadcmd for ACME? (y/n): " setReloadcmd
        if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
            echo -e "\n${green}\t1.${plain} Preset: systemctl reload nginx ; x-ui restart"
            echo -e "${green}\t2.${plain} Input your own command"
            echo -e "${green}\t0.${plain} Keep default reloadcmd"
            read -rp "Choose an option: " choice
            case "$choice" in
            1)
                LOGI "Reloadcmd is: systemctl reload nginx ; x-ui restart"
                reloadCmd="systemctl reload nginx ; x-ui restart"
                ;;
            2)  
                LOGD "It's recommended to put x-ui restart at the end, so it won't raise an error if other services fails"
                read -rp "Please enter your reloadcmd (example: systemctl reload nginx ; x-ui restart): " reloadCmd
                LOGI "Your reloadcmd is: ${reloadCmd}"
                ;;
            *)
                LOGI "Keep default reloadcmd"
                ;;
            esac
        fi
        ~/.acme.sh/acme.sh --installcert -d ${CF_Domain} -d *.${CF_Domain} \
            --key-file ${certPath}/privkey.pem \
            --fullchain-file ${certPath}/fullchain.pem --reloadcmd "${reloadCmd}"
        
        if [ $? -ne 0 ]; then
            LOGE "Certificate installation failed, script exiting..."
            exit 1
        else
            LOGI "Certificate installed successfully, Turning on automatic updates..."
        fi

        # Enable auto-update
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        if [ $? -ne 0 ]; then
            LOGE "Auto update setup failed, script exiting..."
            exit 1
        else
            LOGI "The certificate is installed and auto-renewal is turned on. Specific information is as follows:"
            ls -lah ${certPath}/*
            chmod 600 ${certPath}/privkey.pem
            chmod 644 ${certPath}/fullchain.pem
        fi

        # Prompt user to set panel paths after successful certificate installation
        read -rp "Would you like to set this certificate for the panel? (y/n): " setPanel
        if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
            local webCertFile="${certPath}/fullchain.pem"
            local webKeyFile="${certPath}/privkey.pem"

            if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
                ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
                LOGI "Panel paths set for domain: $CF_Domain"
                LOGI "  - Certificate File: $webCertFile"
                LOGI "  - Private Key File: $webKeyFile"
                echo -e "${green}Access URL: https://${CF_Domain}:${existing_port}${existing_webBasePath}${plain}"
                restart
            else
                LOGE "Error: Certificate or private key file not found for domain: $CF_Domain."
            fi
        else
            LOGI "Skipping panel path setting."
        fi
    else
        show_menu
    fi
}

run_speedtest() {
    # Check if Speedtest is already installed
    if ! command -v speedtest &>/dev/null; then
        # If not installed, determine installation method
        if command -v snap &>/dev/null; then
            # Use snap to install Speedtest
            echo "Installing Speedtest using snap..."
            snap install speedtest
        else
            # Fallback to using package managers
            local pkg_manager=""
            local speedtest_install_script=""

            if command -v dnf &>/dev/null; then
                pkg_manager="dnf"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
            elif command -v yum &>/dev/null; then
                pkg_manager="yum"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
            elif command -v apt-get &>/dev/null; then
                pkg_manager="apt-get"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
            elif command -v apt &>/dev/null; then
                pkg_manager="apt"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
            fi

            if [[ -z $pkg_manager ]]; then
                echo "Error: Package manager not found. You may need to install Speedtest manually."
                return 1
            else
                echo "Installing Speedtest using $pkg_manager..."
                curl -s $speedtest_install_script | bash
                $pkg_manager install -y speedtest
            fi
        fi
    fi

    speedtest
}



ip_validation() {
    ipv6_regex="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    ipv4_regex="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)$"
}

iplimit_main() {
    echo -e "\n${green}\t1.${plain} Install Fail2ban and configure IP Limit"
    echo -e "${green}\t2.${plain} Change Ban Duration"
    echo -e "${green}\t3.${plain} Unban Everyone"
    echo -e "${green}\t4.${plain} Ban Logs"
    echo -e "${green}\t5.${plain} Ban an IP Address"
    echo -e "${green}\t6.${plain} Unban an IP Address"
    echo -e "${green}\t7.${plain} Real-Time Logs"
    echo -e "${green}\t8.${plain} Service Status"
    echo -e "${green}\t9.${plain} Service Restart"
    echo -e "${green}\t10.${plain} Uninstall Fail2ban and IP Limit"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        confirm "Proceed with installation of Fail2ban & IP Limit?" "y"
        if [[ $? == 0 ]]; then
            install_iplimit
        else
            iplimit_main
        fi
        ;;
    2)
        read -rp "Please enter new Ban Duration in Minutes [default 30]: " NUM
        if [[ $NUM =~ ^[0-9]+$ ]]; then
            create_iplimit_jails ${NUM}
            if [[ $release == "alpine" ]]; then
                rc-service fail2ban restart
            else
                systemctl restart fail2ban
            fi
        else
            echo -e "${red}${NUM} is not a number! Please, try again.${plain}"
        fi
        iplimit_main
        ;;
    3)
        confirm "Proceed with Unbanning everyone from IP Limit jail?" "y"
        if [[ $? == 0 ]]; then
            fail2ban-client reload --restart --unban 3x-ipl
            truncate -s 0 "${iplimit_banned_log_path}"
            echo -e "${green}All users Unbanned successfully.${plain}"
            iplimit_main
        else
            echo -e "${yellow}Cancelled.${plain}"
        fi
        iplimit_main
        ;;
    4)
        show_banlog
        iplimit_main
        ;;
    5)
        read -rp "Enter the IP address you want to ban: " ban_ip
        ip_validation
        if [[ $ban_ip =~ $ipv4_regex || $ban_ip =~ $ipv6_regex ]]; then
            fail2ban-client set 3x-ipl banip "$ban_ip"
            echo -e "${green}IP Address ${ban_ip} has been banned successfully.${plain}"
        else
            echo -e "${red}Invalid IP address format! Please try again.${plain}"
        fi
        iplimit_main
        ;;
    6)
        read -rp "Enter the IP address you want to unban: " unban_ip
        ip_validation
        if [[ $unban_ip =~ $ipv4_regex || $unban_ip =~ $ipv6_regex ]]; then
            fail2ban-client set 3x-ipl unbanip "$unban_ip"
            echo -e "${green}IP Address ${unban_ip} has been unbanned successfully.${plain}"
        else
            echo -e "${red}Invalid IP address format! Please try again.${plain}"
        fi
        iplimit_main
        ;;
    7)
        tail -f /var/log/fail2ban.log
        iplimit_main
        ;;
    8)
        service fail2ban status
        iplimit_main
        ;;
    9)
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban restart
        else
            systemctl restart fail2ban
        fi
        iplimit_main
        ;;
    10)
        remove_iplimit
        iplimit_main
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        iplimit_main
        ;;
    esac
}

# install_fail2ban installs fail2ban if it is missing (IP Limit and
# anti-abuse both use it).
install_fail2ban() {
    command -v fail2ban-client &>/dev/null && return 0
    echo -e "${green}Fail2ban is not installed. Installing now...!${plain}\n"

    # Check the OS and install necessary packages
    case "${release}" in
    ubuntu | debian | armbian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o DPkg::Lock::Timeout=180 update -q >/dev/null
        if [[ ${release} == debian && "${os_version}" -ge 12 ]]; then
            apt-get -o DPkg::Lock::Timeout=180 install -y -q python3-systemd >/dev/null
        fi
        apt-get -o DPkg::Lock::Timeout=180 install -y -q fail2ban >/dev/null || return 1
        # Python 3.12 dropped asynchat, which some fail2ban builds still
        # import: add it only where this one does.
        if ! python3 -c 'import fail2ban.server.asyncserver' 2>/dev/null; then
            apt-get -o DPkg::Lock::Timeout=180 install -y -q python3-pyasynchat >/dev/null 2>&1 ||
                { apt-get -o DPkg::Lock::Timeout=180 install -y -q python3-pip >/dev/null && python3 -m pip install -q pyasynchat --break-system-packages; }
        fi
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y install fail2ban
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum install epel-release -y
            yum -y install fail2ban
        else
            dnf -y install fail2ban
        fi
        ;;
    arch | manjaro | parch)
        pacman -S --noconfirm --needed fail2ban
        ;;
    alpine)
        apk add fail2ban
        ;;
    *)
        echo -e "${red}Unsupported operating system. Please check the script and install the necessary packages manually.${plain}\n"
        return 1
        ;;
    esac

    if ! command -v fail2ban-client &>/dev/null; then
        echo -e "${red}Fail2ban installation failed.${plain}\n"
        return 1
    fi

    echo -e "${green}Fail2ban installed successfully!${plain}\n"
}

install_iplimit() {
    if command -v fail2ban-client &>/dev/null; then
        echo -e "${yellow}Fail2ban is already installed.${plain}\n"
    else
        install_fail2ban || exit 1
    fi

    echo -e "${green}Configuring IP Limit...${plain}\n"

    # make sure there's no conflict for jail files
    iplimit_remove_conflicts

    # Check if log file exists
    if ! test -f "${iplimit_banned_log_path}"; then
        touch ${iplimit_banned_log_path}
    fi

    # Check if service log file exists so fail2ban won't return error
    if ! test -f "${iplimit_log_path}"; then
        touch ${iplimit_log_path}
    fi

    # Create the iplimit jail files
    # we didn't pass the bantime here to use the default value
    create_iplimit_jails

    # Launching fail2ban
    if [[ $release == "alpine" ]]; then
        if [[ $(rc-service fail2ban status | grep -F 'status: started' -c) == 0 ]]; then
            rc-service fail2ban start
        else
            rc-service fail2ban restart
        fi
        rc-update add fail2ban
    else
        if ! systemctl is-active --quiet fail2ban; then
            systemctl start fail2ban
        else
            systemctl restart fail2ban
        fi
        systemctl enable fail2ban
    fi

    echo -e "${green}IP Limit installed and configured successfully!${plain}\n"
    before_show_menu
}

remove_iplimit() {
    echo -e "${green}\t1.${plain} Only remove IP Limit configurations"
    echo -e "${green}\t2.${plain} Uninstall Fail2ban and IP Limit"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " num
    case "$num" in
    1)
        rm -f /etc/fail2ban/filter.d/3x-ipl.conf
        rm -f /etc/fail2ban/action.d/3x-ipl.conf
        rm -f /etc/fail2ban/jail.d/3x-ipl.conf
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban restart
        else
            systemctl restart fail2ban
        fi
        echo -e "${green}IP Limit removed successfully!${plain}\n"
        before_show_menu
        ;;
    2)
        rm -rf /etc/fail2ban
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban stop
        else
            systemctl stop fail2ban
        fi
        case "${release}" in
        ubuntu | debian | armbian)
            apt-get remove -y fail2ban
            apt-get purge -y fail2ban -y
            apt-get autoremove -y
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf remove fail2ban -y
            dnf autoremove -y
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then    
                yum remove fail2ban -y
                yum autoremove -y
            else
                dnf remove fail2ban -y
                dnf autoremove -y
            fi
            ;;
        arch | manjaro | parch)
            pacman -Rns --noconfirm fail2ban
            ;;
        alpine)
            apk del fail2ban
            ;;
        *)
            echo -e "${red}Unsupported operating system. Please uninstall Fail2ban manually.${plain}\n"
            exit 1
            ;;
        esac
        echo -e "${green}Fail2ban and IP Limit removed successfully!${plain}\n"
        before_show_menu
        ;;
    0)
        show_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        remove_iplimit
        ;;
    esac
}

show_banlog() {
    local system_log="/var/log/fail2ban.log"

    echo -e "${green}Checking ban logs...${plain}\n"

    if [[ $release == "alpine" ]]; then
        if [[ $(rc-service fail2ban status | grep -F 'status: started' -c) == 0 ]]; then
            echo -e "${red}Fail2ban service is not running!${plain}\n"
            return 1
        fi
    else
        if ! systemctl is-active --quiet fail2ban; then
            echo -e "${red}Fail2ban service is not running!${plain}\n"
            return 1
        fi
    fi

    if [[ -f "$system_log" ]]; then
        echo -e "${green}Recent system ban activities from fail2ban.log:${plain}"
        grep "3x-ipl" "$system_log" | grep -E "Ban|Unban" | tail -n 10 || echo -e "${yellow}No recent system ban activities found${plain}"
        echo ""
    fi

    if [[ -f "${iplimit_banned_log_path}" ]]; then
        echo -e "${green}3X-IPL ban log entries:${plain}"
        if [[ -s "${iplimit_banned_log_path}" ]]; then
            grep -v "INIT" "${iplimit_banned_log_path}" | tail -n 10 || echo -e "${yellow}No ban entries found${plain}"
        else
            echo -e "${yellow}Ban log file is empty${plain}"
        fi
    else
        echo -e "${red}Ban log file not found at: ${iplimit_banned_log_path}${plain}"
    fi

    echo -e "\n${green}Current jail status:${plain}"
    fail2ban-client status 3x-ipl || echo -e "${yellow}Unable to get jail status${plain}"
}

create_iplimit_jails() {
    # Use default bantime if not passed => 30 minutes
    local bantime="${1:-30}"

    # Uncomment 'allowipv6 = auto' in fail2ban.conf
    sed -i 's/#allowipv6 = auto/allowipv6 = auto/g' /etc/fail2ban/fail2ban.conf

    # On Debian 12+ fail2ban's default backend should be changed to systemd
    if [[  "${release}" == "debian" && ${os_version} -ge 12 ]]; then
        sed -i '0,/action =/s/backend = auto/backend = systemd/' /etc/fail2ban/jail.conf
    fi

    cat << EOF > /etc/fail2ban/jail.d/3x-ipl.conf
[3x-ipl]
enabled=true
backend=auto
filter=3x-ipl
action=3x-ipl
logpath=${iplimit_log_path}
maxretry=2
findtime=32
bantime=${bantime}m
EOF

    cat << EOF > /etc/fail2ban/filter.d/3x-ipl.conf
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*Disconnecting OLD IP\s*=\s*<ADDR>\s*\|\|\s*Timestamp\s*=\s*\d+
ignoreregex =
EOF

    cat << EOF > /etc/fail2ban/action.d/3x-ipl.conf
[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   BAN   [Email] = <F-USER> [IP] = <ip> banned for <bantime> seconds." >> ${iplimit_banned_log_path}

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   UNBAN   [Email] = <F-USER> [IP] = <ip> unbanned." >> ${iplimit_banned_log_path}

[Init]
name = default
protocol = tcp
chain = INPUT
EOF

    echo -e "${green}Ip Limit jail files created with a bantime of ${bantime} minutes.${plain}"
}

iplimit_remove_conflicts() {
    local jail_files=(
        /etc/fail2ban/jail.conf
        /etc/fail2ban/jail.local
    )

    for file in "${jail_files[@]}"; do
        # Check for [3x-ipl] config in jail file then remove it
        if test -f "${file}" && grep -qw '3x-ipl' ${file}; then
            sed -i "/\[3x-ipl\]/,/^$/d" ${file}
            echo -e "${yellow}Removing conflicts of [3x-ipl] in jail (${file})!${plain}\n"
        fi
    done
}

SSH_port_forwarding() {
    local URL_lists=(
        "https://api4.ipify.org"
		"https://ipv4.icanhazip.com"
		"https://v4.api.ipinfo.io/ip"
		"https://ipv4.myexternalip.com/raw"
		"https://4.ident.me"
		"https://check-host.net/ip"
    )
    local server_ip=""
    for ip_address in "${URL_lists[@]}"; do
        local response=$(curl -s -w "\n%{http_code}" --max-time 3 "${ip_address}" 2>/dev/null)
        local http_code=$(echo "$response" | tail -n1)
        local ip_result=$(echo "$response" | head -n-1 | tr -d '[:space:]')
        if [[ "${http_code}" == "200" && -n "${ip_result}" ]]; then
            server_ip="${ip_result}"
            break
        fi
    done

    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_listenIP=$(${xui_folder}/x-ui setting -getListen true | grep -Eo 'listenIP: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep -Eo 'cert: .+' | awk '{print $2}')
    local existing_key=$(${xui_folder}/x-ui setting -getCert true | grep -Eo 'key: .+' | awk '{print $2}')

    local config_listenIP=""
    local listen_choice=""

    if [[ -n "$existing_cert" && -n "$existing_key" ]]; then
        echo -e "${green}Panel is secure with SSL.${plain}"
        before_show_menu
    fi
    if [[ -z "$existing_cert" && -z "$existing_key" && (-z "$existing_listenIP" || "$existing_listenIP" == "0.0.0.0") ]]; then
        echo -e "\n${red}Warning: No Cert and Key found! The panel is not secure.${plain}"
        echo "Please obtain a certificate or set up SSH port forwarding."
    fi

    if [[ -n "$existing_listenIP" && "$existing_listenIP" != "0.0.0.0" && (-z "$existing_cert" && -z "$existing_key") ]]; then
        echo -e "\n${green}Current SSH Port Forwarding Configuration:${plain}"
        echo -e "Standard SSH command:"
        echo -e "${yellow}ssh -L 2222:${existing_listenIP}:${existing_port} root@${server_ip}${plain}"
        echo -e "\nIf using SSH key:"
        echo -e "${yellow}ssh -i <sshkeypath> -L 2222:${existing_listenIP}:${existing_port} root@${server_ip}${plain}"
        echo -e "\nAfter connecting, access the panel at:"
        echo -e "${yellow}http://localhost:2222${existing_webBasePath}${plain}"
    fi

    echo -e "\nChoose an option:"
    echo -e "${green}1.${plain} Set listen IP"
    echo -e "${green}2.${plain} Clear listen IP"
    echo -e "${green}0.${plain} Back to Main Menu"
    read -rp "Choose an option: " num

    case "$num" in
    1)
        if [[ -z "$existing_listenIP" || "$existing_listenIP" == "0.0.0.0" ]]; then
            echo -e "\nNo listenIP configured. Choose an option:"
            echo -e "1. Use default IP (127.0.0.1)"
            echo -e "2. Set a custom IP"
            read -rp "Select an option (1 or 2): " listen_choice

            config_listenIP="127.0.0.1"
            [[ "$listen_choice" == "2" ]] && read -rp "Enter custom IP to listen on: " config_listenIP

            ${xui_folder}/x-ui setting -listenIP "${config_listenIP}" >/dev/null 2>&1
            echo -e "${green}listen IP has been set to ${config_listenIP}.${plain}"
            echo -e "\n${green}SSH Port Forwarding Configuration:${plain}"
            echo -e "Standard SSH command:"
            echo -e "${yellow}ssh -L 2222:${config_listenIP}:${existing_port} root@${server_ip}${plain}"
            echo -e "\nIf using SSH key:"
            echo -e "${yellow}ssh -i <sshkeypath> -L 2222:${config_listenIP}:${existing_port} root@${server_ip}${plain}"
            echo -e "\nAfter connecting, access the panel at:"
            echo -e "${yellow}http://localhost:2222${existing_webBasePath}${plain}"
            restart
        else
            config_listenIP="${existing_listenIP}"
            echo -e "${green}Current listen IP is already set to ${config_listenIP}.${plain}"
        fi
        ;;
    2)
        ${xui_folder}/x-ui setting -listenIP 0.0.0.0 >/dev/null 2>&1
        echo -e "${green}Listen IP has been cleared.${plain}"
        restart
        ;;
    0)
        show_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        SSH_port_forwarding
        ;;
    esac
}

# import_db replaces the panel database with one downloaded from a URL. The
# binary does the download, the checks and the swap, which it refuses while the
# panel has the database open; so the panel is stopped around it and started
# again whether or not the import worked.
import_db() {
    local url="$1"
    if [[ -z "$url" ]]; then
        echo -e "${red}Usage: x-ui db=\"https://example.com/x-ui.db\"${plain}"
        return 1
    fi

    echo -e "${yellow}Stopping the panel for the import...${plain}"
    if [[ $release == "alpine" ]]; then
        rc-service x-ui stop >/dev/null 2>&1
    else
        systemctl stop x-ui
    fi

    local ok=0
    /usr/local/x-ui/x-ui "db=${url}" || ok=1

    if [[ $ok == 0 ]]; then
        echo -e "${green}Starting the panel on the new database...${plain}"
    else
        echo -e "${red}The import failed; starting the panel on its old database...${plain}"
    fi
    if [[ $release == "alpine" ]]; then
        rc-service x-ui start >/dev/null 2>&1
    else
        systemctl start x-ui
    fi
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        echo -e "${green}Panel started.${plain}"
    else
        echo -e "${red}The panel did not come back up. Check: x-ui log${plain}"
        return 1
    fi
    return $ok
}

show_usage() {
    echo -e "┌────────────────────────────────────────────────────────────────┐
│  ${blue}x-ui control menu usages (subcommands):${plain}                       │
│                                                                │
│  ${blue}x-ui${plain}                       - Admin Management Script          │
│  ${blue}x-ui start${plain}                 - Start                            │
│  ${blue}x-ui stop${plain}                  - Stop                             │
│  ${blue}x-ui restart${plain}               - Restart                          │
│  ${blue}x-ui restart-xray${plain}          - Restart Xray                     │
│  ${blue}x-ui status${plain}                - Current Status                   │
│  ${blue}x-ui settings${plain}              - Current Settings                 │
│  ${blue}x-ui setting -h${plain}            - Change settings (the binary)     │
│  ${blue}x-ui enable${plain}                - Enable Autostart on OS Startup   │
│  ${blue}x-ui disable${plain}               - Disable Autostart on OS Startup  │
│  ${blue}x-ui log${plain}                   - Check logs                       │
│  ${blue}x-ui banlog${plain}                - Check Fail2ban ban logs          │
│  ${blue}x-ui update${plain}                - Update                           │
│  ${blue}x-ui update-all-geofiles${plain}   - Update all geo files             │
│  ${blue}x-ui anti-abuse${plain}            - Anti-abuse (on, status, off)     │
│  ${blue}x-ui protect${plain}               - Direct guard, speed tests        │
│  ${blue}x-ui dns${plain}                   - DNS cache (on, status, off)      │
│  ${blue}x-ui db=\"<url>\"${plain}            - Replace database from a URL      │
│  ${blue}x-ui install${plain}               - Install                          │
│  ${blue}x-ui uninstall${plain}             - Uninstall                        │
└────────────────────────────────────────────────────────────────┘"
}

show_menu() {
    echo -e "
╔────────────────────────────────────────────────╗
│   ${green}3X-UI Panel Management Script${plain}                │
│   ${green}0.${plain} Exit Script                               │
│────────────────────────────────────────────────│
│   ${green}1.${plain} Install                                   │
│   ${green}2.${plain} Update                                    │
│   ${green}3.${plain} Update Menu                               │
│   ${green}4.${plain} Legacy Version                            │
│   ${green}5.${plain} Uninstall                                 │
│────────────────────────────────────────────────│
│   ${green}6.${plain} Reset Username & Password                 │
│   ${green}7.${plain} Reset Web Base Path                       │
│   ${green}8.${plain} Reset Settings                            │
│   ${green}9.${plain} Change Port                               │
│  ${green}10.${plain} View Current Settings                     │
│────────────────────────────────────────────────│
│  ${green}11.${plain} Start                                     │
│  ${green}12.${plain} Stop                                      │
│  ${green}13.${plain} Restart                                   │
|  ${green}14.${plain} Restart Xray                              │
│  ${green}15.${plain} Check Status                              │
│  ${green}16.${plain} Logs Management                           │
│────────────────────────────────────────────────│
│  ${green}17.${plain} Enable Autostart                          │
│  ${green}18.${plain} Disable Autostart                         │
│────────────────────────────────────────────────│
│  ${green}19.${plain} SSL Certificate Management                │
│  ${green}20.${plain} Cloudflare SSL Certificate                │
│  ${green}21.${plain} IP Limit Management                       │
│  ${green}22.${plain} Firewall Management                       │
│  ${green}23.${plain} SSH Port Forwarding Management            │
│────────────────────────────────────────────────│
│  ${green}24.${plain} Enable BBR                                │
│  ${green}25.${plain} Update Geo Files                          │
│  ${green}26.${plain} Speedtest by Ookla                        │
│  ${green}27.${plain} Anti-Abuse                                │
│  ${green}28.${plain} DNS Cache                                 │
╚────────────────────────────────────────────────╝
"
    show_status
    echo && read -rp "Please enter your selection [0-28]: " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && update_menu
        ;;
    4)
        check_install && legacy_version
        ;;
    5)
        check_install && uninstall
        ;;
    6)
        check_install && reset_user
        ;;
    7)
        check_install && reset_webbasepath
        ;;
    8)
        check_install && reset_config
        ;;
    9)
        check_install && set_port
        ;;
    10)
        check_install && check_config
        ;;
    11)
        check_install && start
        ;;
    12)
        check_install && stop
        ;;
    13)
        check_install && restart
        ;;
    14)
        check_install && restart_xray
        ;;
    15)
        check_install && status
        ;;
    16)
        check_install && show_log
        ;;
    17)
        check_install && enable
        ;;
    18)
        check_install && disable
        ;;
    19)
        ssl_cert_issue_main
        ;;
    20)
        ssl_cert_issue_CF
        ;;
    21)
        iplimit_main
        ;;
    22)
        firewall_menu
        ;;
    23)
        SSH_port_forwarding
        ;;
    24)
        bbr_menu
        ;;
    25)
        update_geo
        ;;
    26)
        run_speedtest
        ;;
    27)
        anti_abuse_menu
        ;;
    28)
        dns_menu
        ;;
    *)
        LOGE "Please enter the correct number [0-28]"
        ;;
    esac
}

if [[ $# -gt 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start 0
        ;;
    "stop")
        check_install 0 && stop 0
        ;;
    "restart")
        check_install 0 && restart 0
        ;;
    "restart-xray")
        check_install 0 && restart_xray 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "settings")
        check_install 0 && check_config 0
        ;;
    "enable")
        check_install 0 && enable 0
        ;;
    "disable")
        check_install 0 && disable 0
        ;;
    "log")
        check_install 0 && show_log 0
        ;;
    "banlog")
        check_install 0 && show_banlog 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "legacy")
        check_install 0 && legacy_version 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    "update-all-geofiles")
        if check_install 0; then
            geo_changed=0
            update_all_geofiles
            rc=$?
            geo_done $rc
            exit $rc
        fi
        ;;
    "dns")
        dns "${2:-}"
        exit $?
        ;;
    "host-setup")
        # The installer's: BBR (install and update) and swap (install).
        host_setup "${2:-update}"
        exit $?
        ;;
    "anti-abuse")
        anti_abuse "${2:-}" "${3:-}"
        exit $?
        ;;
    "protect")
        protect "${2:-}"
        exit $?
        ;;
    "setting" | "migrate" | "cert")
        # Passed straight to the panel binary (x-ui setting -show true ...).
        check_install 0 && { ${xui_folder}/x-ui "$@"; exit $?; }
        ;;
    "db="*)
        check_install 0 && import_db "${1#db=}"
        ;;
    "db")
        check_install 0 && import_db "${2:-}"
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi
