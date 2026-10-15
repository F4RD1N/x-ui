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

    # Undo the server tuning (sysctl file, service drop-in, swapfile...).
    if [[ -x ${xui_folder}/x-ui ]]; then
        ${xui_folder}/x-ui tune revert --purge
    fi
    if [[ -f $anti_abuse_unit || -f $anti_abuse_jail ]]; then
        anti_abuse_off
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
    else
        ${xui_folder}/x-ui setting -port ${port}
        echo -e "The port is set, Please restart the panel now, and use the new port ${green}${port}${plain} to access web panel"
        confirm_restart
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

# Server tuning is done by the panel binary ("x-ui tune"), the same code the
# installer and the service's start run. It only raises limits and can be
# undone exactly.
tune_menu() {
    echo -e "${green}\t1.${plain} Show tuning status"
    echo -e "${green}\t2.${plain} Apply tuning"
    echo -e "${green}\t3.${plain} Revert tuning (and keep it off)"
    echo -e "${green}\t4.${plain} Raise NIC queues now (the link resets for a few seconds)"
    echo -e "${green}\t5.${plain} Diagnostics"
    echo -e "${green}\t0.${plain} Back to Main Menu"
    read -rp "Choose an option: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        ${xui_folder}/x-ui tune status
        before_show_menu
        ;;
    2)
        ${xui_folder}/x-ui tune apply && confirm_restart
        before_show_menu
        ;;
    3)
        ${xui_folder}/x-ui tune revert
        before_show_menu
        ;;
    4)
        # The plan first; the raise itself resets the link, so it is asked.
        ${xui_folder}/x-ui tune queues
        if confirm "Raise the queues now? The link goes down for a few seconds" "n"; then
            ${xui_folder}/x-ui tune queues --now
        fi
        before_show_menu
        ;;
    5)
        ${xui_folder}/x-ui diag
        before_show_menu
        ;;
    *)
        echo -e "${red}Invalid option. Please select a valid number.${plain}\n"
        tune_menu
        ;;
    esac
}

# Anti-abuse keeps the server's IPs out of abuse reports. An nftables table
# refuses outgoing connections to the ports brute-force bots and spammers
# use, to private networks through the uplink (a hoster's "netscan"), and to
# new destinations faster than real users reach them (port and net scans),
# and, for a while, to hosts that do not answer this server at all. fail2ban
# bans an IP after 2 failed SSH logins. Nothing here uses conntrack, so it
# costs nothing on a busy server. "x-ui anti-abuse off" undoes it all.
anti_abuse_nft="/etc/x-ui/anti-abuse.nft"
anti_abuse_unit="/etc/systemd/system/x-ui-anti-abuse.service"
anti_abuse_check_unit="/etc/systemd/system/x-ui-anti-abuse-check.service"
anti_abuse_check_timer="/etc/systemd/system/x-ui-anti-abuse-check.timer"
anti_abuse_jail="/etc/fail2ban/jail.d/x-ui-anti-abuse.conf"
anti_abuse_table="xui_anti_abuse"
# SSH, Telnet, SMTP, MS-RPC, NetBIOS, SMB, MSSQL, Telnet, RDP, VNC
anti_abuse_tcp_ports="22, 23, 25, 135, 139, 445, 1433, 2323, 3389, 5900"
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
	counter private_nets { }
	counter scan_wide { }
	counter scan_deep { }
	counter dead_hosts { }

	chain output {
		type filter hook output priority filter; policy accept;
		oifname "lo" accept
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
        apt-get update && apt-get install -y "$1"
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
anti_abuse_ssh_jail() {
    local ports unit client="" ignore backend=""
    if ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then
        LOGI "No SSH server here, so no SSH ban is needed."
        return 0
    fi
    install_fail2ban || return 1
    ports=$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk '$1 == "port" { print $2 }' | sort -un | paste -sd, -)
    [[ -n $ports ]] || ports=ssh
    # Never banned: loopback, what the admin already lists elsewhere, and
    # the address this is run from.
    [[ -n ${SSH_CLIENT:-} ]] && client=${SSH_CLIENT%% *}
    ignore=$(
        {
            echo "127.0.0.1/8 ::1 ${client}"
            for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.d/*.local; do
                [[ -f $f && $f != "$anti_abuse_jail" ]] && sed -n 's/^[[:space:]]*ignoreip[[:space:]]*=//p' "$f"
            done
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
    cat >"$anti_abuse_jail" <<EOF
# Written by "x-ui anti-abuse"; "x-ui anti-abuse off" removes it.
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
        [[ $(fail2ban-client get sshd maxretry 2>/dev/null) == 2 ]] && return 0
        sleep 1
    done
    LOGE "fail2ban's SSH jail did not start (see: journalctl -u fail2ban)."
    return 1
}

anti_abuse_on() {
    local nft rc=0
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
ExecReload=${nft} -f ${anti_abuse_nft}
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
    systemctl daemon-reload
    systemctl enable x-ui-anti-abuse >/dev/null 2>&1
    systemctl restart x-ui-anti-abuse || { LOGE "x-ui-anti-abuse did not start (see: systemctl status x-ui-anti-abuse)."; return 1; }
    systemctl enable --now x-ui-anti-abuse-check.timer >/dev/null 2>&1 || rc=1
    anti_abuse_ssh_jail || rc=1

    echo -e "${green}Anti-abuse is on:${plain}
  Refused: outgoing TCP ${anti_abuse_tcp_ports} and UDP ${anti_abuse_udp_ports}
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
    local waiting ip set
    ss -Htn state syn-sent 2>/dev/null | awk '{ print $4 }' |
        sed -E 's/:[0-9]+$//; s/^\[(::ffff:)?//; s/\]$//' | sort | uniq -c |
        awk -v n="$anti_abuse_dead_waiting" '$1 >= n { print $1, $2 }' |
        while read -r waiting ip; do
            # One working connection means it answers: busy, not dead.
            [[ -n $(ss -Htn state established dst "$ip" 2>/dev/null | head -1) ]] && continue
            set=dead4
            [[ $ip == *:* ]] && set=dead6
            if nft add element inet "$anti_abuse_table" "$set" "{ $ip }" 2>/dev/null; then
                logger -t x-ui-anti-abuse "refusing $ip for ${anti_abuse_dead_for}: $waiting connection attempts waiting, none working"
            fi
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
        echo -e "Anti-abuse: ${red}off${plain} (turn it on: x-ui anti-abuse)"
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
    if [[ -f $anti_abuse_jail ]] && command -v fail2ban-client >/dev/null 2>&1; then
        fail2ban-client status sshd 2>/dev/null | awk -F':\t' '
            /Currently banned/ { now = $2 } /Total banned/ { total = $2 } /Total failed/ { failed = $2 }
            END { printf "  SSH bans:         %s now, %s in total (%s failed logins)\n", now, total, failed }'
    else
        echo "  SSH bans:         off"
    fi
}

anti_abuse_off() {
    if [[ -f $anti_abuse_check_timer ]]; then
        systemctl disable --now x-ui-anti-abuse-check.timer >/dev/null 2>&1
        rm -f "$anti_abuse_check_timer" "$anti_abuse_check_unit"
    fi
    if [[ -f $anti_abuse_unit ]]; then
        systemctl disable --now x-ui-anti-abuse >/dev/null 2>&1
        rm -f "$anti_abuse_unit"
    fi
    systemctl daemon-reload 2>/dev/null
    command -v nft >/dev/null 2>&1 && nft delete table inet "$anti_abuse_table" 2>/dev/null
    rm -f "$anti_abuse_nft"
    if [[ -f $anti_abuse_jail ]]; then
        rm -f "$anti_abuse_jail"
        systemctl is-active --quiet fail2ban && fail2ban-client reload >/dev/null
    fi
    LOGI "Anti-abuse is off."
}

# anti_abuse runs "x-ui anti-abuse [on|status|off|rules|check]" (check is
# the timer's).
anti_abuse() {
    case "${1:-on}" in
    on) anti_abuse_on ;;
    status) anti_abuse_status ;;
    off) anti_abuse_off ;;
    rules) anti_abuse_rules ;;
    check) anti_abuse_check ;;
    *)
        echo "Usage: x-ui anti-abuse [on|status|off|rules]"
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
    ubuntu)
        apt-get update
        if [[ "${os_version}" -ge 24 ]]; then
            apt-get install python3-pip -y
            python3 -m pip install pyasynchat --break-system-packages
        fi
        apt-get install fail2ban -y
        ;;
    debian)
        apt-get update
        if [ "$os_version" -ge 12 ]; then
            apt-get install -y python3-systemd
        fi
        apt-get install -y fail2ban
        ;;
    armbian)
        apt-get update && apt-get install fail2ban -y
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update && dnf -y install fail2ban
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum update -y && yum install epel-release -y
            yum -y install fail2ban
        else
            dnf -y update && dnf -y install fail2ban
        fi
        ;;
    arch | manjaro | parch)
        pacman -Syu --noconfirm fail2ban
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
│  ${blue}x-ui tune${plain}                  - Server tuning (x-ui tune -h)     │
│  ${blue}x-ui diag${plain}                  - Server diagnostics (x-ui diag -h)│
│  ${blue}x-ui anti-abuse${plain}            - Anti-abuse (status, off)         │
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
│  ${green}24.${plain} Server Tuning                             │
│  ${green}25.${plain} Update Geo Files                          │
│  ${green}26.${plain} Speedtest by Ookla                        │
│  ${green}27.${plain} Anti-Abuse                                │
╚────────────────────────────────────────────────╝
"
    show_status
    echo && read -rp "Please enter your selection [0-27]: " num

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
        check_install && tune_menu
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
    *)
        LOGE "Please enter the correct number [0-27]"
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
    "tune" | "diag")
        check_install 0 && { ${xui_folder}/x-ui "$@"; exit $?; }
        ;;
    "anti-abuse")
        anti_abuse "${2:-}"
        exit $?
        ;;
    "setting" | "migrate" | "cert")
        # Passed straight to the panel binary (x-ui setting -xrayEgress ...).
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
