#!/bin/sh

# Start fail2ban
if [ "$XUI_ENABLE_FAIL2BAN" = "true" ]; then
    fail2ban-client -x start
fi

# A new database gets this fork's defaults, the same as install.sh (username
# fardin, password fardin, port 60000, path /hetzner/); an existing one is
# left as it is.
if [ ! -f /etc/x-ui/x-ui.db ]; then
    /app/x-ui migrate >/dev/null 2>&1
    /app/x-ui setting -username "${XUI_USER:-fardin}" -password "${XUI_PASS:-fardin}" \
        -port "${XUI_PORT:-60000}" -webBasePath "${XUI_PATH:-hetzner}" >/dev/null \
        || echo "x-ui: could not apply the default settings" >&2
fi

# Run x-ui
exec /app/x-ui
