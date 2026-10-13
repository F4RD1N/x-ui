#!/bin/bash
# Updates an installed x-ui (dialect build) in place: the panel and its core
# are replaced, the username, password, port, path and database are kept, and
# the server tuning is re-applied. It does the same as "x-ui update" and the
# panel's Update button: all of them run this fork's install.sh in update mode.
#
#   bash update.sh            update to the latest release
#   bash update.sh tag=<tag>  update to a given release
set -uo pipefail

[[ $EUID -ne 0 ]] && { echo "Run this as root." >&2; exit 1; }

script=$(mktemp) || exit 1
trap 'rm -f "$script"' EXIT
curl -4fsSL -o "$script" https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh \
    || { echo "Could not download install.sh from GitHub." >&2; exit 1; }
XUI_MODE=update bash "$script" update "$@"
