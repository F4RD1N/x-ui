#!/bin/bash
# Fast checks of the installer side, no root and no containers needed:
#
#   tests/install/check.sh
#
#   1. the "x-ui tune" unit tests: every formula at every machine size, the
#      sysctl.d / unit parsers, the never-lower property, idempotence, exact
#      revert, containers (read-only /proc/sys, LXC), legacy files, services;
#      all against fake /proc, /sys and /etc trees;
#   2. bash -n and shellcheck (when available) on every shell script;
#   3. x-ui.sh's command line in a scratch folder with a fake binary: the
#      usage screen prints, and setting/tune reach the binary.
#
# The live checks are separate: netns.sh (root, a throwaway network
# namespace) and docker-install.sh (systemd containers, a release tarball).
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
fail=0
step() { echo "== $*"; }
bad() { echo "FAIL: $*"; fail=1; }

step "go test ./util/tune/"
nice -n 10 go test -count=1 ./util/tune/ || bad "util/tune tests"

step "bash -n"
for f in install.sh update.sh x-ui.sh build.sh tests/install/*.sh; do
    bash -n "$f" || bad "bash -n $f"
done
sh -n x-ui.rc DockerInit.sh DockerEntrypoint.sh || bad "sh -n"

SC=${SHELLCHECK:-$(command -v shellcheck || true)}
if [[ -n "$SC" ]]; then
    step "shellcheck (warnings)"
    "$SC" -S warning install.sh update.sh build.sh tests/install/*.sh || bad "shellcheck"
    "$SC" -S warning -s sh -e SC2034 x-ui.rc DockerInit.sh DockerEntrypoint.sh || bad "shellcheck sh"
    # x-ui.sh is mostly upstream code: only errors fail the check.
    "$SC" -S error x-ui.sh || bad "shellcheck x-ui.sh"
else
    echo "(shellcheck not found; set SHELLCHECK=/path/to/shellcheck)"
fi

step "x-ui.sh command line"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/xui" "$tmp/svc" "$tmp/log" "$tmp/cwd"
printf '#!/bin/sh\necho "BIN: $*"\n' > "$tmp/xui/x-ui"
chmod +x "$tmp/xui/x-ui"
touch "$tmp/svc/x-ui.service"
xui() { (cd "$tmp/cwd" && XUI_MAIN_FOLDER="$tmp/xui" XUI_SERVICE="$tmp/svc" XUI_LOG_FOLDER="$tmp/log" bash "$OLDPWD/x-ui.sh" "$@" 2>&1); }
if [[ $EUID -eq 0 ]]; then
    out=$(xui help)
    grep -q 'x-ui tune' <<<"$out" && grep -q 'db="<url>"' <<<"$out" || bad "usage screen: $out"
    [[ -z $(ls -A "$tmp/cwd") ]] || bad "usage screen created files: $(ls -A "$tmp/cwd")"
    [[ $(xui setting -xrayEgress xray-1=192.0.2.1) == "BIN: setting -xrayEgress xray-1=192.0.2.1" ]] || bad "setting passthrough"
    [[ $(xui tune status --json) == "BIN: tune status --json" ]] || bad "tune passthrough"
    grep -q 'XUI_MODE=update run_installer update' x-ui.sh || bad "x-ui update must run install.sh in update mode"
else
    echo "(x-ui.sh refuses to run without root; skipped)"
fi

if [[ $fail -eq 0 ]]; then echo "check.sh: PASS"; else echo "check.sh: FAILED"; fi
exit $fail
