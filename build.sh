#!/bin/bash
# Builds the panel and the bundled Xray core into a release tarball.
#
# The core is built from ./core, the dialect fork vendored in this repository.
# It is not downloaded, and the panel has no way to replace it: one panel build
# ships exactly one core, which is what the dialect feature requires -- a core
# that does not know dialects would silently accept stock VLESS only.
set -euo pipefail

cd "$(dirname "$0")"
ARCHES="${ARCHES:-amd64 arm64}"
OUT="${OUT:-$PWD/dist}"
GEO_SRC="${GEO_SRC:-}"

rm -rf "$OUT" && mkdir -p "$OUT"

geo_files() {
    local dest="$1"
    if [[ -n "$GEO_SRC" && -d "$GEO_SRC" ]]; then
        echo "  geo: copying from $GEO_SRC"
        cp -f "$GEO_SRC"/geoip.dat "$GEO_SRC"/geosite.dat "$dest"/ 2>/dev/null || true
        for extra in geoip_IR geosite_IR geoip_RU geosite_RU; do
            [[ -f "$GEO_SRC/$extra.dat" ]] && cp -f "$GEO_SRC/$extra.dat" "$dest"/
        done
        return
    fi
    echo "  geo: downloading"
    curl -4fsSL -o "$dest/geoip.dat"       https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -4fsSL -o "$dest/geosite.dat"     https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    curl -4fsSL -o "$dest/geoip_IR.dat"    https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
    curl -4fsSL -o "$dest/geosite_IR.dat"  https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
    curl -4fsSL -o "$dest/geoip_RU.dat"    https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -4fsSL -o "$dest/geosite_RU.dat"  https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
}

for ARCH in $ARCHES; do
    echo "==> building $ARCH"
    STAGE="$OUT/stage-$ARCH/x-ui"
    mkdir -p "$STAGE/bin"

    # The panel needs cgo: its SQLite driver (mattn/go-sqlite3) is a cgo
    # binding and compiles to a stub that refuses to open a database without it.
    echo "  panel"
    cc=""
    if [[ "$ARCH" != "$(go env GOHOSTARCH)" ]]; then
        case "$ARCH" in
            arm64) cc="aarch64-linux-gnu-gcc" ;;
            amd64) cc="x86_64-linux-gnu-gcc" ;;
        esac
        if ! command -v "$cc" >/dev/null 2>&1; then
            echo "  !! skipping $ARCH: cgo cross-compiler $cc not installed"
            rm -rf "$OUT/stage-$ARCH"
            continue
        fi
    fi
    # env, not a bare assignment prefix: a CC= produced by expansion is not
    # recognised as an assignment and would be run as a command.
    env CGO_ENABLED=1 GOOS=linux GOARCH="$ARCH" ${cc:+CC="$cc"} \
        go build -trimpath -ldflags "-s -w" -o "$STAGE/x-ui" .

    echo "  core (dialect fork)"
    ( cd core && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath -ldflags "-s -w" -o "$STAGE/bin/xray-linux-$ARCH" ./main )

    geo_files "$STAGE/bin"

    cp x-ui.sh "$STAGE/"
    cp x-ui.service.debian x-ui.service.arch x-ui.service.rhel x-ui.rc "$STAGE/" 2>/dev/null || true
    chmod +x "$STAGE/x-ui" "$STAGE/x-ui.sh" "$STAGE/bin/xray-linux-$ARCH"

    tar -C "$OUT/stage-$ARCH" -czf "$OUT/x-ui-linux-$ARCH.tar.gz" x-ui
    rm -rf "$OUT/stage-$ARCH"
    echo "  -> $OUT/x-ui-linux-$ARCH.tar.gz"
done

ls -la "$OUT"
