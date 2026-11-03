#!/bin/sh
# Build the complete panel and the matching local core. No stock core or
# external protocol helper is downloaded into this image.
set -eu

case "${1-}" in
    amd64|arm64) target_arch="$1" ;;
    *)
        echo "Docker target architecture must be amd64 or arm64." >&2
        exit 1
        ;;
esac

cd "$(dirname "$0")"
project_root=$(pwd -P)
host_arch=$(go env GOHOSTARCH)
if [ "$host_arch" != "$target_arch" ]; then
    echo "Build this image with --platform linux/$target_arch so the panel's C compiler matches its target." >&2
    exit 1
fi

build_jobs=${GO_BUILD_PARALLELISM:-2}
case "$build_jobs" in
    1|2) ;;
    *) echo "GO_BUILD_PARALLELISM must be 1 or 2." >&2; exit 1 ;;
esac
GOMAXPROCS=${GOMAXPROCS:-2}
export GOMAXPROCS

stage=$(mktemp -d "$project_root/.docker-build-stage.XXXXXX")
cleanup() {
    if [ -n "$stage" ]; then rm -rf "$stage"; fi
}
trap cleanup 0
trap 'exit 1' 1 2 3 15
mkdir -p "$stage/bin" "$stage/licenses/core"

# The SQLite panel binding requires cgo; the native protocol core does not.
# Building '.' is essential: main.go uses helpers in adjacent source files.
env CGO_ENABLED=1 GOOS=linux GOARCH="$target_arch" \
    go build -trimpath -p "$build_jobs" -ldflags '-s -w' -o "$stage/x-ui" .
(
    cd "$project_root/core"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" \
        go build -trimpath -p "$build_jobs" -ldflags '-s -w' \
        -o "$stage/bin/xray-linux-$target_arch" ./main
)

copy_or_fetch_geo() {
    geo_name=$1
    geo_url=$2
    if [ -n "${GEO_SRC:-}" ]; then
        if [ ! -s "$GEO_SRC/$geo_name" ]; then
            echo "Missing or empty local geo asset: $geo_name" >&2
            exit 1
        fi
        cp "$GEO_SRC/$geo_name" "$stage/bin/$geo_name"
    else
        curl --fail --show-error --location --retry 3 --connect-timeout 15 \
            --max-time 180 --output "$stage/bin/$geo_name" "$geo_url"
        if [ ! -s "$stage/bin/$geo_name" ]; then
            echo "Downloaded geo asset is empty: $geo_name" >&2
            exit 1
        fi
    fi
}

copy_or_fetch_geo geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
copy_or_fetch_geo geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
copy_or_fetch_geo geoip_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
copy_or_fetch_geo geosite_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
copy_or_fetch_geo geoip_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
copy_or_fetch_geo geosite_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat

# Fail the image build if this exact local core cannot load the default panel
# configuration with the geo assets shipped next to it.
XRAY_LOCATION_ASSET="$stage/bin" "$stage/bin/xray-linux-$target_arch" \
    run -test -c "$project_root/web/service/config.json"
"$stage/x-ui" -v

cp "$project_root/LICENSE" "$stage/licenses/PANEL-LICENSE"
cp "$project_root/core/LICENSE" "$stage/licenses/core/XRAY-LICENSE"
cp -R "$project_root/core/licenses/." "$stage/licenses/core/"
cp "$project_root/DIALECT11.md" "$stage/DIALECT11.md"

# Publish only a fully built and validated bundle. A failed local invocation
# preserves the previous build instead of mixing old and new core files.
rm -rf "$project_root/build"
mv "$stage" "$project_root/build"
stage=
