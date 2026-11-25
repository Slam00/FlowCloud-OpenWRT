#!/usr/bin/env bash
# Builds flowcloud_<version>_<arch>.ipk for common OpenWrt architectures and
# luci-app-flowcloud_<version>_all.ipk into dist/.
#   GO=/path/to/go scripts/build.sh [version]
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"
VERSION="${1:-$(cat VERSION)}"
PKG_VERSION="${VERSION}-r1"
DIST=dist
STAGE=build/stage
rm -rf "$STAGE" "$DIST"
mkdir -p "$DIST"

"$GO" test ./...
"$GO" build -o build/ipkbuild ./tools/ipkbuild

# opkg architecture -> GOARCH[/variant]
TARGETS=(
	"aarch64_cortex-a53:arm64"
	"aarch64_cortex-a72:arm64"
	"aarch64_generic:arm64"
	"arm_cortex-a7_neon-vfpv4:arm/7"
	"arm_cortex-a9_vfpv3-d16:arm/7"
	"arm_cortex-a15_neon-vfpv4:arm/7"
	"mipsel_24kc:mipsle/softfloat"
	"mips_24kc:mips/softfloat"
	"x86_64:amd64"
)

declare -A BUILT
for target in "${TARGETS[@]}"; do
	arch="${target%%:*}"
	spec="${target#*:}"
	goarch="${spec%%/*}"
	variant=""
	[[ "$spec" == */* ]] && variant="${spec#*/}"
	binary="build/bin/flowcloudd-${goarch}${variant:+-$variant}"
	if [[ -z "${BUILT[$binary]:-}" ]]; then
		env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
			GOARM="$([[ $goarch == arm ]] && echo "$variant" || true)" \
			GOMIPS="$([[ $goarch == mips* ]] && echo "$variant" || true)" \
			"$GO" build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$binary" ./cmd/flowcloudd
		BUILT[$binary]=1
	fi
	root="$STAGE/flowcloud-$arch"
	mkdir -p "$root/usr/bin"
	cp -r openwrt/flowcloud/files/. "$root/"
	cp "$binary" "$root/usr/bin/flowcloudd"
	build/ipkbuild -data "$root" -control openwrt/flowcloud/control \
		-package flowcloud -version "$PKG_VERSION" -arch "$arch" \
		-depends "libc, nftables-json | nftables-nojson, ip-tiny | ip-full" \
		-description "Routes selected domains and subnets through WARP and other tunnels" \
		-out "$DIST/flowcloud_${PKG_VERSION}_${arch}.ipk"
done

root="$STAGE/luci-app-flowcloud"
mkdir -p "$root/www"
cp -r openwrt/luci-app-flowcloud/root/. "$root/"
cp -r openwrt/luci-app-flowcloud/htdocs/. "$root/www/"
build/ipkbuild -data "$root" -control openwrt/luci-app-flowcloud/control \
	-package luci-app-flowcloud -version "$PKG_VERSION" -arch all \
	-depends "flowcloud, luci-base" \
	-description "LuCI interface for FlowCloud" \
	-out "$DIST/luci-app-flowcloud_${PKG_VERSION}_all.ipk"
# Version-less copies for releases/latest/download links (install.sh).
cp "$DIST/luci-app-flowcloud_${PKG_VERSION}_all.ipk" "$DIST/luci-app-flowcloud_all.ipk"
for file in "$DIST"/flowcloud_"${PKG_VERSION}"_*.ipk; do
	arch="${file##*/flowcloud_${PKG_VERSION}_}"
	cp "$file" "$DIST/flowcloud_${arch}"
done

( cd "$DIST" && sha256sum *.ipk > SHA256SUMS )
ls -l "$DIST"
