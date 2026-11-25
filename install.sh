#!/bin/sh
# FlowCloud for OpenWrt installer.
#   sh <(wget -O - https://raw.githubusercontent.com/Slam00/FlowCloud-OpenWRT/main/install.sh)
# Options: -y installs kmod-amneziawg without asking, -z installs zapret2,
# -Z skips zapret2. Without -z/-Z the script asks.
set -e

REPO="Slam00/FlowCloud-OpenWRT"
AWG_REPO="Slava-Shchipunov/awg-openwrt"
# The zapret2 release FlowCloud's strategies were tested with.
ZAPRET2_VERSION="1.0.8"
ZAPRET2_DIR="/usr/lib/flowcloud/zapret2"
ASSUME_YES=0
ZAPRET=ask
for ARG in "$@"; do
	case "$ARG" in
	-y) ASSUME_YES=1 ;;
	-z) ZAPRET=yes ;;
	-Z) ZAPRET=no ;;
	esac
done

die() { echo "Ошибка: $*" >&2; exit 1; }

command -v opkg >/dev/null 2>&1 || die "нужен opkg (OpenWrt 23.05 / 24.10). OpenWrt 25.x с apk пока не поддерживается."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

# The package architecture with the highest priority, e.g. aarch64_cortex-a53.
ARCH=$(opkg print-architecture | awk '$2 != "all" && $2 != "noarch" {print $3, $2}' | sort -n | tail -1 | cut -d' ' -f2)
[ -n "$ARCH" ] || die "не удалось определить архитектуру пакетов"
echo "Архитектура: $ARCH"

if ! ip link add dev fcprobe0 type amneziawg 2>/dev/null; then
	VERSION=$(ubus call system board | jsonfilter -e '@.release.version')
	TARGET=$(ubus call system board | jsonfilter -e '@.release.target')
	echo
	echo "В системе нет модуля ядра AmneziaWG. Он нужен для WARP-туннелей."
	echo "Готовые пакеты публикует сторонний проект https://github.com/$AWG_REPO"
	echo "для OpenWrt $VERSION ($TARGET)."
	ANSWER=y
	if [ "$ASSUME_YES" != "1" ]; then
		printf "Установить kmod-amneziawg и amneziawg-tools оттуда? [y/N] "
		read -r ANSWER
	fi
	case "$ANSWER" in
	y|Y|yes|д|Д|да)
		SUFFIX="v${VERSION}_${ARCH}_$(echo "$TARGET" | tr '/' '_')"
		for PKG in kmod-amneziawg amneziawg-tools; do
			URL="https://github.com/$AWG_REPO/releases/download/v${VERSION}/${PKG}_${SUFFIX}.ipk"
			echo "Скачиваю $URL"
			fetch "$URL" "$TMP/$PKG.ipk" || die "нет пакета $PKG для OpenWrt $VERSION ($TARGET). WARP-туннели работать не будут, но интерфейсные — будут."
		done
		opkg install "$TMP/kmod-amneziawg.ipk" "$TMP/amneziawg-tools.ipk"
		;;
	*)
		echo "Пропускаю: WARP-туннели будут недоступны, туннели через существующие интерфейсы работают."
		;;
	esac
else
	ip link del dev fcprobe0
fi

BASE="https://github.com/$REPO/releases/latest/download"
echo
echo "Скачиваю FlowCloud для $ARCH"
fetch "$BASE/flowcloud_${ARCH}.ipk" "$TMP/flowcloud.ipk" || die "нет сборки FlowCloud для $ARCH"
fetch "$BASE/luci-app-flowcloud_all.ipk" "$TMP/luci-app-flowcloud.ipk"
opkg install "$TMP/flowcloud.ipk" "$TMP/luci-app-flowcloud.ipk"

install_zapret2() {
	case "$ARCH" in
	aarch64*) ZARCH=linux-arm64 ;;
	arm*) ZARCH=linux-arm ;;
	mipsel*) ZARCH=linux-mipsel ;;
	mips64*) ZARCH=linux-mips64 ;;
	mips*) ZARCH=linux-mips ;;
	x86_64) ZARCH=linux-x86_64 ;;
	i386*|i686*) ZARCH=linux-x86 ;;
	riscv64*) ZARCH=linux-riscv64 ;;
	*) echo "zapret2: нет сборки для $ARCH, пропускаю."; return 0 ;;
	esac
	NAME="zapret2-v${ZAPRET2_VERSION}"
	BASE="https://github.com/bol-van/zapret2/releases/download/v${ZAPRET2_VERSION}"
	echo "Скачиваю zapret2 ${ZAPRET2_VERSION} ($ZARCH)"
	fetch "$BASE/${NAME}-openwrt-embedded.tar.gz" "$TMP/zapret2.tar.gz" || die "не удалось скачать zapret2"
	fetch "$BASE/sha256sum.txt" "$TMP/zapret2.sha256" || die "не удалось скачать контрольные суммы zapret2"
	tar -xzf "$TMP/zapret2.tar.gz" -C "$TMP" "$NAME/binaries/$ZARCH/nfqws2" \
		"$NAME/lua/zapret-lib.lua.gz" "$NAME/lua/zapret-antidpi.lua.gz" "$NAME/lua/zapret-auto.lua.gz"
	EXPECTED=$(grep " $NAME/binaries/$ZARCH/nfqws2\$" "$TMP/zapret2.sha256" | cut -d' ' -f1)
	ACTUAL=$(sha256sum "$TMP/$NAME/binaries/$ZARCH/nfqws2" | cut -d' ' -f1)
	[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "контрольная сумма nfqws2 не совпала"
	opkg update >/dev/null 2>&1 || true
	opkg install kmod-nft-queue kmod-nfnetlink-queue || die "не удалось установить kmod-nft-queue"
	mkdir -p "$ZAPRET2_DIR/lua"
	cp "$TMP/$NAME/binaries/$ZARCH/nfqws2" "$ZAPRET2_DIR/nfqws2"
	chmod 755 "$ZAPRET2_DIR/nfqws2"
	for LUA in zapret-lib zapret-antidpi zapret-auto; do
		gunzip -c "$TMP/$NAME/lua/$LUA.lua.gz" > "$ZAPRET2_DIR/lua/$LUA.lua"
	done
	echo "zapret2 установлен в $ZAPRET2_DIR"
}

if [ "$ZAPRET" = ask ]; then
	echo
	echo "zapret2 (https://github.com/bol-van/zapret2) обходит DPI без туннеля: секции с действием"
	echo "«Через zapret2» идут напрямую с вашего IP, стратегия подбирается автоматически."
	printf "Установить zapret2? [y/N] "
	read -r ANSWER
	case "$ANSWER" in y|Y|yes|д|Д|да) ZAPRET=yes ;; *) ZAPRET=no ;; esac
fi
[ "$ZAPRET" = yes ] && install_zapret2

echo
echo "Готово. Настройте FlowCloud в LuCI: Службы → FlowCloud, затем включите его в «Настройках»."
