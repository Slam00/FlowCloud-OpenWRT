#!/bin/sh
# FlowCloud for OpenWrt installer.
#   sh <(wget -O - https://raw.githubusercontent.com/Slam00/FlowCloud-OpenWRT/main/install.sh)
# Add -y to install kmod-amneziawg without asking.
set -e

REPO="Slam00/FlowCloud-OpenWRT"
AWG_REPO="Slava-Shchipunov/awg-openwrt"
ASSUME_YES=0
[ "$1" = "-y" ] && ASSUME_YES=1

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

echo
echo "Готово. Настройте FlowCloud в LuCI: Службы → FlowCloud, затем включите его в «Настройках»."
