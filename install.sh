#!/usr/bin/env bash
# Mirage installer. Either run it from the extracted release folder:
#   sudo bash install.sh
# or straight from GitHub (downloads the binary from the latest release):
#   bash <(curl -fsSL https://raw.githubusercontent.com/hope-s/Mirage/main/install.sh)
set -euo pipefail

repo="hope-s/Mirage"

if [[ ${EUID} -ne 0 ]]; then
  echo "please run as root (sudo -i first)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)          arch=amd64 ;;
  aarch64|arm64)         arch=arm64 ;;
  armv7l|armv7|armhf)    arch=armv7 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
bin="${here}/bin/mirage-linux-${arch}"
tmp=""

if [[ ! -f "${bin}" ]]; then
  # not inside an extracted release: fetch the binary from GitHub
  url="https://github.com/${repo}/releases/latest/download/mirage-linux-${arch}"
  tmp="$(mktemp /tmp/mirage.XXXXXX)"
  trap 'rm -f "${tmp}"' EXIT
  bin="${tmp}"
  echo "downloading ${url}"
  if command -v curl >/dev/null; then
    curl -fL --retry 3 -o "${bin}" "${url}"
  elif command -v wget >/dev/null; then
    wget -O "${bin}" "${url}"
  else
    echo "need curl or wget" >&2
    exit 1
  fi
fi
chmod +x "${bin}"

"${bin}" install
[[ -n "${tmp}" ]] && rm -f "${tmp}"
echo
exec /usr/local/bin/mirage
