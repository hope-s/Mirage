#!/usr/bin/env bash
# Mirage installer: run as root from the extracted release folder.
#   bash install.sh
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "please run as root:  sudo bash install.sh" >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$(uname -m)" in
  x86_64|amd64)          arch=amd64 ;;
  aarch64|arm64)         arch=arm64 ;;
  armv7l|armv7|armhf)    arch=armv7 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

bin="${here}/bin/mirage-linux-${arch}"
if [[ ! -f "${bin}" ]]; then
  echo "missing ${bin} - extract the full release archive first" >&2
  exit 1
fi
chmod +x "${bin}"

"${bin}" install
echo
exec /usr/local/bin/mirage
