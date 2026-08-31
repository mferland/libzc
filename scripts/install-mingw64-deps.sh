#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

"${SCRIPT_DIR}/install-deps.sh"

apt install -yq \
	libtool-bin \
	libz-mingw-w64-dev \
	mingw-w64 \
	mingw-w64-x86-64-dev \
	wine64 \
	zip
