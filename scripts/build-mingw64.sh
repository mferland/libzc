#!/bin/bash

set -e

S=${1}
D=${S}/build-mingw64
MINGW_BIN_PATH=/usr/x86_64-w64-mingw32/lib

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

./autogen.sh
cd ${D}
../configure --host=x86_64-w64-mingw32 \
	     --enable-static \
	     --disable-shared \
	     CFLAGS="-Ofast" \
	     LDFLAGS="-L/usr/x86_64-w64-mingw32/lib -lmman"
make -j12

V=$(../configure -V | grep 'zc configure' | cut -d' ' -f3)
ARCHIVE=yazc-v${V}-win64.zip
ARCHIVE_DIR=yazc-v${V}

mkdir ${D}/${ARCHIVE_DIR}
cp ${MINGW_BIN_PATH}/libwinpthread-1.dll ${D}/${ARCHIVE_DIR}
cp ${MINGW_BIN_PATH}/zlib1.dll ${D}/${ARCHIVE_DIR}
cp yazc/yazc.exe ${D}/${ARCHIVE_DIR}
zip -r ${D}/${ARCHIVE} ./${ARCHIVE_DIR}

echo archive ${ARCHIVE} ready
