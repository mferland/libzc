#!/bin/bash

set -e

S=${1}
D=${S}/build-mingw64
MINGW_LIB_PATH=/usr/x86_64-w64-mingw32/lib
MINGW_LOCAL_PATH=/usr/x86_64-w64-mingw32/local

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

./autogen.sh
cd ${D}
export PTHREAD_LIBS="-I${MINGW_LOCAL_PATH}/include -L${MINGW_LOCAL_PATH}/lib -lpthreadGC3"
export PTHREAD_CFLAGS="-I${MINGW_LOCAL_PATH}/include"
../configure --host=x86_64-w64-mingw32 \
	     --enable-static \
	     --disable-shared \
	     CPPFLAGS="-D_FILE_OFFSET_BITS=64" \
	     LDFLAGS="-L${MINGW_LIB_PATH} -lmman ${PTHREAD_LIBS}"
make V=1

V=$(../configure -V | grep 'zc configure' | cut -d' ' -f3)
ARCHIVE=yazc-v${V}-win64.zip
ARCHIVE_DIR=yazc-v${V}

mkdir ${D}/${ARCHIVE_DIR}
cp ${MINGW_LOCAL_PATH}/bin/pthreadGC3.dll ${D}/${ARCHIVE_DIR}
cp ${MINGW_LIB_PATH}/zlib1.dll ${D}/${ARCHIVE_DIR}
cp yazc/yazc.exe ${D}/${ARCHIVE_DIR}
zip -r ${D}/${ARCHIVE} ./${ARCHIVE_DIR}

echo archive ${ARCHIVE} ready
