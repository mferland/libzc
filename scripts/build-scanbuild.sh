#!/bin/bash

set -e

S=${1}
D=${S}/build-scanbuild

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

./autogen.sh
cd ${D}
../configure CFLAGS="-O0 -g"
scan-build -o ${D}/output make -j12
