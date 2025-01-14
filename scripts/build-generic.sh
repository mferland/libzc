#!/bin/bash

set -e

S=${1}
D=${S}/build-${2}

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

./autogen.sh
cd ${D}
../configure CFLAGS="-O3 -ffast-math"
make -j12 check
make dist
