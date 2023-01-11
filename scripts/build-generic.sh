#!/bin/bash

set -e

S=${1}
D=${S}/build-${2}

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

./autogen.sh
cd ${D}
../configure CFLAGS="-Ofast"
make -j12 check
make dist
