#!/bin/bash

set -e

S=${1}
D=${S}/build-afl

source ${S}/scripts/common.sh

prepare_src ${S} ${D}

export CC="afl-clang-fast"
export CFLAGS="-O3 -ffast-math -mtune=native -march=native"
export CXXFLAGS="-O3 -ffast-math  -mtune=native -march=native"

T=${D}/targets
INST=${T}/root
IN=${T}/in
OUT=${T}/out

for d in ${INST} ${IN} ${OUT}; do
    mkdir -p ${d}
done

./autogen.sh
cd ${D}
../configure --prefix=${INST}
make -j12
make install

# TODO: add more examples zip files
cp ${S}/tests/noradi.zip ${IN}
LD_LIBRARY_PATH=${INST}/lib afl-fuzz -i ${IN} -o ${OUT} -t 2000 -- ${INST}/bin/yazc info @@
