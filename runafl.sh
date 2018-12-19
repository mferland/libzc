#!/bin/sh

TMP=targets/root
IN=targets/in
OUT=targets/out

trap cleanup 1 2 3 6

cleanup() {
    echo "Caught signal ... cleaning up"
    rm -rf $(pwd)/targets
    #cd /sys/devices/system/cpu
    #echo ondemand | sudo tee cpu*/cpufreq/scaling_governor
    #cd -
    echo "Done cleaning up!"
    exit 1
}

for d in ${TMP} ${IN} ${OUT}; do
    mkdir -p ${d}
done

make distclean
./autogen.sh
CC="afl-clang-fast" CFLAGS="-Ofast -mtune=native -march=native" CXXFLAGS="-Ofast -mtune=native -march=native" ./configure --prefix=$(pwd)/${TMP}
make
make install

# set cpu governor to 'performance'
#cd /sys/devices/system/cpu
#echo performance | sudo tee cpu*/cpufreq/scaling_governor
#cd -

cp data/noradi.zip ${IN}

#LD_LIBRARY_PATH=$(pwd)/${TMP}/lib/ afl-fuzz -i ${IN} -o ${OUT} -t 2000 -- $(pwd)/${TMP}/bin/yazc bruteforce -c noradi @@

LD_LIBRARY_PATH=$(pwd)/${TMP}/lib/ afl-fuzz -i ${IN} -o ${OUT} -t 2000 -- $(pwd)/${TMP}/bin/yazc info @@

cleanup
