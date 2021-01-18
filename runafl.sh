#!/bin/bash

TMP=targets/root
IN=targets/in
OUT=targets/out

trap cleanup 1 2 3 6

cleanup() {
    echo "Caught signal ... cleaning up"
    rm -rf $(pwd)/targets/root
    echo "Done cleaning up!"
    exit 1
}

afl_run_info() {
    cp data/noradi.zip ${IN}
    LD_LIBRARY_PATH=$(pwd)/${TMP}/lib/ afl-fuzz -i ${IN} -o ${OUT} -t 2000 -- $(pwd)/${TMP}/bin/yazc info @@
}

afl_run_bruteforce() {
    cp data/noradi.zip ${IN}
    LD_LIBRARY_PATH=$(pwd)/${TMP}/lib/ afl-fuzz -i ${IN} -o ${OUT} -t 2000 -- $(pwd)/${TMP}/bin/yazc bruteforce -c noradi @@
}

for d in ${TMP} ${IN} ${OUT}; do
    mkdir -p ${d}
done

make distclean
./autogen.sh
export CC="afl-clang-fast"
export CFLAGS="-Ofast -mtune=native -march=native"
export CXXFLAGS="-Ofast -mtune=native -march=native"
./configure --prefix=$(pwd)/${TMP} || { exit 1; }
make || { exit 1; }
make install || { exit 1; }

PS3='Select which sub-command to test: '
OPTIONS=("info" "bruteforce" "dictionary" "plaintext" "quit")
select opt in "${OPTIONS[@]}"
do
    case $opt in
	"info")
	    echo "Testing info sub-command..."
	    afl_run_info
	    break
	    ;;
	"bruteforce")
	    echo "Testing bruteforce sub-command..."
	    afl_run_bruteforce
	    break
	    ;;
	"quit")
	    break
	    ;;
	*)
	    echo >&2 "invalid option"
	    ;;
    esac
done

cleanup

exit 0
