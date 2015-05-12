#!/bin/bash

VALGRIND=`which valgrind`
YAZC="yazc/yazc"
OPTS="--tool=memcheck --leak-check=full --show-leak-kinds=all --log-file=valgrind_run.txt"
CMD="libtool --mode=execute $VALGRIND $OPTS $YAZC"

check_output() {
    if cat valgrind_run.txt | grep -q "no leaks are possible"
    then
        tput setf 2
        echo OK
        tput setf 7
        rm -f valgrind_run.txt
    else
        tput setf 1
        echo LEAK
        tput setf 7
        cat valgrind_run.txt
        exit 1
    fi
}

$CMD
check_output

$CMD --help
check_output

$CMD bruteforce --help
check_output

$CMD bruteforce -l0 data/noradi.zip
check_output

$CMD bruteforce -t0 data/noradi.zip
check_output

$CMD bruteforce -t1 data/noradi.zip
check_output

$CMD bruteforce -cabc -t1 -l5 -iabcdef data/noradi.zip
check_output

$CMD bruteforce -cabc -t1 -l5 -iaaaaaa data/noradi.zip
check_output

$CMD bruteforce -a -t8 -l6 -inoradh data/noradi.zip
check_output

$CMD dictionary --help
check_output

for i in `seq 5`
do
    $CMD bruteforce -cnoradi -t${i} data/noradi.zip
    check_output
done

$CMD dictionary -d data/dict.txt data/noradi.zip
check_output

$CMD dictionary -d data/dict.txt data/test_non_encrypted.zip
check_output

$CMD bruteforce -cnoradi -t1 data/test_non_encrypted.zip
check_output

$CMD plaintext
check_output

$CMD plaintext --help
check_output

$CMD plaintext data/archive.zip:64:1808 data/archivec.zip:76:1820:64
check_output

exit 0
