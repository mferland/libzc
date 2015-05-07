#!/bin/sh

VALGRIND=`which valgrind`
OPTS="--tool=memcheck --leak-check=full --log-file=valgrind_run.txt"
CMD="libtool --mode=execute $VALGRIND $OPTS"

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

export CK_FORK=no

$CMD bin/yazc
check_output

$CMD bin/yazc --help
check_output

$CMD bin/yazc bruteforce --help
check_output

# invalid max length, 0
$CMD bin/yazc bruteforce -l0 data/noradi.zip
check_output

# invalid number of threads o
$CMD bin/yazc bruteforce -t0 data/noradi.zip
check_output

# invalid character set
$CMD bin/yazc bruteforce -t1 data/noradi.zip
check_output

# invalid initial passw (wrong chars)
$CMD bin/yazc bruteforce -cabc -t1 -l5 -iabcdef data/noradi.zip
check_output

# invalid initial passw (too long)
$CMD bin/yazc bruteforce -cabc -t1 -l5 -iaaaaaa data/noradi.zip
check_output

# valid
$CMD bin/yazc bruteforce -a -t8 -l6 -inoradh data/noradi.zip
check_output

$CMD bin/yazc dictionary --help
check_output

#$CMD lib/.libs/lt-test_libzc
#check_output

for i in `seq 5`
do
    $CMD bin/yazc bruteforce -cnoradi -t${i} data/noradi.zip
    check_output
done

$CMD bin/yazc dictionary -d data/dict.txt data/noradi.zip
check_output

$CMD bin/yazc dictionary -d data/dict.txt data/test_non_encrypted.zip
check_output

$CMD bin/yazc bruteforce -cnoradi -t1 data/test_non_encrypted.zip
check_output

$CMD bin/yazc plaintext
check_output

$CMD bin/yazc plaintext --help
check_output

exit 0
