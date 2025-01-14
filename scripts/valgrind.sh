#!/bin/bash

# Copyright (C) 2012-2021 Marc Ferland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

$CMD bruteforce -a -t1 -l6 -inoradh data/noradi.zip
check_output

$CMD dictionary --help
check_output

$CMD info data/noradi.zip
check_output

for i in `seq 2`
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

$CMD plaintext -o data/archive_ptext.zip 64 1808 data/archivec.zip 76 1820 64
check_output

$CMD plaintext data/archive_ptext.zip cv.tex data/archivec.zip cv.tex
check_output

$CMD plaintext -f data/plaintext.bin data/ciphertext.bin
check_output

$CMD plaintext -i 0x61852369 0x54cba4d5 0x1c5d5a2e
check_output

$CMD plaintext -i 0x12345678 0x23456789 0x34567890
check_output

exit 0
