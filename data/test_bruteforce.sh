#!/bin/bash

# Copyright (C) 2012-2018 Marc Ferland
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

ZIP=$(which zip)
CMD="libtool --mode=execute ../yazc/yazc"

create_dummy_files() {
    for i in $(seq 0 2)
    do
        dd if=/dev/urandom of=file_${i} bs=$(($RANDOM * 10)) count=1 &>/dev/null
    done
}

create_zip_file() {
    FILES="file_0 file_1 file_2"
    zip -e -P ${PW} ${E} ${FILES} &>/dev/null
}

cleanup() {
    rm -f file_[0-9] e_archive_*
}

if [ ! -f "${ZIP}" ]; then
    echo >&2 "error: zip not found!"
    exit 1
fi

while true; do
    PW=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w $(($RANDOM % 7 + 1)) | head -n 1)
    E="e_archive_${PW}.zip"

    cleanup
    create_dummy_files
    create_zip_file

    EINFO=$(${CMD} info ${E} | grep file_0 | sed 's/\ \+/ /g')

    echo libtool exe ../yazc/yazc bruteforce -aA -l7 ${E}
    if ! libtool exe ../yazc/yazc bruteforce -aA -l7 ${E}; then
	echo >&2 "ERROR"
	exit 1
    fi
done

exit 0
