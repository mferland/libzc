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

create_zip_files() {
    FILES="file_0 file_1 file_2"
    zip -e -P ${PW} ${E} ${FILES} &>/dev/null
    zip ${P} ${FILES} &>/dev/null
}

cleanup() {
    rm -f file_[0-9] [ep]_archive_*
}

if [ ! -f "${ZIP}" ]; then
    echo >&2 "error: zip not found!"
    exit 1
fi

while true; do
    PW=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $(($RANDOM % 10 + 1)) | head -n 1)
    E="e_archive_${PW}.zip"
    P="p_archive_${PW}.zip"

    cleanup
    create_dummy_files
    create_zip_files

    EINFO=$(${CMD} info ${E} | grep file_0 | sed 's/\ \+/ /g')
    PINFO=$(${CMD} info ${P} | grep file_0 | sed 's/\ \+/ /g')
    POFF1=$(echo ${PINFO} | cut -d' ' -f4)
    POFF2=$(echo ${PINFO} | cut -d' ' -f5)
    COFF1=$(echo ${EINFO} | cut -d' ' -f4)
    COFF2=$(echo ${EINFO} | cut -d' ' -f5)
    CBEGN=$(echo ${EINFO} | cut -d' ' -f3)

    echo libtool exe ../yazc/yazc plaintext ${P}:${POFF1}:${POFF2} ${E}:${COFF1}:${COFF2}:${CBEGN}
    if ! libtool exe ../yazc/yazc plaintext ${P}:${POFF1}:${POFF2} ${E}:${COFF1}:${COFF2}:${CBEGN}; then
	echo >&2 "ERROR"
	exit 1
    fi
done

exit 0
