#!/bin/bash

ZIP=$(which zip)
EPREFIX="eptext_archive_"
PREFIX="ptext_archive_"
SUFFIX=".zip"
YAZC="../yazc/yazc"
CMD="libtool --mode=execute $YAZC"

if [ ! -f "${ZIP}" ]; then
    echo >&2 "error: zip not found!"
    exit 1
fi

create_dummy_files() {
    for i in $(seq 0 2)
    do
        dd if=/dev/urandom of=file_${i} bs=$(($RANDOM * 50)) count=1
    done
}

cleanup() {
    rm -f file_[0-9]
}

cleanup
create_dummy_files

FILES="file_0 file_1 file_2"
for pw in a aa aaa
do
    zip -e -P ${pw} ${EPREFIX}${pw}${SUFFIX} ${FILES}
    zip ${PREFIX}${pw}${SUFFIX} ${FILES}
done

EINFO=$(${CMD} info ${EPREFIX}a${SUFFIX} | grep file_0 | sed 's/\ \+/ /g')
INFO=$(${CMD} info ${PREFIX}a${SUFFIX} | grep file_0 | sed 's/\ \+/ /g')
PLAINOFF1=$(echo ${INFO} | cut -d' ' -f4)
PLAINOFF2=$(echo ${INFO} | cut -d' ' -f5)
CIPHEROFF1=$(echo ${EINFO} | cut -d' ' -f4)
CIPHEROFF2=$(echo ${EINFO} | cut -d' ' -f5)
CIPHERBEGIN=$(echo ${EINFO} | cut -d' ' -f3)

echo $PLAINOFF1 $PLAINOFF2 $CIPHEROFF1 $CIPHEROFF2 $CIPHERBEGIN

echo libtool exe ../yazc/yazc plaintext ${PREFIX}a${SUFFIX}:${PLAINOFF1}:${PLAINOFF2} ${EPREFIX}a${SUFFIX}:${CIPHEROFF1}:${CIPHEROFF2}:${CIPHERBEGIN}

cleanup

exit 0
