#!/bin/sh

TMP=$(mktemp -d)
REV="v0.4.1
v0.3.6
v0.3.5
v0.3.4
v0.3.2
v0.3.1
v0.3.0
v0.2.0
bc621294c57fa688e535babfc0f05726277e65b6
78b42d456766eebf0682c162592603712c7c03f4
907fd7285ab51fe51ad7a67c8f348b4744198fa1
5e4362267fbe30ea08e2cfaa68e903bdb2f79575
"
OUT=$(echo $(pwd)/log)

cd ${TMP}
git clone https://github.com/mferland/libzc.git
cp libzc/data/noradi.zip .

cd libzc
rm -f ${OUT}

for r in ${REV}
do
    git checkout ${r}
    ./autogen.sh
    ./configure CFLAGS='-O3 -ffast-math -march=native -mtune=native'
    make -j8
    for i in $(seq 1 10)
    do
        if [ -x yazc/yazc ]; then
            /usr/bin/time -a -o ${OUT} -f "${r} %e" libtool exe yazc/yazc bruteforce -a ${TMP}/noradi.zip
        else
            /usr/bin/time -a -o ${OUT} -f "${r} %e" libtool exe bin/yazc bruteforce -a ${TMP}/noradi.zip
        fi
    done
    git clean -d -X -f
done

for r in ${REV}
do
    echo ${r} $(cat ${OUT} | grep ${r} | awk '{ total += $2 } END { print total/NR }')
done

exit 0
