#!/bin/bash

PERF=$(which perf)
FGPATH=./perf/flamegraph
FGBIN=${FGPATH}/flamegraph.pl
SCBIN=${FGPATH}/stackcollapse-perf.pl
VMLINUX=/usr/lib/debug/boot/vmlinux-$(uname -r)
PERF_DATA=./perf/perf.data
PERF_SCRIPT=./perf/perf.script
PERF_FOLDED=./perf/perf.folded
PERF_SVG=./perf/perf.svg

echo "Starting perf script..."

if [ ! -x ${FGBIN} ]; then
    echo >&2 "cannot find flamegraph.pl executable"
    read -p "Do you want to install flamegraph? (y/n) " yn
    case $yn in
	[yY] ) echo "Installing flamegraph..."
	       git clone https://github.com/brendangregg/FlameGraph.git ${FGPATH}
	       ;;
	[nN] ) echo "exiting..."
	       exit 0
	       ;;
	* ) echo "invalid response"
	    exit 1
	    ;;
    esac
fi

if [ ! -x ${SCBIN} ]; then
    echo >&2 "cannot find stackcollapse-perf.pl executable"
    exit 1
fi

if [ ! -x ${PERF} ]; then
    echo >&2 "cannot find perf executable"
    read -p "Do you want to install perf? (y/n) " yn
    case $yn in
	[yY] ) echo "Installing perf..."
	       KVER=$(uname -r)
	       sudo apt install linux-tools-common \
		    linux-tools-$(KVER) \
		    linux-cloud-tools-$(KVER) \
		    linux-tools-generic \
		    linux-cloud-tools-generic
	       ;;
	[nN] ) echo "exiting..."
	       exit 0
	       ;;
	* ) echo "invalid response"
	    exit 1
	    ;;
    esac
fi

if [ ! -f ${VMLINUX} ]; then
    echo >&2 "cannot find vmlinux image"
    read -p "Install vmlinux image? (y/n) " yn
    case $yn in
	[yY] ) echo "Installing vmlinux image..."
	       echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
	       deb http://ddebs.ubuntu.com $(lsb_release -cs)-security main restricted universe multiverse
	       deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
		   sudo tee -a /etc/apt/sources.list.d/ddebs.list
	       
	       sudo apt install ubuntu-dbgsym-keyring

	       sudo apt update
	       sudo apt install linux-image-$(uname -r)-dbgsym
	       ;;
	[nN] ) echo "exiting..."
	       exit 0
	       ;;
	* ) echo "invalid response"
	    exit 1
	    ;;
    esac
fi

sudo sysctl -w kernel.perf_event_paranoid=1

echo "using flamegraph at: ${FGBIN}"
echo "using stackcollapse at: ${SCBIN}"
echo "using perf at: ${PERF}"
echo "using vmlinux at: ${VMLINUX}"

echo "Cleaning..."
make clean

echo "Configure..."
./configure CFLAGS="-g -Ofast -mtune=native -march=native -fno-omit-frame-pointer"

echo "Compile..."
make -j24

# sudo ${PERF} stat libtool exe yazc/yazc plaintext -t24 -o data/perfdata_ptext.zip 64 141029 data/perfdata_ctext.zip 76 141041 64
# exit 0

echo "Recording samples..."
sudo ${PERF} record -g -o ${PERF_DATA} libtool exe yazc/yazc plaintext -t24 -o data/perfdata_ptext.zip 64 141029 data/perfdata_ctext.zip 76 141041 64
sudo chown marc:marc ${PERF_DATA}

echo "Convert to script..."
${PERF} script -i ${PERF_DATA} -k ${VMLINUX} > ${PERF_SCRIPT}

echo "Fold..."
${SCBIN} ${PERF_SCRIPT} > ${PERF_FOLDED}

echo "FlameGraph..."
${FGBIN} ${PERF_FOLDED} > ${PERF_SVG}

exit 0
