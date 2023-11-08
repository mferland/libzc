#!/bin/sh

if [ -f /etc/os-release ]
then
    . /etc/os-release
else
    echo "ERROR: OS name is not provided."
    exit 1
fi

if [ "$NAME" = "Fedora Linux" ]
then
    dnf install -y git make automake libtool autoconf zlib-devel pkg-config texinfo diffutils
elif [ "$NAME" = "Ubuntu" ]
then
    apt update
    apt install -yq git make automake libtool autoconf zlib1g-dev pkg-config texinfo diffutils
elif [ "$NAME" = "Debian GNU/Linux" ]
then
    apt update
    apt install -yq git make automake libtool autoconf zlib1g-dev pkg-config texinfo diffutils
else
    echo "ERROR: OS name is not provided."
    exit 1
fi

# install our hacked version of libcheck
git clone https://github.com/mferland/check
cd check
autoreconf --install
./configure --prefix=/usr
make
make install
ldconfig