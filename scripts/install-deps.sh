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
    dnf install -y gcc git make automake autoconf bison flex zlib-devel pkg-config texinfo diffutils check
elif [ "$NAME" = "Ubuntu" ]
then
    apt update
    apt install -yq gcc git make automake autoconf bison flex zlib1g-dev pkg-config texinfo diffutils check
elif [ "$NAME" = "Debian GNU/Linux" ]
then
    apt update
    apt install -yq gcc git make automake autoconf bison flex zlib1g-dev pkg-config texinfo diffutils check
else
    echo "ERROR: OS name is not provided."
    exit 1
fi
