# libzc debian build environment

FROM debian:unstable
MAINTAINER Marc Ferland <marc.ferland@gmail.com>

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool-bin autoconf zlib1g-dev pkg-config check gcc \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc && scripts/build-generic.sh /home/dev/libzc debian
