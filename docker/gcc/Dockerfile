# libzc gcc:latest build environment

FROM gcc:latest
MAINTAINER Marc Ferland <marc.ferland@gmail.com>

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool autoconf zlib1g-dev pkg-config check gcc \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc \
    && rm -rf ./build-gcc \
    && mkdir build-gcc \
    && git clean -d -X -f \
    && (([ -f Makefile ] && make distclean) || true) \
    && ./autogen.sh \
    && cd build-gcc \
    && ../configure CC="gcc" CFLAGS="-g -O0 -fanalyzer" \
    && make -j8 check
