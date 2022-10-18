# libzc debian build environment

FROM debian:unstable
MAINTAINER Marc Ferland <marc.ferland@gmail.com>

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool-bin autoconf gdb zlib1g-dev pkg-config check gcc \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc \
    && rm -rf ./build-deb \
    && mkdir build-deb \
    && git clean -d -X -f \
    && (([ -f Makefile ] && make distclean) || true) \
    && ./autogen.sh \
    && cd build-deb \
    && ../configure CC="gcc" CFLAGS="-g -O2 -fsanitize=undefined -fsanitize=leak" \
    && make -j8 check
