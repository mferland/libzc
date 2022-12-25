# libzc clang build environment

FROM silkeh/clang:15-bullseye
MAINTAINER Marc Ferland <marc.ferland@gmail.com>

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool autoconf zlib1g-dev pkg-config check \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc \
    && rm -rf ./build-clang \
    && mkdir build-clang \
    && git clean -d -X -f \
    && (([ -f Makefile ] && make distclean) || true) \
    && ./autogen.sh \
    && cd build-clang \
    && ../configure CC="clang" CFLAGS="-g -O2" \
    && make -j8 check
