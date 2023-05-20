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
ENV CC=clang
ENV CCC_CC=clang

CMD cd /home/dev/libzc && scripts/build-scanbuild.sh /home/dev/libzc
