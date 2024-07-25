# libzc gcc:latest build environment

FROM gcc:latest

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool autoconf zlib1g-dev pkg-config check \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc && scripts/build-generic.sh /home/dev/libzc gcc
