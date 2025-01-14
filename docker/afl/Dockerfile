# afl++ related tests

FROM aflplusplus/aflplusplus:latest

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool autoconf zlib1g-dev pkg-config check gcc \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc && scripts/build-afl.sh /home/dev/libzc
