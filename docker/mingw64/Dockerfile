# yazc static executable for Windows 64-bits

FROM ubuntu:22.10
MAINTAINER Marc Ferland <marc.ferland@gmail.com>

RUN apt update \
    && apt upgrade -y \
    && apt install -y git make automake libtool-bin autoconf zlib1g-dev pkg-config check gcc mingw-w64 mingw-w64-x86-64-dev libz-mingw-w64-dev zip \
    && apt clean

RUN useradd --create-home --shell /bin/bash dev

RUN cd /home/dev
RUN git clone https://github.com/alitrack/mman-win32.git
RUN cd mman-win32 \
    && ./configure --prefix=/usr/x86_64-w64-mingw32 --enable-static --cc=x86_64-w64-mingw32-gcc --cross-prefix=x86_64-w64-mingw32- \
    && make \
    && make install

RUN git clone https://git.code.sf.net/p/pthreads4w/code /home/dev/pthreads4w
COPY 0001-Temp-Makefile-fix.patch /home/dev/pthreads4w
RUN git config --global user.email "test@libzc.net" \
    && git config --global user.name "Dev User"
RUN cd /home/dev/pthreads4w \
    && git am 0001-Temp-Makefile-fix.patch \
    && autoreconf --install \
    && ./configure --prefix=/usr/x86_64-w64-mingw32/local --host=x86_64-w64-mingw32 \
    && make clean GC \
    && make install

USER dev
WORKDIR /home/dev

CMD cd /home/dev/libzc && scripts/build-mingw64.sh /home/dev/libzc
