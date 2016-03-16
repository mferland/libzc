#!/bin/bash

BIN=`which cppcheck`
OPT="--enable=all --language=c --platform=unix64 --std=c99"
FILES="yazc/ lib/"

if [ ! -x "$BIN" ]; then
    echo >&2 "cppcheck is not installed."
    exit 1
fi

${BIN} ${OPT} ${FILES}
