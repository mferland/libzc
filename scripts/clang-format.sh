#!/bin/bash

OPTS="-i"
FILES="./yazc/*.[ch] ./lib/*.[ch] ./tests/*.[ch]"

clang-format ${OPTS} ${FILES}
