#!/bin/bash

OPTS="-i"
FILES="./src/*.[ch] ./tests/*.[ch]"

clang-format ${OPTS} ${FILES}
