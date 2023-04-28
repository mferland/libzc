#!/bin/bash

prepare_src() {
    S=${1}
    D=${2}
    rm -rf ${D}
    mkdir -p ${D}
    git clean -dxf -e build-\*
}
