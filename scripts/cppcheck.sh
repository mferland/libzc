#!/bin/bash

# Copyright (C) 2012-2021 Marc Ferland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

BIN=$(command -v cppcheck)

if [ ! -x "$BIN" ]; then
    echo >&2 "cppcheck is not installed."
    exit 1
fi

options=(
    --enable=all
    --language=c
    --platform=unix64
    --std=c99
    --suppress=missingIncludeSystem
    --suppress=missingInclude
    --suppress=unusedFunction
    --suppress=staticFunction
    --suppress=normalCheckLevelMaxBranches
    --suppress=checkersReport
    -i lib/mask_parser.c
    -i lib/mask_scanner.c
)

# Autoconf feature and package macros are normally supplied to every build.
# Loading them here prevents warnings caused solely by cppcheck parsing the
# source outside the configured build.
if [ -f config.h ]; then
    options+=(--include=config.h)
fi

"${BIN}" "${options[@]}" yazc/ lib/
