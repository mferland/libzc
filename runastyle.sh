#!/bin/sh

astyle --style=kr --attach-extern-c --pad-oper -k3 -W3 -m0 -M80 "./bin/*.c" "./bin/*.h" "./lib/*.c" "./lib/*.h"

exit 0
