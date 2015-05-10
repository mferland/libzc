#!/bin/sh

OPTIONS="\
--style=kr \
--attach-extern-c \
--pad-oper \
-k3 \
-W3 \
-m0 \
-M80 \
--suffix=none \
"
astyle $OPTIONS "./bin/*.c" "./bin/*.h" "./lib/*.c" "./lib/*.h"

exit 0
