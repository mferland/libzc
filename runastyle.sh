#!/bin/sh

# Copyright (C) 2012-2017 Marc Ferland
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

OPTIONS="\
--style=linux \
--pad-oper \
--indent=force-tab=8 \
--max-code-length=80 \
-k3 \
-W3 \
-m0 \
-M80 \
--suffix=none \
"
astyle $OPTIONS "./yazc/*.c" "./yazc/*.h" "./lib/*.c" "./lib/*.h" "./tests/*.c" "./tests/*.h"

exit 0
