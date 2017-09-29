#!/usr/bin/python3

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

# Generate decrypt_byte table.
#
# Rationale: 
# The original decrypt_byte function:
#
# unsigned char decrypt_byte()
#       local unsigned short temp
#       temp <- Key(2) | 2
#       decrypt_byte <- (temp * (temp ^ 1)) >> 8
# end decrypt_byte
#
# bit1 of temp is always 1 (because of |2) and bit 0 is flipped in
# (temp ^ 1). This is equivalent of clearing the last 2 bits of temp
# and replacing it with b11 and b10. We can thus generate the final
# byte using only the first 14bits of temp:
for i in range(2**(16-2)):
    byte = ((i << 2) | 0x3) * ((i << 2) | 0x2)
    byte = byte >> 8
    byte = byte & 0xff
    print(format(byte, '#04x') + ", ", end = "\n" if (i + 1) % 8 == 0 else "")
