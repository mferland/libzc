#!/usr/bin/python3

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
