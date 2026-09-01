<a href="https://scan.coverity.com/projects/mferland-libzc">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/7176/badge.svg"/>
</a>

<a href="https://github.com/mferland/libzc/actions">
   <img alt="Build Status"
        src="https://github.com/mferland/libzc/actions/workflows/build.yml/badge.svg"/>
</a>

# Overview

libzc is a simple ZIP password-cracking library. It also includes a
command-line tool called `yazc` (Yet Another Zip Cracker).

# Dependencies

On Ubuntu, install the required packages with:

    sudo apt install -y autoconf libtool zlib1g-dev pkg-config

Building the unit tests also requires
[Check](https://github.com/libcheck/check).

# Installation

Clone, configure, compile, and install the project:

    git clone https://github.com/mferland/libzc.git
    cd libzc
    ./autogen.sh
    ./configure CFLAGS='-O3 -ffast-math -march=native -mtune=native'
    make
    sudo make install

# Usage

There are currently three attack modes available:

## Brute force

This mode tries every password that can be generated from the given
character set. It supports multithreading.

### Options

`-c, --charset` specifies the character set. For example, `-c abc123`
tries every combination of `a`, `b`, `c`, `1`, `2`, and `3` up to the
maximum password length, which defaults to eight characters.

`-i, --initial` specifies the first password to try. By default, the
initial password is the first character in the character set. For
example, with the character set `abc`, the search begins with `a`, then
`b`, `c`, `aa`, and so on. This option is useful for skipping part of
the password search space.

`-l, --length` specifies the maximum password length. The program stops
after testing every password whose length is between one and `length`.

`-a, --alpha` uses lowercase ASCII letters (`a-z`).

`-A, --alpha-caps` uses uppercase ASCII letters (`A-Z`).

`-n, --numeric` uses digits (`0-9`).

`-s, --special` uses printable special ASCII characters.

`-t, --threads` specifies the number of worker threads. By default, the
program uses the number of online CPUs reported by
`sysconf(_SC_NPROCESSORS_ONLN)`.

`-S, --stats` prints runtime statistics.

### Mask options

A mask defines the allowed characters separately for each password
position. Using `-m, --mask` selects mask mode instead of the character-set
mode described above. Quote masks on the command line so the shell does not
interpret characters such as `?`, `[`, or `]`.

`-m, --mask=MASK` specifies the password mask. Without either of the length
options below, the program tests passwords whose length exactly matches the
mask. Passwords cannot exceed 16 characters.

`-k, --mask-minlen=N` also tests shorter prefixes of the mask, starting at
length `N`. The minimum length cannot exceed the number of positions in the
mask.

`-x, --mask-maxlen=N` also tests longer passwords, up to length `N`, by
repeating the final mask position. The maximum length cannot be shorter than
the mask.

Each mask position can be a literal character, a character list such as
`[abc]`, an alphanumeric range such as `[a-z]`, or one of these placeholders:

| Placeholder | Characters |
| --- | --- |
| `?l` | Lowercase ASCII letters (`a-z`) |
| `?u` | Uppercase ASCII letters (`A-Z`) |
| `?d` | Decimal digits (`0-9`) |
| `?s` | Printable special ASCII characters, including space |
| `?a` | All printable ASCII characters (`0x20`–`0x7e`) |
| `?B` | Upper-half byte values (`0x80`–`0xff`) |
| `?b` | All non-NUL byte values (`0x01`–`0xff`) |
| `?h` | Lowercase hexadecimal characters (`a-f`, `0-9`) |
| `?H` | Uppercase hexadecimal characters (`A-F`, `0-9`) |

Lists can combine characters and ranges. For example, `[a-f0-9_]` matches a
lowercase hexadecimal character or an underscore. Use a backslash to include
a mask metacharacter literally, such as `\?` for a question mark or `\\` for
a backslash. A byte can also be written as `\xNN`, where `NN` is its two-digit
hexadecimal value. Unescaped whitespace in a mask is ignored; use `\x20` when
a position must contain a space.

For example, try a literal `pass-` prefix followed by four digits:

    yazc bruteforce --mask='pass-?d?d?d?d' archive.zip

Try either `Pass0` or `pass0` through `Pass9` or `pass9`:

    yazc bruteforce --mask='[Pp]ass?d' archive.zip

The following mask first tests one lowercase letter, then a lowercase letter
followed by one digit, and finally passwords with that prefix followed by up
to two more digits:

    yazc bruteforce --mask='?l?d' --mask-minlen=1 --mask-maxlen=4 archive.zip

`-i, --initial` can also be used in mask mode. The initial password must have
the minimum generated length and every character must match its corresponding
mask position.

### Examples

Try all passwords in `a-z0-9` up to eight characters using four worker
threads:

    yazc bruteforce -a -n -l8 -t4 archive.zip

Try all password combinations using the characters `abc123` up to a
maximum of ten characters, using the default number of worker threads:

    yazc bruteforce -c abc123 -l10 archive.zip

## Dictionary

This mode tries every password from the given dictionary file. If no
dictionary file is provided, the program reads passwords from standard
input (`stdin`).

### Options

`-d, --dictionary` reads passwords from the specified file.

`-S, --stats` prints runtime statistics.

### Examples

Try all passwords from `words.dict`:

    cat words.dict | yazc dictionary archive.zip
    yazc dictionary -d words.dict archive.zip

Use John the Ripper to generate more passwords:

    john --wordlist=words.dict --rules --stdout | yazc dictionary archive.zip

## Plaintext

This mode uses a known vulnerability in the PKZIP stream cipher to find
the internal representation of the encryption key. Once the internal
representation has been recovered, the program tries to find the
actual password or an equivalent one.

Three methods are available for mapping plaintext bytes to ciphertext
bytes: file (`-f`), offset (`-o`), and ZIP entry (the default).

If no mapping option is given, the program reads the plaintext and
ciphertext from ZIP archives. Provide the corresponding entry name
from each archive. For example:

    yazc plaintext notencrypted.zip file.exe encrypted.zip file.exe

### Options

`-o, --offset` uses offsets instead of ZIP entry names. This mode can
map plaintext bytes from anywhere in one file to ciphertext bytes in
another file. The number of mapped bytes must match. This option is
useful when only part of a ZIP entry can be used. The following example
tries to find the password for `archive.zip` by mapping bytes 100–650
of `plain.bin` to bytes 112–662 of `archive.zip`; the first ciphertext
byte is at offset 64:

    yazc plaintext -o plain.bin 100 650 archive.zip 112 662 64

`-f, --file` uses plaintext bytes from `plaintextfile` and maps them to
bytes in `cipherfile`. The program assumes that the first 12 bytes of
`cipherfile` are the encryption header. Bytes that cannot be mapped are
ignored, which can happen when either file is shorter. For example:

    yazc plaintext -f plaintextfile cipherfile

`-i, --password-from-internal-rep` finds a password from the provided
internal representation. See section 3.6 of the Biham and Kocher paper
for more information. For example:

    yazc plaintext -i 0x777095c0 0xc1764180 0xf5d5b494

`-p, --password` calculates the internal representation of a password.
For example:

    yazc plaintext -p pAssW0Rd

`-t, --threads` specifies the number of worker threads. By default, the
program uses the number of online CPUs reported by
`sysconf(_SC_NPROCESSORS_ONLN)`.

`-S, --stats` prints runtime statistics.

## Info

The `info` subcommand lists the contents of a ZIP archive. It provides
information useful for plaintext and other attack modes. For example:

    yazc info data/noradi.zip

Result:

    INDEX NAME      OFFSETS     SIZE CSIZE ENCRYPTED HEADER
        0 TEXT1.TXT 39  51  155 110  116   875dee36d843e98819faae48
        1 TEXT2.TXT 194 206 302 99   108   4fa3648cd55cdbdc071bfae1
        2 TEXT3.TXT 341 353 439 88   98    0d9507f1cd95d217c8cadb11

- The first column (INDEX) is the index of the file in the archive.
- The second column (NAME) is the name of the file taken from the ZIP
  header.
- The third column (OFFSETS) contains offsets useful for the plaintext
  attack when using the `-o` option. The first number is the offset of
  the first byte of the encrypted header; the second is the offset of
  the first byte of the compressed data; and the third is the offset of
  the last byte of the compressed data.
- The fourth column (SIZE) is the original file size in bytes.
- The fifth column (CSIZE) is the compressed file size _including_ the
  encrypted header (always 12 bytes).
- The sixth column (ENCRYPTED HEADER) is the encrypted header.

This subcommand makes it easier to inspect the contents of ZIP archives.
Another tool you can use is `zipinfo`.

# TODO

- Use a per-position alphabet table for both charset and mask modes so
  `candidate_char()` does not need to check `crk->parsed_mask_len` for every
  generated character.

# License

Distributed under the GPLv3+ license. See `COPYING` for more information.

# Contact

Marc Ferland - marc.ferland@gmail.com
