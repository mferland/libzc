<a href="https://scan.coverity.com/projects/mferland-libzc">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/7176/badge.svg"/>
</a>

<a href="https://github.com/mferland/libzc/actions">
   <img alt="Build Status"
        src="https://github.com/mferland/libzc/actions/workflows/build.yml/badge.svg"/>
</a>

# What is it?

The libzc library is a simple zip cracking library. It also comes with
a command line tool called 'yazc' (Yet Another Zip Cracker).

# Dependencies

The following packages are required (following example is for Ubuntu):

    sudo apt install -y autoconf libtool zlib1g-dev pkg-config

Unit tests require linking with [libcheck](https://github.com/libcheck/check)

# How to install it?

Just clone, configure, compile and install.

    git clone https://github.com/mferland/libzc.git
    cd libzc
    ./autogen.sh
    ./configure CFLAGS='-O3 -ffast-math -march=native -mtune=native'
    make
    sudo make install

# How to use it?

There are currently 3 attack modes available:

## Bruteforce

This mode tries all possible passwords from the given character
set. It supports multi-threading.

### Options

`-c, --charset` allows you to specify the character set you want. For
example, `-c abc123` will try all combinations of characters 'a', 'b',
'c', '1', '2' and '3' up the a maximum length (default is 8).

`-i, --initial` allows you to specify the initial password, the first
password to be tried. By default the initial password is the first
character of the character set (so if your character set is 'abc' the
first password that will be tested is 'a', then 'b', then 'c', then
'aa', etc). This is usefull to skip part of the password 'space'.

`-l, length` allows you to specify a maximum password length. Once all
passwords between 1 and `length` have been tested, the program will
stop.

`-a, --alpha` use characters [a-z].

`-A, --alpha-caps` use characters [A-Z].

`-n, --numeric` use characters [0-9].

`-s, --special` use special characters. These are the special,
printable, ASCII characters.

`-t, --threads` number of threads to start. By default, this is the
number of online CPUs, aka the number returned by
`sysconf(_SC_NPROCESSORS_ONLN)`.

`-S, --stats` prints different statistics.

### Examples

Try all passwords in [a-z0-9] up to 8 characters with 4 threads:

    yazc bruteforce -a -n -l8 -t4 archive.zip

Try all password combinations using characters "abc123" up to a
maximum of 10 characters with all available cores:

    yazc bruteforce -c abc123 -l10 archive.zip

## Dictionary

This mode tries all passwords from the given dictionary file. If no
password file is given as argument it reads from stdin.

### Options

`-d, --dictionary` read passwords from the specified file.

`-S, --stats` prints different statistics.

### Examples

Try all password from words.dict:

    cat words.dict | yazc dictionary archive.zip
	yazc dictionary -d words.dict archive.zip

Use John The Ripper to generate more passwords:

    john --wordlist=words.dict --rules --stdout | yazc dictionary archive.zip

## Plaintext

This mode uses a known vulnerability in the pkzip stream cipher to
find the internal representation of the encryption key. Once the
internal representation of the key has been found, we try to find the
actual (or an equivalent) password.

Three different options are available to map the plaintext bytes on
the ciphertext: file (`-f`), offset (`-o`) and zip entry (default).

If no option switch is given, the program will read the plaintext and
ciphertext from zip files. You just need to give the entry names of
both files within the zips. For example:

    yazc plaintext notencrypted.zip file.exe encrypted.zip file.exe

### Options

`-o, --offset` use offsets instead of the zip file entry names. Using
this mode, you can map plaintext bytes from anywhere in any file to
the ciphertext bytes in another file. Note that the number of bytes
must match. This option can be usefull if only part of the zip entries
can be used. For example, try to find archive.zip password by using
plaintext bytes from plain.bin (map bytes 100-650 of plain.bin to
bytes 112-662 of archive.zip, first cipher byte is at offset 64):

    yazc plaintext -o plain.bin 100 650 archive.zip 112 662 64

`-f, --file` use plaintext bytes from plaintextfile and map them to
the bytes from cipherfile. We assume that the first 12 bytes from
cipherfile is the encryption header. If some bytes cannot be mapped,
they are ignored (can happen if either the plaintext or the cipher
file is smaller). Example:

    yazc plaintext -f plaintextfile cipherfile

`-i, --password-from-internal-rep` find the password from the provided
internal representation (see section 3.6 of the Biham & Kocher paper
for more information about the internal representation). For example:

    yazc plaintext -i 0x777095c0 0xc1764180 0xf5d5b494

`-p, --password` from a password, calculate the internal
representation. For example:

    yazc plaintext -p pAssW0Rd

`-t, --threads` number of threads to start. By default, this is the
number of online CPUs, aka the number returned by
`sysconf(_SC_NPROCESSORS_ONLN)`.

`-S, --stats` prints different statistics.

## Info

The `info` sub-command lists the content of the zip file. It can help
you get the needed information needed for the plaintext or other
attack modes. Example:

    yazc info data/noradi.zip

Result:

    INDEX NAME      OFFSETS     SIZE CSIZE ENCRYPTED HEADER
        0 TEXT1.TXT 39  51  155 110  116   875dee36d843e98819faae48
        1 TEXT2.TXT 194 206 302 99   108   4fa3648cd55cdbdc071bfae1
        2 TEXT3.TXT 341 353 439 88   98    0d9507f1cd95d217c8cadb11

- The first column (INDEX) is the index of the file in the archive.
- The second column (NAME) is the name of the file taken from the zip
  header.
- The third column (OFFSETS) are some interesting indexes for the
  plaintext attack (when using the offset '-o' option). The first
  number is the index of the first byte of the encrypted header, the
  second number is the first byte of the compressed file and the third
  number is the index of the last byte of the compressed file.
- The fourth column (SIZE) is the original file size in bytes.
- The fifth column (CSIZE) is the compressed file size _including_ the
  encrypted header (always 12 bytes).
- The sixth column (ENCRYPTED HEADER) is the encrypted header.

This sub-command is provided to facilitate exploring the content of
zip files. Another tool you can use is `zipinfo`.

# License

Distributed under the GPLv3+ license. See `COPYING` for more information.

# Contact

Marc Ferland - marc.ferland@gmail.com
