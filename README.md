<a href="https://scan.coverity.com/projects/mferland-libzc">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/7176/badge.svg"/>
</a>

<a href="https://travis-ci.org/mferland/libzc">
   <img alt="Build Status"
        src="https://travis-ci.org/mferland/libzc.svg?branch=master"/>
</a>

What is it?
===========
The libzc library is a simple zip cracking library. It also comes with
a command line tool called 'yazc' (Yet Another Zip Cracker).

Dependencies
============

The following packages are required (following example is for Ubuntu):

    sudo apt install -y autoconf libtool zlib1g-dev pkg-config

How to install it?
==================

Just clone, configure, compile and install.

    git clone https://github.com/mferland/libzc.git
    cd libzc
    ./autogen.sh
    ./configure CFLAGS='-Ofast -march=native -mtune=native'
    make
    sudo make install

How to use it?
==============
There are currently 3 attack modes available:

Bruteforce
----------
This mode tries all possible passwords from the given character
set. It supports multi-threading.

Example:
Try all passwords in [a-z0-9] up to 8 characters with 4 threads:

    yazc bruteforce -a -n -l8 -t4 archive.zip

Dictionary
----------
This mode tries all passwords from the given dictionary file. If no
password file is given as argument it reads from stdin.

Examples:
Try all password from words.dict:

    cat words.dict | yazc dictionary archive.zip

Use John The Ripper to generate more passwords:

    john --wordlist=words.dict --rules --stdout | yazc dictionary archive.zip

Plaintext
---------
This mode uses a known vulnerability in the pkzip stream cipher to
find the internal representation of the encryption key. Once the
internal representation of the key has been found, we try to find the
actual (or an equivalent) password.

Example 1:
Try to find archive.zip password by using plaintext bytes from
plain.bin (map bytes 100-650 of plain.bin to bytes 112-662 of
archive.zip, first cipher byte is at offset 64):

    yazc plaintext -o plain.bin 100 650 archive.zip 112 662 64

Example 2:
Try to find the password by mapping the plaintext bytes of
document.txt from plaintext.zip to the encrypted version found in
encrypted.zip:

    yazc plaintext plaintext.zip document.txt encrypted.zip document.txt

Info
----
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

License
=======
Distributed under the GPLv3+ license. See `COPYING` for more information.

Contact
=======
Marc Ferland - marc.ferland@gmail.com
