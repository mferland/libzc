What is it?
===========
The libz library is a simple zip cracking library. It also comes with
a command line tool called 'yazc' (Yet Another Zip Cracker).

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
There are currently 2 attack modes available:

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
