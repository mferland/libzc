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

TESTS = basic compat file pwstream pool bruteforce dictionary reduce plaintext_password plaintext cli
TESTS_ENVIRONMENT = YAZC='$(abs_top_builddir)/yazc/yazc'; export YAZC;

check_PROGRAMS = basic \
	compat \
	file \
	pwstream \
	pool \
	bruteforce \
	dictionary \
	reduce \
	plaintext_password \
	plaintext

AM_CPPFLAGS = -Wall -Wextra -DDATADIR='"$(srcdir)/"' @CPPFLAGS@

EXTRA_DIST = noradi.zip \
	bruteforce_max_length.zip \
	bruteforce_mixed_methods.zip \
	bruteforce_one_char.zip \
	bruteforce_special_chars.zip \
	bruteforce_unsupported_method.zip \
	mask_options.zip \
	pay.zip \
	pw.txt \
	stored.zip \
	test_non_encrypted.zip \
	test.zip \
	test_zyx.zip \
	dict.txt \
	cli

TEST_CORE = $(top_builddir)/lib/libyazc-core.a -lm $(ZLIB_LIBS)

# basic functions test
basic_SOURCES = check_basic.c
basic_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
basic_LDADD = $(TEST_CORE) @CHECK_LIBS@

# compatibility functions
compat_SOURCES = check_compat.c
compat_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
compat_LDADD = $(TEST_CORE) @CHECK_LIBS@

# zc_file related functions
file_SOURCES = check_file.c
file_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
file_LDADD = $(TEST_CORE) @CHECK_LIBS@

# zc_crk_bforce related functions
bruteforce_SOURCES = check_bruteforce.c
bruteforce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
bruteforce_LDADD = $(TEST_CORE) @CHECK_LIBS@

# zc_crk_dict related functions
dictionary_SOURCES = check_dictionary.c
dictionary_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
dictionary_LDADD = $(TEST_CORE) @CHECK_LIBS@

# pwstream related functions
pwstream_SOURCES = check_pwstream.c
pwstream_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
pwstream_LDADD = $(TEST_CORE) @CHECK_LIBS@

# pool related functions
pool_SOURCES = check_pool.c
pool_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
pool_LDADD = $(TEST_CORE) @CHECK_LIBS@

# reduce related functions
reduce_SOURCES = check_reduce.c test_plaintext.h
reduce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
reduce_LDADD = $(TEST_CORE) @CHECK_LIBS@

# plaintext password functions
plaintext_password_SOURCES = check_plaintext_password.c
plaintext_password_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_password_LDADD = $(TEST_CORE) @CHECK_LIBS@

# plaintext related functions
plaintext_SOURCES = check_plaintext.c
plaintext_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_LDADD = $(TEST_CORE) @CHECK_LIBS@
