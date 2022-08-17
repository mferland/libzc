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

TESTS = basic file pwstream pool bruteforce dictionary reduce plaintext_password plaintext

check_PROGRAMS = basic \
	file \
	pwstream \
	pool \
	bruteforce \
	dictionary \
	reduce \
	plaintext_password \
	plaintext

AM_CPPFLAGS = -Wall -Wextra -DDATADIR='"$(top_srcdir)/data/"' @CPPFLAGS@

# basic functions test
basic_SOURCES = check_basic.c
basic_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
basic_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@

# zc_file related functions
file_SOURCES = check_file.c
file_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
file_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@

# zc_crk_bforce related functions
bruteforce_SOURCES = check_bruteforce.c
bruteforce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
bruteforce_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@

# zc_crk_dict related functions
dictionary_SOURCES = check_dictionary.c
dictionary_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
dictionary_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@

# pwstream related functions
pwstream_SOURCES = check_pwstream.c
pwstream_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
pwstream_LDADD = $(top_builddir)/lib/pwstream.lo @CHECK_LIBS@ -lm

# pool related functions
pool_SOURCES = check_pool.c
pool_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
pool_LDADD = $(top_builddir)/lib/pool.lo \
	$(top_builddir)/lib/sys.lo \
	$(top_builddir)/lib/libzc.lo \
	@CHECK_LIBS@

# reduce related functions
reduce_SOURCES = check_reduce.c
reduce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
reduce_LDADD = $(top_builddir)/lib/libzc.la \
	$(top_builddir)/lib/ptext.lo \
	$(top_builddir)/lib/pool.lo \
	$(top_builddir)/lib/sys.lo \
	$(top_builddir)/lib/qsort.lo \
	@CHECK_LIBS@

# plaintext password functions
plaintext_password_SOURCES = check_plaintext_password.c
plaintext_password_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_password_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@

# plaintext related functions
plaintext_SOURCES = check_plaintext.c
plaintext_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_LDADD = $(top_builddir)/lib/libzc.la @CHECK_LIBS@
