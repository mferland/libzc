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

EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\"

AM_CFLAGS = \
        -Wall -Wextra  \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

# - Start with version information of '0:0:0' for each libtool library.
# - Update the version information only immediately before a public release
#   of your software. More frequent updates are unnecessary, and only
#   guarantee that the current interface number gets larger faster.
# - If the library source code has changed at all since the last update,
#   then increment revision ('c:r:a' becomes 'c:r+1:a').
# - If any interfaces have been added, removed, or changed since the last
#   update, increment current, and set revision to 0.
# - If any interfaces have been added since the last public release, then
#   increment age.
# - If any interfaces have been removed or changed since the last public
#   release, then set age to 0. 
LIBZC_CURRENT=6
LIBZC_REVISION=0
LIBZC_AGE=0

lib_LTLIBRARIES = libzc.la
libzc_la_SOURCES =\
	bitmap.c \
	bitmap.h \
	common.c \
	crc32.h \
	decrypt_byte.h \
	find_password.c \
	inflate.c \
	libzc.c \
	libzc.h \
	libzc_private.h \
	list.h \
	ptext_attack.c \
	ptext_private.h \
	ptext_reduce.c \
	pwstream.c \
	pwstream.h \
	pool.c \
	pool.h \
	bforce.c \
	dict.c \
	ptext.c \
	file.c \
	sys.c \
	qsort.h \
	qsort.c \
	uniq.c

include_HEADERS = libzc.h

libzc_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE)
libzc_la_LIBADD = -lm ${ZLIB_LIBS}

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzc.pc
CLEANFILES += libzc.pc
