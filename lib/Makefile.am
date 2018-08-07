# Copyright (C) 2012-2018 Marc Ferland
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
	-fdata-sections \
	${CL_CFLAGS}

AM_LDFLAGS = -lm ${ZLIB_LIBS} ${CL_LIBS}

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
LIBZC_CURRENT=4
LIBZC_REVISION=1
LIBZC_AGE=0

if USE_OPENCL
OCL_SRC = zc_crk_ocl.c
endif

lib_LTLIBRARIES = libzc.la
libzc_la_SOURCES =\
	common.c \
	crc32.h \
	decrypt_byte.h \
	find_password.c \
	inflate.c \
	ka.c \
	libzc.c \
	libzc.h \
	libzc_private.h \
	list.h \
	ptext_attack.c \
	ptext_private.h \
	ptext_reduce.c \
	pwstream.c \
	pwstream.h \
	qsort.h \
	zc_crk_bforce.c \
	$(OCL_SRC) \
	zc_crk_dict.c \
	zc_crk_ptext.c \
	zc_file.c
include_HEADERS = libzc.h

libzc_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzc.pc
CLEANFILES += libzc.pc
