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

EXTRA_DIST = mask_scanner.h
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\"

AM_CFLAGS = \
        -Wall -Wextra  \
	-ffunction-sections \
	-fdata-sections

noinst_LTLIBRARIES = libyazc-core.la
libyazc_core_la_SOURCES =\
	common.c \
	compat.c \
	compat.h \
	crc32.h \
	decrypt_byte.h \
	find_password.c \
	inflate.c \
	libzc.c \
	libzc.h \
	libzc_private.h \
	list.h \
	mask_scanner.l \
	mask_parser.y \
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

BUILT_SOURCES = mask_parser.c mask_parser.h mask_scanner.c

YACC = bison -o y.tab.c
AM_YFLAGS = -d
LEX = flex
