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

bin_PROGRAMS = yazc
yazc_SOURCES = \
	yazc.c \
	bruteforce.c \
	dictionary.c \
	plaintext.c \
	info.c \
	yazc.h
yazc_CFLAGS = $(AM_CFLAGS) -Wall -Wextra -I$(top_srcdir)/lib
yazc_LDADD = $(top_builddir)/lib/libzc.la
dist_man_MANS = yazc.1
docdir = $(datadir)/doc/yazc
doc_DATA = $(top_srcdir)/README.md
