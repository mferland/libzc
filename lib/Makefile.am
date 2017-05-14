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

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed \
	-Wl,-z,defs \
	-lm ${ZLIB_LIBS}

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
LIBZC_CURRENT=3
LIBZC_REVISION=1
LIBZC_AGE=0

lib_LTLIBRARIES = libzc.la
libzc_la_SOURCES =\
	crc32.h \
	libzc.c \
	pwstream.h \
	decrypt_byte.h \
	libzc.h \
	qsort.h \
	ka.c \
	libzc_private.h \
	zc_crk_bforce.c \
	key2_reduce.c \
	list.h \
	zc_crk_ptext.c \
	key2_reduce.h \
	pwstream.c \
	zc_file.c \
	common.c \
	zc_crk_dict.c \
	inflate.c \
	find_password.c
include_HEADERS = libzc.h

libzc_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzc.pc
CLEANFILES += libzc.pc
