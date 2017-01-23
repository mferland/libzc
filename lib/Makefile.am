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
	-pthread -lz

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed \
	-Wl,-z,defs \
	-lm

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
LIBZC_CURRENT=2
LIBZC_REVISION=0
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
	zc_crk_dict.c
include_HEADERS = libzc.h

libzc_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzc.pc
CLEANFILES += libzc.pc

# automated tests
if BUILD_TESTS
TESTS = test_libzc test_ka test_pwstream test_key2reduce
check_PROGRAMS = test_libzc test_ka test_pwstream test_key2reduce

# test_libzc
test_libzc_SOURCES = \
        test_libzc.c \
	test_file.c \
	test_crk.c \
	test_pwdict.c \
	test_crk_ptext.c \
	libzc.h
test_libzc_CFLAGS = @CHECK_CFLAGS@
test_libzc_LDADD = libzc.la @CHECK_LIBS@

# test_ka
test_ka_SOURCES = test_ka.c ka.c libzc_private.h
test_ka_CFLAGS = @CHECK_CFLAGS@
test_ka_LDADD = @CHECK_LIBS@

# test_pwstream
test_pwstream_SOURCES = test_pwstream.c pwstream.c libzc_private.h
test_pwstream_CFLAGS = @CHECK_CFLAGS@
test_pwstream_LDADD = @CHECK_LIBS@

# test_key2reduce
test_key2reduce_SOURCES = test_key2_reduce.c key2_reduce.c key2_reduce.h ka.c libzc_private.h
test_key2reduce_CFLAGS = @CHECK_CFLAGS@
test_key2reduce_LDADD = @CHECK_LIBS@
endif
