EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I${top_srcdir}/lib

AM_CFLAGS = ${my_CFLAGS} \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

LIBZC_CURRENT=0
LIBZC_REVISION=0
LIBZC_AGE=0

pkginclude_HEADERS = lib/libzc.h
lib_LTLIBRARIES = lib/libzc.la

lib_libzc_la_SOURCES =\
	lib/libzc_private.h \
	lib/libzc.c \
	lib/zc_file.c \
	lib/zip.c \
	lib/zc_pwgen.c \
	lib/zc_crack.c

EXTRA_DIST += lib/libzc.sym

lib_libzc_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE) \
	-Wl,--version-script=$(top_srcdir)/lib/libzc.sym
lib_libzc_la_DEPENDENCIES = ${top_srcdir}/lib/libzc.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lib/libzc.pc
EXTRA_DIST += lib/libzc.pc.in
CLEANFILES += lib/libzc.pc

TESTS = lib/test_libzc
check_PROGRAMS = lib/test_libzc
lib_test_libzc_SOURCES = lib/test_libzc.c lib/test_file.c lib/test_pwgen.c lib/test_crack.c lib/libzc.h
lib_test_libzc_CFLAGS = @CHECK_CFLAGS@
lib_test_libzc_LDADD = lib/libzc.la @CHECK_LIBS@

if BUILD_YAZC
bin_PROGRAMS = bin/yazc

bin_yazc_SOURCES = bin/yazc.c
bin_yazc_CPPFLAGS = $(AM_CPPFLAGS)
bin_yazc_CFLAGS = $(AM_CFLAGS)
bin_yazc_LDADD = lib/libzc.la

endif
