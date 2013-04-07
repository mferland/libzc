EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I${top_srcdir}/src

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

pkginclude_HEADERS = src/libzc.h
lib_LTLIBRARIES = src/libzc.la

src_libzc_la_SOURCES =\
	src/libzc_private.h \
	src/libzc.c \
	src/zc_file.c \
	src/zip.c \
	src/zc_pwgen.c \
	src/zc_crack.c

EXTRA_DIST += src/libzc.sym

src_libzc_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libzc.sym
src_libzc_la_DEPENDENCIES = ${top_srcdir}/src/libzc.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = src/libzc.pc
EXTRA_DIST += src/libzc.pc.in
CLEANFILES += src/libzc.pc

TESTS = src/test_libzc
check_PROGRAMS = src/test_libzc
src_test_libzc_SOURCES = src/test_libzc.c src/test_file.c src/test_pwgen.c src/test_crack.c src/libzc.h
src_test_libzc_CFLAGS = @CHECK_CFLAGS@
src_test_libzc_LDADD = src/libzc.la @CHECK_LIBS@

if BUILD_YAZC
bin_PROGRAMS = yazc/yazc

yazc_yazc_SOURCES = yazc/yazc.c
yazc_yazc_CPPFLAGS = $(AM_CPPFLAGS)
yazc_yazc_CFLAGS = $(AM_CFLAGS)
yazc_yazc_LDADD = src/libzc.la

endif
