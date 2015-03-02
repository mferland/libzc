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

# The rules of thumb, when dealing with these values are:
#  Always increase the revision value.
#  Increase the current value whenever an interface has been added, removed or changed.
#  Increase the age value only if the changes made to the ABI are backward compatible. 
LIBZC_CURRENT=1
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
	lib/zc_crk.c \
	lib/zc_pwdict.c \
	lib/zc_crk_ptext.c \
	lib/key_table.c \
	lib/key2_reduce.c

EXTRA_DIST += lib/libzc.sym

lib_libzc_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBZC_CURRENT):$(LIBZC_REVISION):$(LIBZC_AGE) \
	-Wl,--version-script=$(top_srcdir)/lib/libzc.sym
lib_libzc_la_DEPENDENCIES = ${top_srcdir}/lib/libzc.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lib/libzc.pc
EXTRA_DIST += lib/libzc.pc.in
CLEANFILES += lib/libzc.pc

TESTS = lib/test_libzc lib/test_keytable lib/test_key2reduce
check_PROGRAMS = lib/test_libzc lib/test_keytable lib/test_key2reduce
lib_test_libzc_SOURCES = lib/test_libzc.c \
	lib/test_file.c \
	lib/test_pwgen.c \
	lib/test_crk.c \
	lib/test_pwdict.c \
	lib/test_crk_ptext.c \
	lib/libzc.h
lib_test_libzc_CFLAGS = @CHECK_CFLAGS@
lib_test_libzc_LDADD = lib/libzc.la @CHECK_LIBS@

lib_test_keytable_SOURCES = lib/test_key_table.c lib/key_table.c lib/key_table.h
lib_test_keytable_CFLAGS = @CHECK_CFLAGS@
lib_test_keytable_LDADD = @CHECK_LIBS@

lib_test_key2reduce_SOURCES = lib/test_key2_reduce.c lib/key2_reduce.c lib/key2_reduce.h lib/key_table.c
lib_test_key2reduce_CFLAGS = @CHECK_CFLAGS@
lib_test_key2reduce_LDADD = @CHECK_LIBS@

if BUILD_YAZC
bin_PROGRAMS = bin/yazc

bin_yazc_SOURCES = bin/yazc.c \
	bin/yazc-bruteforce.c \
	bin/yazc-dictionary.c \
	bin/yazc-common.c \
	bin/cleanupqueue.c \
	bin/yazc-plaintext.c \
	bin/yazc-info.c
bin_yazc_CPPFLAGS = $(AM_CPPFLAGS)
bin_yazc_CFLAGS = $(AM_CFLAGS) -pthread
bin_yazc_LDADD = lib/libzc.la

endif
