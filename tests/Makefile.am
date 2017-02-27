TESTS = check_basic check_file

check_PROGRAMS = check_basic check_file

# basic functions test
check_basic_SOURCES = check_basic.c $(top_srcdir)/lib/libzc.h
check_basic_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
check_basic_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# zc_file related functions
check_file_SOURCES = check_file.c $(top_srcdir)/lib/libzc.h
check_file_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
check_file_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@
