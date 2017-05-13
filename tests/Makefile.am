TESTS = basic file pwstream bruteforce dictionary reduce plaintext_password plaintext

check_PROGRAMS = basic \
	file \
	pwstream \
	bruteforce \
	dictionary \
	reduce \
	plaintext_password \
	plaintext

# basic functions test
basic_SOURCES = check_basic.c
basic_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
basic_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# zc_file related functions
file_SOURCES = check_file.c
file_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
file_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# zc_crk_bforce related functions
bruteforce_SOURCES = check_bruteforce.c
bruteforce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
bruteforce_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# zc_crk_dict related functions
dictionary_SOURCES = check_dictionary.c
dictionary_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
dictionary_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# pwstream related functions
pwstream_SOURCES = check_pwstream.c
pwstream_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
pwstream_LDADD = $(top_srcdir)/lib/pwstream.lo @CHECK_LIBS@

# reduce related functions
reduce_SOURCES = check_reduce.c
reduce_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
reduce_LDADD = $(top_srcdir)/lib/key2_reduce.lo \
	$(top_srcdir)/lib/ka.lo \
	@CHECK_LIBS@

# plaintext password functions
plaintext_password_SOURCES = check_plaintext_password.c
plaintext_password_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_password_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@

# plaintext related functions
plaintext_SOURCES = check_plaintext.c
plaintext_CFLAGS = @CHECK_CFLAGS@ -I$(top_srcdir)/lib
plaintext_LDADD = $(top_srcdir)/lib/libzc.la @CHECK_LIBS@
