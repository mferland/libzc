bin_PROGRAMS = yazc
yazc_SOURCES = \
	yazc.c \
	yazc-bruteforce.c \
	yazc-dictionary.c \
	yazc-common.c \
	yazc-plaintext.c \
	yazc-info.c \
	yazc.h
yazc_CFLAGS = $(AM_CFLAGS) -Wall -Wextra -I$(top_srcdir)/lib
yazc_LDADD = $(top_srcdir)/lib/libzc.la
dist_man_MANS = yazc.1
