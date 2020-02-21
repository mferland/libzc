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

AC_PREREQ(2.60)
AC_INIT([zc],
        [0.4.2],
        [marc.ferland@gmail.com],
        [libzc],
        [http://github.com/mferland/libzc])
m4_include([m4/ax_pthread.m4])
AC_CONFIG_SRCDIR([lib/libzc.c])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-extra-portability])
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT([disable-static pic-only])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O

AX_PTHREAD([CLIBS="$PTHREAD_LIBS $LIBS"
            CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
            LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"])

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(ZLIB, zlib)
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [HAVE_CHECK=1], [HAVE_CHECK=0])
AM_CONDITIONAL([USE_CHECK], [test "$HAVE_CHECK" -eq 1])

AC_ARG_ENABLE([logging],
        AS_HELP_STRING([--disable-logging], [disable system logging @<:@default=enabled@:>@]),
        [], enable_logging=yes)
AS_IF([test "x$enable_logging" = "xyes"], [
        AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
])

AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [
            AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
            AC_DEFINE(NDEBUG, [], [Assert macro.])
])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
        Makefile
        lib/Makefile
        yazc/Makefile
        tests/Makefile
        lib/libzc.pc
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE $VERSION
        ===========

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LIBS} ${LDFLAGS}

        logging:                ${enable_logging}
        debug:                  ${enable_debug}
])
