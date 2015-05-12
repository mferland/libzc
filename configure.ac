AC_PREREQ(2.60)
AC_INIT([zc],
        [0.1.0],
        [marc.ferland@gmail.com],
        [libzc],
        [http://github.com/mferland/libzc])
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

AC_CHECK_PROG([UNZIP], [unzip], [yes])
if test x"$UNZIP" != x"yes" ; then
    AC_MSG_ERROR([unzip command missing.])
fi

AC_CHECK_LIB(pthread, pthread_create)

PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE([logging],
        AS_HELP_STRING([--disable-logging], [disable system logging @<:@default=enabled@:>@]),
        [], enable_logging=yes)
AS_IF([test "x$enable_logging" = "xyes"], [
        AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
])

AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])])

AC_ARG_ENABLE([tests],
        AS_HELP_STRING([--enable-tests], [enable automated testing @<:@default=disabled@:>@]),
        [], [enable_tests=no])
AS_IF([test "x$enable_tests" = "xyes"], [PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])])
AM_CONDITIONAL([BUILD_TESTS], [test "x$enable_tests" = "xyes"])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
        Makefile
        lib/Makefile
        yazc/Makefile
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
        ldflags:                ${LDFLAGS}

        logging:                ${enable_logging}
        debug:                  ${enable_debug}
        tests:                  ${enable_tests}
])
