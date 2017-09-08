AC_PREREQ(2.60)
AC_INIT([zc],
        [0.3.4],
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

AC_CANONICAL_HOST

build_linux=no
build_mac=no

# Detect the target system
case "${host_os}" in
    linux*)
        build_linux=yes
        ;;
    darwin*)
        build_mac=yes
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac
AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([OSX], [test "$build_mac" = "yes"])

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
