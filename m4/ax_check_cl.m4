# -*- mode: autoconf -*-
#
# AX_CHECK_CL
#
# Check for an OpenCL implementation.  If CL is found, the required compiler
# and linker flags are included in the output variables "CL_CFLAGS" and
# "CL_LIBS", respectively.  If no usable CL implementation is found, "no_cl"
# is set to "yes".
#
# If the header "CL/cl.h" is found, "HAVE_CL_CL_H" is defined.  If the header
# "OpenCL/cl.h" is found, HAVE_OPENCL_CL_H is defined.  These preprocessor
# definitions may not be mutually exclusive.
#
# Based on AX_CHECK_GL, version: 2.4 author: Braden McDaniel
# <braden@endoframe.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# As a special exception, the you may copy, distribute and modify the
# configure scripts that are the output of Autoconf when processing
# the Macro.  You need not follow the terms of the GNU General Public
# License when using or distributing such scripts.
#

AC_DEFUN([AX_CHECK_CL], [

AC_LANG_PUSH([C])

ax_save_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$CL_CFLAGS $CPPFLAGS"
AC_CHECK_HEADERS([CL/cl.h OpenCL/cl.h])
CPPFLAGS=$ax_save_CPPFLAGS

m4_define([AX_CHECK_CL_PROGRAM],
          [AC_LANG_PROGRAM([[
# if defined(HAVE_WINDOWS_H) && defined(_WIN32)
#   include <windows.h>
# endif
# ifdef HAVE_CL_CL_H
#   include <CL/cl.h>
# elif defined(HAVE_OPENCL_CL_H)
#   include <OpenCL/cl.h>
# else
#   error no cl.h
# endif]],
                           [[clFinish(0)]])])

AC_CACHE_CHECK([for OpenCL library], [ax_cv_check_cl_libcl],
[ax_cv_check_cl_libcl=no
ax_save_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$CL_CFLAGS $CPPFLAGS"
ax_save_LIBS=$LIBS
LIBS=""
ax_check_libs="-lOpenCL -lCL"
for ax_lib in $ax_check_libs
do
  LIBS="$ax_lib $CL_LIBS $ax_save_LIBS"
  AC_LINK_IFELSE([AX_CHECK_CL_PROGRAM],
                 [ax_cv_check_cl_libcl="$ax_lib"; break])
done
LIBS=$ax_save_LIBS
CPPFLAGS=$ax_save_CPPFLAGS])

AS_IF([test "X$ax_cv_check_cl_libcl" = Xno],
      [no_cl=yes; CL_CFLAGS=""; CL_LIBS=""],
      [CL_LIBS="$ax_cv_check_cl_libcl $CL_LIBS"])

AC_LANG_POP([C])

AC_SUBST([CL_CFLAGS])
AC_SUBST([CL_LIBS])

])
