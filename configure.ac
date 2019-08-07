AC_INIT([kdump-elftool], [1.4.0], [minyard@mvista.com])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CONFIG_HEADER([config.h])
AC_CHECK_HEADER([gelf.h], [],
                [AC_MSG_ERROR([gelf.h not found, please install the libelf developement package])])
AC_CHECK_HEADER([zlib.h], [],
                [AC_MSG_ERROR([zlib.h not found, please install the zlib developement package])])
AC_CHECK_LIB(z, uncompress, , [AC_MSG_ERROR([Could not find proper libz library])])
AC_OUTPUT([Makefile])
