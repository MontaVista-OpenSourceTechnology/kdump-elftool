AC_INIT([kdump-elftool], [1.4.0], [minyard@mvista.com])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CONFIG_HEADER([config.h])
AC_CHECK_HEADER([gelf.h], [],
                [AC_MSG_ERROR([gelf.h not found, please install the libelf developement package])])
AC_OUTPUT([Makefile])
