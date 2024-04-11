AC_INIT([kdump-elftool],[1.5.1],[minyard@mvista.com])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
LT_INIT
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADER([gelf.h], [],
                [AC_MSG_ERROR([gelf.h not found, please install the libelf developement package])])
AC_CHECK_HEADER([zlib.h], [],
                [AC_MSG_ERROR([zlib.h not found, please install the zlib developement package])])
AC_CHECK_LIB(z, uncompress, , [AC_MSG_ERROR([Could not find proper libz library])])
AC_CHECK_HEADER([lzo/lzo1x.h], [],
                [AC_MSG_ERROR([lzo1x.h not found, please install the lzo2 developement package])])
AC_CHECK_LIB(lzo2, lzo1x_decompress_safe, , [AC_MSG_ERROR([Could not find proper liblzo2 library])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
