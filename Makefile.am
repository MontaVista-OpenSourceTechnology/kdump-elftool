bin_PROGRAMS = kdump-elftool
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS=-Wall
kdump_elftool_SOURCES = elfc.c kdump-elftool.c list.c oldmem.c \
	kdump-x86_64.c kdump-i386.c kdump-mips.c kdump-arm.c kdump-ppc32.c \
	kdump-arm64.c qemumem.c rawfile.c makedumpfile.c diskdumpmem.c
noinst_HEADERS = elfc.h kdump-elftool.h list.h
man_MANS = kdump-elftool.1
dist_pkgdata_DATA = kdump_gdbinit
EXTRA_DIST = $(man_MANS)
