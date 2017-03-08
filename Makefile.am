bin_PROGRAMS = kdump-elftool
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS=-Wall
kdump_elftool_SOURCES = elfc.c kdump-elftool.c list.c oldmem.c \
	kdump-x86_64.c kdump-i386.c kdump-mips.c kdump-arm.c kdump-ppc32.c
noinst_HEADERS = elfc.h kdump-elftool.h list.h
man_MANS = kdump-elftool.1
EXTRA_DIST = $(man_MANS)
