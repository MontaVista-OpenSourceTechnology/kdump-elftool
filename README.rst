=============
kdump-elftool
=============

This is kdump-elftool, a tool for creating usable coredumps from a
kernel crash.

You will need to patch your kernel with the patches in
"kernel-patches" before this will work.  These patches add system
memory ranges and the physical address of the kernel page table to the
data passed from the old kernel to the new kernel.  The MIPS-specific
patch is only required for MIPS, obviously, it adds a boatload of
parameters that are required to successfully navigate the page tables.

Building
========

Build Requirements
------------------

The libelf developement package must be installed.  Only the include
files are used, the libelf library itself is not used.

autoconf, automake, and libtool must be installed if you download
from git directly.

kdump-elftool has no other external requirements beyond the standard
library.

Setting up autotools
--------------------

If you download this program directly from git, it will not be
set up properly.  You must run the following commands to set it
up so it can be configured and built:

  libtoolize
  aclocal
  autoconf
  autoheader
  automake -a

If you download a tar file with the program, it most likely already
has done this, so you can skip to the next section.

Then see the install program for standard autotools instructions.

Getting a Kernel Coredump
=========================

To use this, you must get a dump of kernel memory.  You have two
options: use kexec/kdump (optionally with makedumpfile), or take a
vmdump from qemu if you are running in qemu.

kexec/kdump
-----------

For kexec/kdump see the man page for kexec for instructions to get
into a crash dump kernel (the kernel that boots from the crashed
kernel).  It will have /dev/oldmem and /proc/vmcore available.

Run "kdump-elftool topelf -o pmcore" and copy pmcore to your system
where you will be doing the analysis.  Or do:

  kdump-elftool topelf | gzip >pmcore.gz

to compress it, probably a good idea as it will compress quite well.

Before doing analysis, uncompress it if necessary and then run:

  kdump-elftool tovelf -i pmcore -o vmcore

to generate the gdb-usable core file.

If your kernel use a randomized base, you need the original vmlinux
file so kdump-elftool can calculate the offsets.  Use the following
options to tovelf instead:

  kdump-elftool tovelf -i pmcore -o vmcore -m vmlinux

Then run:

  kdump-elftool makedyn vmlinux

to convert the vmlinux file into a relocatable executable.  Then gdb
will be able to debug it without issues. If you forget to add the -m
option to running tovelf, all is not lost.  You can do:

  kdump-elftool addrandoff -m vmlinux -v vmcore

to add the information to an existing vmcore file.  This will replace
any existing offset information.

makedumpfile
------------

If you have a dump taken with makedumpfile, kdump-elftool might be
able to read it.  Currently it only works with x86_64, but adding
new machines should be simple.

You might have to add a vminfo file if the dump file does not have
vmcoreinfo data in it, the tool will tell you if that is the case.
This is the same procedure as getting the vminfo file in qemu
below.

qemu
----

To save a vmdump from the qemu console, run the command:

  (qemu) migrate "exec:cat >qemu-vmdump"

Or, to compress it, do:

  (qemu) migrate "exec:gzip >qemu-vmdump.gz"

The kdump-elftool man page has instructions in the QEMU VMDUMP section
on how convert this to a vmcore file.  You will need the original vmlinux
file the dump was taken with, and you will need the kdump_gdbinit
file from kdump-elftool.

If the kernel was compiled with crash dump support (CONFIG_CRASH_DUMP)
you can do:

  gdb vmlinux
  (gdb) source ../kdump_gdbinit
  (gdb) vminfo_qemu_base

vminfo_qemu_base will dump out a bunch of information in a format
that kdump-elftool understands about internal symbols.  Then you can
save the output of vminfo_qemu_baseto a file name vminfo and run:
  kdump-elftool tovelf -I qemu -i qemu_vmcore -e vminfo --m64 -o vmcore
This is for a 64-bit virtual machine (qemu-system-x86_64).  You must
use --m64 even if you ran a 32-bit kernel in it.  If you used a 32-bit
virtual machine (qemu-system-i386), thne use --m32 instead of --m64.
kdump-elftool will pull the rest of the values it needs from the crash
dump info section of the kernel.

If the kernel was not compiled with CONFIG_CRASH_DUMP, then things
get quite a bit harder.  Instead of running vminfo_qemu_base, you
must run vminfo_qemu_all.  This will output several parameters with
"??" for the values.  You have to find the values for your kernel and
put them in.  Then the procedure is the same after that.

Kernel Threads
==============

By default, each CPU will appear as a thread in gdb, so you will be
able to see the state of each running thread, backtrace it, look at
local variables, etc.  For architectures that support it, you can tell
kdump-elftool to create a thread for each process/thread running in the
system, so you can backtrace and look at local variables for processes
that were not running when the system crashed.

The kernel crash information does not have all the info required to do
this, however.  But it can be extracted from the vmlinux file for the
running kernel.  You will keed kdump_gdbinit from the kdump-elftool
package.  To do this:

  gdb vmlinux
  (gdb) source ../kdump_gdbinit
  (gdb) thread_vminfo_<arch>

where <arch> is one of mips, arm, i386, or x86_64.  Save the output of
that last command to a file name vminfo.  Then you will need to add
the vmlinux file and the vminfo file to the conversion command, along
with "-p", like:

  kdump-elftool tovelf -i pmcore -o vmcore -m vmlinux -e vminfo -p

and the thread information will be added to the vmcore file.

The procedure is fairly involved for older kernels (before 4.9) on
x86_64, as some vital information is missing from the kernel
information.  See the man page for details on that.

Coredump Analysis
=================

Then do:
  gdb vmlinux vmcore

For more information, see:
http://www.elinux.org/Debugging_The_Linux_Kernel_Using_Gdb

The kdump_gdbinit program has some helper functions to make your life
a little easier.  Inside gdb you have to "source" that file.  The
following are available:

  dmesg - Dump the kernel log

  ps - Dump the running processes

  ps_old - ps for older kernels (before 3.10) that had a different
     thread setup

  lsmod - List modules and their bases.  This is useful for loading
     symbol tables from module .o files.

Modules
-------

To make module symbols available to gdb, you have to load the module
symbols.  To do this, use lsmod to dump a list of the modules, get the
"Base Addr" for the module you are interested in, and run the command:

  add-symbol-file <module .o> <Base Addr>

Note that you use the .o file, not the .ko file, for the module, and
the module must match the kernel, of course.
