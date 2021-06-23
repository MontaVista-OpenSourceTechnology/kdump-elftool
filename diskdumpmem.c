/*
 * diskdumpmem.c
 *
 * Handling for reading diskdump vmdump files
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2019 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * A lot of this was lifted from the crash utility's qemu dump code.
 */

#include "kdump-elftool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <assert.h>
#include <zlib.h>

#include "elfc.h"
#include "kdump-x86.h"


struct new_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
        char domainname[65];
};

struct timeval64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

struct timeval32 {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct task_struct;

#define KDUMP_SIG		"KDUMP   "

struct disk_dump_header {
	char			signature[8];	/* = "DISKDUMP", "KDUMP   " */
	int			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	struct timeval64	timestamp;	/* Time stamp */
	unsigned int		status; 	/* Above flags */
	int			block_size;	/* Size of a block in byte */
	int			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	unsigned int		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	unsigned int		max_mapnr;	/* = max_mapnr, OBSOLETE!
						   32bit only, full 64bit
						   in sub header. */
	unsigned int		total_ram_blocks;/* Number of blocks should be
						   written */
	unsigned int		device_blocks;	/* Number of total blocks in
						 * the dump device */
	unsigned int		written_blocks; /* Number of written blocks */
	unsigned int		current_cpu;	/* CPU# which handles dump */
	int			nr_cpus;	/* Number of CPUs */
	struct task_struct	*tasks[0];
};

struct kdump_sub_header32 {
	uint32_t	phys_base;
	int		dump_level;         /* header_version 1 and later */
	int		split;              /* header_version 2 and later */
	uint32_t	start_pfn;          /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in start_pfn_64. */
	uint32_t	end_pfn;            /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in end_pfn_64. */
	uint32_t	offset_vmcoreinfo;  /* header_version 3 and later */
	uint32_t	size_vmcoreinfo;    /* header_version 3 and later */
	uint32_t	offset_note;        /* header_version 4 and later */
	uint32_t	size_note;          /* header_version 4 and later */
	uint32_t	offset_eraseinfo;   /* header_version 5 and later */
	uint32_t	size_eraseinfo;     /* header_version 5 and later */
	uint64_t	start_pfn_64;       /* header_version 6 and later */
	uint64_t	end_pfn_64;         /* header_version 6 and later */
	uint64_t	max_mapnr_64;       /* header_version 6 and later */
};

struct kdump_sub_header64 {
	uint64_t	phys_base;
	int		dump_level;         /* header_version 1 and later */
	int		split;              /* header_version 2 and later */
	uint64_t	start_pfn;          /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in start_pfn_64. */
	uint64_t	end_pfn;            /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in end_pfn_64. */
	uint64_t	offset_vmcoreinfo;  /* header_version 3 and later */
	uint64_t	size_vmcoreinfo;    /* header_version 3 and later */
	uint64_t	offset_note;        /* header_version 4 and later */
	uint64_t	size_note;          /* header_version 4 and later */
	uint64_t	offset_eraseinfo;   /* header_version 5 and later */
	uint64_t	size_eraseinfo;     /* header_version 5 and later */
	uint64_t	start_pfn_64;       /* header_version 6 and later */
	uint64_t	end_pfn_64;         /* header_version 6 and later */
	uint64_t	max_mapnr_64;       /* header_version 6 and later */
};

struct note_header {
	uint32_t name_size;
	uint32_t data_size;
	uint32_t type;
};

/* flags field in page_desc */
#define DUMP_DH_COMPRESSED_ZLIB    0x1   /* page is compressed with zlib */
#define DUMP_DH_COMPRESSED_LZO     0x2   /* page is compressed with lzo */
#define DUMP_DH_COMPRESSED_SNAPPY  0x4   /* page is compressed with snappy */

struct page_desc64 {
        uint64_t	offset;
        uint32_t	size;
        uint32_t	flags;
        uint64_t	page_flags;
};

struct page_desc32 {
        uint32_t	offset;
        uint32_t	size;
        uint32_t	flags;
        uint64_t	page_flags;
};

/*
 * If a page is not set in bitmap2, then it is not present in the page
 * headers.  To make things easier to calculate, we record the
 * starting location of every 4096th page in page_sect_pfn_start so we
 * only have a small section of memory to look through
 */
#define PAGES_PER_SECT	4096ULL

struct diskdump_info {
	bool is_64bit;
	struct absio *io;
	struct elfc *elf;
	unsigned int blocksize;
	uint32_t (*conv32)(uint32_t v);
	uint64_t (*conv64)(uint64_t v);
	struct disk_dump_header hdr;
	struct kdump_sub_header64 subhdr;
	unsigned char *bitmap1;
	unsigned char *bitmap2;
	off_t page_desc_start;
	uint64_t max_mapnr;
	unsigned char *pgbuf;
	unsigned char *cmpr_pgbuf;

	int64_t *page_sect_pfn_start;
};

static bool
page_dumpable(struct diskdump_info *di, uint64_t pfn)
{
	return (di->bitmap2[pfn >> 3] & (1 << (pfn & 0x7))) != 0;
}

uint64_t
get_pfn_idx(struct diskdump_info *di, uint64_t pfn)
{
	uint64_t idx;
	uint64_t i;

	idx = di->page_sect_pfn_start[pfn / PAGES_PER_SECT];
	for (i = pfn & ~(PAGES_PER_SECT - 1); i < pfn; i++) {
		if (page_dumpable(di, i))
			idx++;
	}
	return idx;
}

static int
mdfmem_read_addr(struct diskdump_info *di, uint64_t addr, unsigned char *buf)
{
	int rv;
	uint64_t pfn = addr / di->blocksize, idx;
	struct page_desc64 pd;

	if (pfn >= di->max_mapnr) {
		fprintf(stderr, "pfn %llu is after end of memory\n",
			(unsigned long long) pfn);
		return -1;
	}

	if (!page_dumpable(di, pfn)) {
		fprintf(stderr, "pfn %llu not present\n",
			(unsigned long long) pfn);
		return -1;
	}

	idx = get_pfn_idx(di, pfn);
	if (di->is_64bit) {
		rv = absio_read(di->io,
				di->page_desc_start + (idx * sizeof(pd)),
				sizeof(pd), &pd);
		if (rv) {
			fprintf(stderr, "can't read page data for pfn %llu\n",
				(unsigned long long) pfn);
			return -1;
		}
		pd.offset = di->conv64(pd.offset);
		pd.size = di->conv32(pd.size);
		pd.flags = di->conv32(pd.flags);
		pd.page_flags = di->conv64(pd.page_flags);
	} else {
		struct page_desc32 p3;

		rv = absio_read(di->io,
				di->page_desc_start + (idx * sizeof(p3)),
				sizeof(p3), &p3);
		if (rv) {
			fprintf(stderr, "can't read page desc for pfn %llu\n",
				(unsigned long long) pfn);
			return -1;
		}
		pd.offset = di->conv32(p3.offset);
		pd.size = di->conv32(p3.size);
		pd.flags = di->conv32(p3.flags);
		pd.page_flags = di->conv64(p3.page_flags);
	}
	if (pd.size > di->blocksize) {
		fprintf(stderr,
			"Invalid page descriptor size for pfn %llu: %d\n",
			(unsigned long long) pfn, pd.size);
		return -1;
	}

	if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
		fprintf(stderr, "LZO compression not supported for pfn %llu\n",
			(unsigned long long) pfn);
		return -1;
	}
	if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {
		fprintf(stderr, "Snappy compression not supported for "
			"pfn %llu\n", (unsigned long long) pfn);
		return -1;
	}

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		uLongf destlen = di->blocksize;

		rv = absio_read(di->io, pd.offset, pd.size, di->cmpr_pgbuf);
		if (!rv) {
			rv = uncompress(buf, &destlen, di->cmpr_pgbuf, pd.size);
			if (rv != Z_OK) {
				fprintf(stderr,
					"Error uncompressing pfn %llu\n",
					(unsigned long long) pfn);
				return -1;
			}
			if (destlen != di->blocksize) {
				fprintf(stderr,
					"Bad size uncompressing pfn %llu, "
					"got %lu, expected %d\n",
					(unsigned long long) pfn, destlen,
					di->blocksize);
				return -1;
			}
			rv = 0;
		}
	} else {
		rv = absio_read(di->io, pd.offset, pd.size, buf);
	}
	if (rv) {
		fprintf(stderr, "can't read page data for pfn %llu\n",
			(unsigned long long) pfn);
		return -1;
	}

	return 0;
}

static int
mdfmem_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
		void *data, void *userdata)
{
	struct diskdump_info *di = userdata;
	int rv, lerrno;
	off_t loff = 0;
	off_t pos;
	off_t left;

	/*
	 * Align on a chunk size and get the offset from there.
	 */
	pos = phdr->p_paddr;
	loff = pos - (pos & ~((off_t) (di->blocksize - 1)));
	pos -= loff;
	left = phdr->p_filesz;

	/*
	 * Copy in sections.
	 */
	while (left > 0) {
		off_t sz = left;

		if (sz + loff > di->blocksize)
			sz = di->blocksize - loff;

		rv = mdfmem_read_addr(di, pos, di->pgbuf);
		if (rv == -1)
			return rv;

		rv = write(fd, di->pgbuf + loff, sz);
		lerrno = errno;
		if (rv == -1) {
			fprintf(stderr,
				"qmem_do_write: Error on write: %s\n",
				strerror(lerrno));
			errno = lerrno;
			return -1;
		}
		left -= sz;
		pos += di->blocksize;
		loff = 0;
	}
	return 0;
}

static int
mdfmem_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
		GElf_Off off, void *odata, size_t len,
		void *userdata)
{
	struct diskdump_info *di = userdata;
	int rv;
	off_t loff;
	off_t pos;
	off_t left;
	char *wdata = odata;

	/*
	 * Align on a chunk size and get the offset from there.
	 */
	pos = phdr->p_paddr + off;
	loff = pos - (pos & ~((off_t) (di->blocksize - 1)));
	pos -= loff;
	left = len;
	assert(len <= phdr->p_filesz);

	/*
	 * Copy in sections.
	 */
	while (left > 0) {
		off_t sz = left;

		if (sz + loff > di->blocksize)
			sz = di->blocksize - loff;

		rv = mdfmem_read_addr(di, pos, di->pgbuf);
		if (rv)
			return -1;
		memcpy(wdata, di->pgbuf + loff, sz);
		wdata += sz;
		left -= sz;
		pos += di->blocksize;
		loff = 0;
	}
	return 0;
}

static int
mdfmem_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
		GElf_Off off, const void *idata, size_t len,
		void *userdata)
{
	return -1;
}

static void
mdfmem_free(struct elfc *e, void *data, void *userdata)
{
	struct diskdump_info *di = userdata;

	if (di->io)
		di->io->free(di->io);
	free(di->bitmap1);
	free(di->page_sect_pfn_start);
	free(di->pgbuf);
	free(di->cmpr_pgbuf);
	free(di);
}

/* xexxtoh may be macros, make sure they are functions. */
static uint32_t
ile32toh(uint32_t v)
{
	return le32toh(v);
}

static uint64_t
ile64toh(uint64_t v)
{
	return le64toh(v);
}

#define align(v, a) (((v) + (a) - 1) & ~((typeof(v)) (a - 1)))

struct elfc *
read_diskdumpmem(struct absio *io, char *extra_vminfo)
{
	int rv;
	struct diskdump_info *di;
	struct vmcoreinfo_data vmci[] = {
		{ "PAGESIZE", 10 },			/* 0 */
		{ "SYMBOL(swapper_pg_dir)", 16 },	/* 1 */
		{ "ADDRESS(phys_pgd_ptr)", 16 },	/* 2 */
		{ "SIZE(list_head)", 10 },		/* 3 */
		{ "SYMBOL(vmcoreinfo_data)", 16 },	/* 4 */
		{ "SYMBOL(_stext)", 16 },		/* 6 */
		{ "SYMBOL(per_cpu__current_task)", 16 },/* 7 */
		{ "OFFSET(task_struct.pid)", 10 },	/* 8 */
		{ "SYMBOL(swapper_pg_dir)", 16 },	/* 9 */
		{ "SYMBOL(init_level4_pgt)", 16 },	/* 10 */
		{ "SYMBOL(init_top_pgt)", 16 },		/* 11 */
		{ NULL }
	};
	struct kdt_data dummy_d;
	char buf[100];
	uint64_t start_kernel;
	int endc;
	off_t pos = 0;
	bool elfc_phdr_set = false;
	uint64_t psect, pfn, num_pghdrstart;

	di = malloc(sizeof(*di));
	if (!di) {
		fprintf(stderr, "Unable to allocate diskdump mem info\n");
		return NULL;
	}
	memset(di, 0, sizeof(*di));
	di->io = io;

	/*
	 * Read the beginning of the header so we can determine what type
	 * of machine this is.
	 */
	rv = absio_read(io, 0, offsetof(struct disk_dump_header, timestamp),
			&di->hdr);
	if (rv) {
		fprintf(stderr, "Error reading diskdump header\n");
		goto out_err;
	}
	pos += offsetof(struct disk_dump_header, timestamp);

	if (memcmp(di->hdr.signature, KDUMP_SIG,
		   sizeof(di->hdr.signature)) != 0) {
		fprintf(stderr, "Unknown dump file type: %s\n",
			di->hdr.signature);
		goto out_err;
	}

	di->elf = elfc_alloc();
	if (!di->elf) {
		fprintf(stderr, "Out of memory allocating elfc\n");
		goto out_err;
	}
	rv = elfc_setup(di->elf, ET_CORE);
	if (rv == -1) {
		fprintf(stderr, "Error setting up elfc: %s\n",
			strerror(elfc_get_errno(di->elf)));
		goto out_err;
	}

	if (strcmp(di->hdr.utsname.machine, "x86_64") == 0) {
		di->is_64bit = true;
		dummy_d.arch = &x86_64_arch;
		di->conv32 = ile32toh;
		di->conv64 = ile64toh;
		elfc_setmachine(di->elf, EM_X86_64);
		elfc_setclass(di->elf, ELFCLASS64);
		elfc_setencoding(di->elf, ELFDATA2LSB);
		start_kernel = 0xffffffff80000000;
	} else {
		fprintf(stderr, "Unknown dump machine type: %s\n",
			di->hdr.utsname.machine);
		goto out_err;
	}

	if (di->conv32(di->hdr.header_version) < 6) {
		fprintf(stderr, "Header version was %d, minimum supported "
			"is 6\n", di->conv32(di->hdr.header_version));
		goto out_err;
	}

	/* Reading the timestamp depends on the machine word size. */
	if (di->is_64bit) {
		struct timeval64 tv;

		rv = absio_read(io, pos, sizeof(tv), &tv);
		if (rv) {
			fprintf(stderr, "Error reading diskdump timestamp\n");
			goto out_err;
		}
		di->hdr.timestamp.tv_sec = di->conv64(tv.tv_sec);
		di->hdr.timestamp.tv_usec = di->conv64(tv.tv_usec);
		pos += sizeof(tv);
	} else {
		struct timeval32 tv;

		rv = absio_read(io, pos, sizeof(tv), &tv);
		if (rv) {
			fprintf(stderr, "Error reading diskdump timestamp\n");
			goto out_err;
		}
		di->hdr.timestamp.tv_sec = di->conv32(tv.tv_sec);
		di->hdr.timestamp.tv_usec = di->conv32(tv.tv_usec);
		pos += sizeof(tv);
	}

	/* Now read the rest of the header. */
	rv = absio_read(io, pos,
			(sizeof(di->hdr) -
			 offsetof(struct disk_dump_header, status)),
			(((unsigned char *) &di->hdr) +
			 offsetof(struct disk_dump_header, status)));
	if (rv) {
		fprintf(stderr, "Error reading diskdump header 2\n");
		goto out_err;
	}

	di->blocksize = di->conv32(di->hdr.block_size);
	if (di->is_64bit) {
		rv = absio_read(io, di->blocksize, sizeof(di->subhdr),
				&di->subhdr);
		if (rv) {
			fprintf(stderr, "Error reading sub header\n");
			goto out_err;
		}
		di->subhdr.phys_base = di->conv64(di->subhdr.phys_base);
		di->subhdr.dump_level = di->conv32(di->subhdr.dump_level);
		di->subhdr.split = di->conv32(di->subhdr.split);
		di->subhdr.start_pfn = di->conv64(di->subhdr.start_pfn);
		di->subhdr.end_pfn = di->conv64(di->subhdr.end_pfn);
		di->subhdr.offset_vmcoreinfo =
			di->conv64(di->subhdr.offset_vmcoreinfo);
		di->subhdr.size_vmcoreinfo =
			di->conv64(di->subhdr.size_vmcoreinfo);
		di->subhdr.offset_note = di->conv64(di->subhdr.offset_note);
		di->subhdr.size_note = di->conv64(di->subhdr.size_note);
		di->subhdr.offset_eraseinfo =
			di->conv64(di->subhdr.offset_eraseinfo);
		di->subhdr.size_eraseinfo =
			di->conv64(di->subhdr.size_eraseinfo);
		di->subhdr.start_pfn_64 = di->conv64(di->subhdr.start_pfn_64);
		di->subhdr.end_pfn_64 = di->conv64(di->subhdr.end_pfn_64);
		di->subhdr.max_mapnr_64 = di->conv64(di->subhdr.max_mapnr_64);
	} else {
		struct kdump_sub_header32 subhdr32;

		rv = absio_read(io, di->blocksize, sizeof(subhdr32), &subhdr32);
		if (rv) {
			fprintf(stderr, "Error reading sub header\n");
			goto out_err;
		}
		di->subhdr.phys_base = di->conv32(subhdr32.phys_base);
		di->subhdr.dump_level = di->conv32(subhdr32.dump_level);
		di->subhdr.split = di->conv32(subhdr32.split);
		di->subhdr.start_pfn = di->conv32(subhdr32.start_pfn);
		di->subhdr.end_pfn = di->conv32(subhdr32.end_pfn);
		di->subhdr.offset_vmcoreinfo =
			di->conv32(subhdr32.offset_vmcoreinfo);
		di->subhdr.size_vmcoreinfo =
			di->conv32(subhdr32.size_vmcoreinfo);
		di->subhdr.offset_note = di->conv32(subhdr32.offset_note);
		di->subhdr.size_note = di->conv32(subhdr32.size_note);
		di->subhdr.offset_eraseinfo =
			di->conv32(subhdr32.offset_eraseinfo);
		di->subhdr.size_eraseinfo = di->conv32(subhdr32.size_eraseinfo);
		di->subhdr.start_pfn_64 = di->conv64(subhdr32.start_pfn_64);
		di->subhdr.end_pfn_64 = di->conv64(subhdr32.end_pfn_64);
		di->subhdr.max_mapnr_64 = di->conv64(subhdr32.max_mapnr_64);
	}

	di->pgbuf = malloc(di->blocksize);
	if (!di->pgbuf) {
		fprintf(stderr, "Could not allocate page buffer\n");
		goto out_err;
		
	}

	di->cmpr_pgbuf = malloc(di->blocksize);
	if (!di->cmpr_pgbuf) {
		fprintf(stderr, "Could not allocate compressed page buffer\n");
		goto out_err;
		
	}

	if (di->subhdr.size_vmcoreinfo == 0 && !extra_vminfo) {
		fprintf(stderr, "No vmcoreinfo in makedump, must supply on the "
			"command line\n");
		goto out_err;
	}

	if (di->subhdr.size_vmcoreinfo) {
		char *vmc = malloc(di->subhdr.size_vmcoreinfo);

		if (!vmc) {
			fprintf(stderr, "Could not allocate vmcoreinfo\n");
			goto out_err;
		}

		rv = absio_read(io, di->subhdr.offset_vmcoreinfo,
				di->subhdr.size_vmcoreinfo, vmc);
		if (rv) {
			free(vmc);
			fprintf(stderr, "Error reading vmcoreinfo 1\n");
			goto out_err;
		}
		rv = elfc_add_note(di->elf, 0, "VMCOREINFO",
				   strlen("VMCOREINFO"),
				   vmc, di->subhdr.size_vmcoreinfo);
		free(vmc);
		if (rv) {
			fprintf(stderr, "Error adding vmcoreinfo 1\n");
			goto out_err;
		}
	}
	
	if (di->subhdr.size_note) {
		char *note = malloc(di->subhdr.size_note);
		struct note_header nhdr;
		unsigned int datapos;

		if (!note) {
			fprintf(stderr, "Could not allocate note data\n");
			goto out_err;
		}

		rv = absio_read(io, di->subhdr.offset_note,
				di->subhdr.size_note, note);
		if (rv) {
			free(note);
			fprintf(stderr, "Error reading vmcoreinfo 1\n");
			goto out_err;
		}
		pos = 0;
		while (pos < di->subhdr.size_note) {
			nhdr = *((struct note_header *) (note + pos));
			nhdr.name_size = di->conv32(nhdr.name_size);
			nhdr.data_size = di->conv32(nhdr.data_size);
			nhdr.type = di->conv32(nhdr.type);
			pos += sizeof(nhdr);
			datapos = align(pos + nhdr.name_size, 4);
			if (datapos + nhdr.data_size > di->subhdr.size_note) {
				free(note);
				fprintf(stderr, "Invalid note info\n");
				goto out_err;
			}
			rv = elfc_add_note(di->elf, nhdr.type,
					   note + pos, nhdr.name_size,
					   note + datapos, nhdr.data_size);
			if (rv) {
				free(note);
				fprintf(stderr, "Error adding note\n");
				goto out_err;
			}
			pos = align(datapos + nhdr.data_size, 4);
		}
		free(note);
	}
		
	handle_vminfo_notes(di->elf, vmci, extra_vminfo);
	if (!vmci[3].found) {
		fprintf(stderr,
			"Error: SIZE(list_head) not in vmcore\n");
		goto out_err;
	}

	if (vmci[9].found) {
		dummy_d.pgd = vmci[9].val - start_kernel + di->subhdr.phys_base;
	} else if (vmci[10].found) {
		dummy_d.pgd = vmci[10].val - start_kernel +di->subhdr.phys_base;
	} else if (vmci[11].found) {
		dummy_d.pgd = vmci[11].val - start_kernel +di->subhdr.phys_base;
	} else {
		fprintf(stderr, "No swapper_pg_dir or init_level4_pgd or "
			"init_top_pgt in vminfo, can't get pgd.\n");
		goto out_err;
	}

	pos = (1 + di->hdr.sub_hdr_size) * di->blocksize;

	di->bitmap1 = malloc(di->hdr.bitmap_blocks * di->blocksize);
	if (!di->bitmap1) {
		fprintf(stderr, "Could not allocate bitmap memory\n");
		goto out_err;
	}
	rv = absio_read(io, pos, di->hdr.bitmap_blocks * di->blocksize,
			di->bitmap1);
	if (rv) {
		fprintf(stderr, "Could not read bitmap memory\n");
		goto out_err;
	}
	di->bitmap2 = di->bitmap1 + (di->hdr.bitmap_blocks * di->blocksize / 2);
	di->page_desc_start = pos + di->hdr.bitmap_blocks * di->blocksize;
	di->max_mapnr = di->subhdr.max_mapnr_64;

	/* Calculate the page section start locations. */
	num_pghdrstart = (di->max_mapnr + PAGES_PER_SECT - 1) / PAGES_PER_SECT;
	di->page_sect_pfn_start = malloc(num_pghdrstart * sizeof(int64_t));
	if (!di->page_sect_pfn_start) {
		fprintf(stderr,
			"Could not allocate page header start memory\n");
		goto out_err;
	}
	di->page_sect_pfn_start[0] = 0;
	for (psect = 1, pfn = 0; psect < num_pghdrstart; psect++) {
		unsigned int j;

		di->page_sect_pfn_start[psect] =
			di->page_sect_pfn_start[psect - 1];
		for (j = 0; j < PAGES_PER_SECT; j++, pfn++) {
			if (page_dumpable(di, pfn))
				di->page_sect_pfn_start[psect]++;
		}
	}

	rv = elfc_add_phdr(di->elf, PT_LOAD, 0, 0,
			   di->max_mapnr * di->blocksize,
			   di->max_mapnr * di->blocksize,
			   PF_R | PF_W | PF_X, di->blocksize);
	if (rv == -1) {
		fprintf(stderr, "Could not add makedumpfile elf phdr: %s\n",
			strerror(elfc_get_errno(di->elf)));
		goto out_err;
	}
	rv = elfc_set_phdr_data(di->elf, rv, NULL, mdfmem_free,
				NULL, mdfmem_do_write, NULL,
				mdfmem_get_data, mdfmem_set_data,
				di);
	if (rv == -1) {
		fprintf(stderr, "Error setting qmem phdr data: %s\n",
			strerror(elfc_get_errno(di->elf)));
		goto out_err;
	}
	elfc_phdr_set = true;

	dummy_d.extra_vminfo = extra_vminfo;

	endc = sprintf(buf, "ADDRESS(phys_pgd_ptr)=%llx\n",
		       (unsigned long long) dummy_d.pgd);

	dummy_d.elf = di->elf;

	rv = dummy_d.arch->setup_arch_pelf(di->elf, &dummy_d,
					   &dummy_d.arch_data);
	if (rv)
		goto out_err;

	if (vmci[4].found) { /* Try to get vmcoreinfo_data from dump. */
		char read_page[4097];

		rv = fetch_vaddr_data_err(&dummy_d,
					  vmci[4].val + di->subhdr.phys_base,
				          sizeof(read_page) - 1, read_page,
					  "vmcoreinfo_data");
		if (rv)
			goto out_err;
		read_page[4096] = '\0';
		rv = elfc_add_note(di->elf, 0, "VMCOREINFO",
				   strlen("VMCOREINFO"),
				   read_page, strlen(read_page));
		if (rv == -1) {
			fprintf(stderr,
				"Error adding elf VMCOREINFO note: %s\n",
				strerror(elfc_get_errno(di->elf)));
			goto out_err;
		}
	} else if (di->subhdr.phys_base && vmci[6].found) {
		/*
		 * Set our own value for _stext and disable the other.
		 * This will let the other code calculate the base offsets
		 * properly.
		 */
		char *pos = strstr(extra_vminfo, "SYMBOL(_stext)");

		*pos = 'W'; /* Change "SYMBOL" to "WYMBOL" */
		endc = sprintf(buf + endc, "SYMBOL(_stext)=%llx\n",
			       (unsigned long long) (vmci[6].val +
						     di->subhdr.phys_base));
	}

	rv = elfc_add_note(di->elf, 0, "VMCOREINFO", 12,
			   buf, strlen(buf) + 1);
	if (rv == -1) {
		fprintf(stderr, "Error adding phys_pgd_ptr note: %s\n",
			strerror(elfc_get_errno(di->elf)));
		goto out_err;
	}

	dummy_d.arch->cleanup_arch_data(dummy_d.arch_data);

	return di->elf;

out_err:
	if (dummy_d.arch_data)
		dummy_d.arch->cleanup_arch_data(dummy_d.arch_data);
	di->io = NULL; /* Don't free io on a failure. */
	if (di->elf)
		elfc_free(di->elf);
	if (!elfc_phdr_set) {
		/* Once we set the phdr data, elfc_free() will free di. */
		if (di->page_sect_pfn_start)
			free(di->page_sect_pfn_start);
		if (di->bitmap1)
			free(di->bitmap1);
		if (di->pgbuf)
			free(di->pgbuf);
		if (di->cmpr_pgbuf)
			free(di->cmpr_pgbuf);
		free(di);
	}
	return NULL;
}
