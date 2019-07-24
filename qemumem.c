/*
 * qemumem.c
 *
 * Handling for reading qemu vmdump files
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
#include <sys/mman.h>
#include <signal.h>
#include <assert.h>

#include "list.h"
#include "elfc.h"
#include "kdump-x86.h"

#define QEMU_VM_FILE_MAGIC	0x5145564D

enum qemu_save_section {
	QEMU_VM_EOF,
	QEMU_VM_SECTION_START,
	QEMU_VM_SECTION_PART,
	QEMU_VM_SECTION_END,
	QEMU_VM_SECTION_FULL,
	QEMU_VM_SECTION_SUBSECTION,
};

/*
 * Memory in qemu vmdumps is in 4096 byte chunks, each one of these
 * represents one chunk.
 */
struct qmem_info {
	uint64_t addr;
	off_t foffset;
};

#define QEMU_ADDR_GET_ADDR(addr) ((addr) & (~4095ULL))
#define QEMU_ADDR_FLAG_COMPRESSED 0x1
#define QEMU_ADDR_IS_COMPRESSED(addr) ((addr) & QEMU_ADDR_FLAG_COMPRESSED)

#define BTREE_NODE_SIZE 10
#define btree_val_t struct qmem_info
#define btree_t qmem_btree_t
#define BTREE_EXPORT_NAME(s) qmem_btree_ ## s
#define BTREE_NAMES_LOCAL static
#define btree_cmp_key qmem_cmp_key

int
qmem_cmp_key(struct qmem_info val1, struct qmem_info val2)
{
	uint64_t v1 = QEMU_ADDR_GET_ADDR(val1.addr);
	uint64_t v2 = QEMU_ADDR_GET_ADDR(val2.addr);

	if (v1 < v2)
		return -1;
	else if (v1 > v2)
		return 1;
	else
		return 0;
}

/* We only need add and search. */
#define BTREE_NEEDS 0

#include "btree.h"

#undef BTREE_NODE_SIZE
#undef btree_val_t
#undef btree_t
#undef BTREE_EXPORT_NAME
#undef BTREE_NAMES_LOCAL
#undef btree_cmp_key


struct qemu_info;
struct qemu_device_info;

struct qemu_device_type {
	const char *name;
	int (*load)(struct qemu_info *qi, uint8_t section,
		    struct qemu_device_info *device);
	unsigned int devinfo_size;
};

struct qemu_device_info {
	struct link link;

	const struct qemu_device_type *type;

	unsigned int section_id;
	unsigned int instance_id;
	unsigned int version_id;

	void *devinfo;
};

struct qemu_info {
	bool is_64bit;
	bool is_machine_64bit;
	FILE *f;
	qmem_btree_t qmem;
	struct elfc *elf;
	unsigned int page_size;

	/* Count how many headers point to me. */
	unsigned int refcount;

	bool ram_present;
	bool cpu_present;
	bool is_kvm;
	struct list devices;
};

static int
qemu_read_64(struct qemu_info *qi, uint64_t *v, const char *name, int inst)
{
	unsigned char buf[8];
	int rv;

	rv = fread(buf, 1, 8, qi->f);
	if (rv != 8) {
		if (name) {
			if (inst >= 0)
				fprintf(stderr,
					"qemu: Unable to read64 %s[%d]: %d\n",
					name, inst, rv);
			else
				fprintf(stderr,
					"qemu: Unable to read64 %s: %d\n",
					name, rv);
		}
		return -1;
	}
	*v = (((uint64_t) buf[0]) << 56) | (((uint64_t) buf[1]) << 48) |
		(((uint64_t) buf[2]) << 40) | (((uint64_t) buf[3]) << 32) |
		(((uint64_t) buf[4]) << 24) | (((uint64_t) buf[5]) << 16) |
		(((uint64_t) buf[6]) << 8) | buf[7];
	return 0;
}

static int
qemu_read_32(struct qemu_info *qi, uint32_t *v, const char *name, int inst)
{
	unsigned char buf[4];
	int rv;

	rv = fread(buf, 1, 4, qi->f);
	if (rv != 4) {
		if (name) {
			if (inst >= 0)
				fprintf(stderr,
					"qemu: Unable to read32 %s[%d]: %d\n",
					name, inst, rv);
			else
				fprintf(stderr,
					"qemu: Unable to read32 %s: %d\n",
					name, rv);
		}
		return -1;
	}
	*v = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	return 0;
}

static int
qemu_read_16(struct qemu_info *qi, uint16_t *v, const char *name, int inst)
{
	unsigned char buf[2];
	int rv;

	rv = fread(buf, 1, 2, qi->f);
	if (rv != 2) {
		if (name) {
			if (inst >= 0)
				fprintf(stderr,
					"qemu: Unable to read16 %s[%d]: %d\n",
					name, inst, rv);
			else
				fprintf(stderr,
					"qemu: Unable to read16 %s: %d\n",
					name, rv);
		}
		return -1;
	}
	*v = (buf[0] << 8) | buf[1];
	return 0;
}

static int
qemu_read_8(struct qemu_info *qi, uint8_t *v, const char *name, int inst)
{
	int rv = fread(v, 1, 1, qi->f);

	if (rv != 1) {
		if (name) {
			if (inst >= 0)
				fprintf(stderr,
					"qemu: Unable to read8 %s[%d]: %d\n",
					name, inst, rv);
			else
				fprintf(stderr,
					"qemu: Unable to read8 %s: %d\n",
					name, rv);
		}
		return -1;
	}
	return 0;
}

static int
qemu_read_string(struct qemu_info *qi, char *str, const char *name)
{
	int rv;
	uint8_t len;

	rv = qemu_read_8(qi, &len, name, -1);
	if (rv)
		return rv;
	rv = fread(str, 1, len, qi->f);
	if (rv != len) {
		fprintf(stderr, "qemu: Short string read on %s: %d %u\n",
			name, rv, len);
		return -1;
	}
	str[rv] = '\0';
	return 0;
}

static int
qemu_skip(FILE *f, unsigned int size, const char *name)
{
	int rv;

	rv = fseek(f, size, SEEK_CUR);
	if (rv == -1) {
		fprintf(stderr, "Unable to skip %s (%u bytes): %s\n",
			name, size, strerror(errno));
		return rv;
	}
	return 0;
}

static int
qmem_read_addr(struct qemu_info *qi, off_t addr, unsigned char *buf)
{
	struct qmem_info qm_s = { .addr = addr }, qm;
	int rv, lerrno;
	size_t read_rv;

	rv = qmem_btree_search(&qi->qmem, qm_s, &qm, BTREE_NO_CLOSEST);
	if (rv) {
		fprintf(stderr,
			"qmem_do_write: Could not find item at"
			" address %llx\n", (unsigned long long) addr);
		errno = ENOENT;
		return -1;
	}

	if (qm.addr & QEMU_ADDR_FLAG_COMPRESSED) {
		memset(buf, qm.foffset, 4096);
		return 0;
	}

	rv = fseeko(qi->f, qm.foffset, SEEK_SET);
	if (rv == -1) {
		lerrno = errno;
		fprintf(stderr,
			"qmem_do_write: Error seeking fd: %s\n",
			strerror(lerrno));
		errno = lerrno;
		return -1;
	}

	read_rv = fread(buf, 1, 4096, qi->f);
	lerrno = errno;
	if (read_rv < 4096) {
		fprintf(stderr,
			"qmem_do_write: Short read on fd: %d\n",
			(int) read_rv);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static int
qmem_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
	      void *data, void *userdata)
{
	struct qemu_info *qi = userdata;
	unsigned char buf[4096];
	int rv, lerrno;
	off_t loff = 0;
	off_t pos;
	off_t left;

	/*
	 * Align on a chunk size and get the offset from there.
	 */
	pos = phdr->p_paddr;
	loff = pos - (pos & ~((off_t) 4095));
	pos -= loff;
	left = phdr->p_filesz;

	/*
	 * Copy in sections.
	 */
	while (left > 0) {
		off_t sz = left;

		if (sz + loff > 4096)
			sz = 4096 - loff;

		rv = qmem_read_addr(qi, pos, buf);
		if (rv == -1)
			return rv;

		rv = write(fd, buf + loff, sz);
		lerrno = errno;
		if (rv == -1) {
			fprintf(stderr,
				"qmem_do_write: Error on write: %s\n",
				strerror(lerrno));
			errno = lerrno;
			return -1;
		}
		left -= sz;
		pos += 4096;
		loff = 0;
	}
	return 0;
}

static int
qmem_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, void *odata, size_t len,
	      void *userdata)
{
	struct qemu_info *qi = userdata;
	unsigned char buf[4096];
	int rv;
	off_t loff = 0;
	off_t pos;
	off_t left;
	char *wdata = odata;

	/*
	 * Align on a chunk size and get the offset from there.
	 */
	pos = phdr->p_paddr + off;
	loff = pos - (pos & ~((off_t) 4095));
	pos -= loff;
	left = len;
	assert(len <= phdr->p_filesz);

	/*
	 * Copy in sections.
	 */
	while (left > 0) {
		off_t sz = left;

		if (sz + loff > 4096)
			sz = 4096 - loff;

		rv = qmem_read_addr(qi, pos, buf);
		if (rv)
			return -1;
		memcpy(wdata, buf + loff, sz);
		wdata += sz;
		left -= sz;
		pos += 4096;
		loff = 0;
	}
	return 0;
}

static int
qmem_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, const void *idata, size_t len,
	      void *userdata)
{
	return -1;
}

static void
qmem_free(struct elfc *e, void *data, void *userdata)
{
	struct qemu_info *qi = userdata;
	struct qemu_device_info *device;
	struct link *tmp;

	if (qi->refcount == 1) {
		qmem_btree_free(&qi->qmem);
		list_for_each_item_safe(&qi->devices, device, tmp,
					struct qemu_device_info, link) {
		    list_unlink(&device->link);
		    free(device);
		}
		free(qi);
	} else {
		qi->refcount--;
	}
}

static struct qemu_device_info *
qemu_find_device(struct qemu_info *qi, uint32_t section_id)
{
	struct qemu_device_info *device;

	list_for_each_item(&qi->devices, device, struct qemu_device_info,
			   link) {
		if (device->section_id == section_id)
			return device;
	}
	return NULL;
}

static struct qemu_device_info *
qemu_find_device_name(struct qemu_info *qi, const char *name,
		      struct qemu_device_info *prev)
{
	struct qemu_device_info *device;

	
	list_for_each_item(&qi->devices, device, struct qemu_device_info,
			   link) {
		if (prev && prev != device)
			continue;
		if (prev) {
			prev = NULL;
			continue;
		}
		if (strcmp(device->type->name, name) == 0)
			return device;
	}
	return NULL;
}

#define RAM_SAVE_FLAG_FULL	0x01
#define RAM_SAVE_FLAG_COMPRESS	0x02
#define RAM_SAVE_FLAG_MEM_SIZE	0x04
#define RAM_SAVE_FLAG_PAGE	0x08
#define RAM_SAVE_FLAG_EOS	0x10
#define RAM_SAVE_FLAG_CONTINUE	0x20
#define RAM_SAVE_ADDR_MASK	(~4095ULL)

static int
qemu_ram_read_blocks(struct qemu_info *qi, uint64_t size)
{
	char name[257];
	int rv;
	uint64_t block_size;

	while (size) {
		rv = qemu_read_string(qi, name, "ram block name");
		if (rv)
			return rv;
		rv = qemu_read_64(qi, &block_size, "ram block size", -1);
		if (rv)
			return rv;
		if (block_size > size) {
			fprintf(stderr, "ram blocks overflow: %llu %llu\n",
				(unsigned long long) block_size,
				(unsigned long long) size);
			return -1;
		}
		size -= block_size;
	}
	return 0;
}

static const char *
qmem_err_to_str(int err)
{
	if (err == BTREE_ITEM_ALREADY_EXISTS) {
		return "duplicate entry";
	} else if (err == BTREE_OUT_OF_MEMORY) {
		return "out of memory";
	} else if (err == BTREE_ITEM_NOT_FOUND) {
		return "not found";
	} else if (err ==  BTREE_AT_END_OF_TREE) {
		return "end of tree";
	} else {
		return "unknown";
	}
}

static int
qmem_add_section(struct qemu_info *qi, uint64_t addr, uint64_t size)
{
	int rv;

	rv = elfc_add_phdr(qi->elf, PT_LOAD, 0, addr, size, size,
			   PF_R | PF_W | PF_X, qi->page_size);
	if (rv == -1) {
		fprintf(stderr, "Error adding qmem elfc phdr: %s\n",
			strerror(elfc_get_errno(qi->elf)));
		return rv;
	}

	rv = elfc_set_phdr_data(qi->elf, rv, NULL, qmem_free,
				NULL, qmem_do_write, NULL,
				qmem_get_data, qmem_set_data,
				qi);
	if (rv == -1) {
		fprintf(stderr, "Error setting qmem phdr data: %s\n",
			strerror(elfc_get_errno(qi->elf)));
		return rv;
	}

	qi->refcount++;

	qi->ram_present = true;
	return 0;
}

struct qemu_ram_devinfo {
	struct qemu_device_info info;
	bool is_ram;
};

static int
qemu_ram_load(struct qemu_info *qi, uint8_t section,
	      struct qemu_device_info *device)
{
	struct qemu_ram_devinfo *d = (void *) device;
	char name[257];
	int rv;
	struct qmem_info qm;
	bool first = true;
	uint64_t last_addr = 0, start_addr = 0;

	while (1) {
		uint64_t header, addr;

		rv = qemu_read_64(qi, &header, "ram header", -1);
		if (rv)
			return rv;
		if (header & RAM_SAVE_FLAG_EOS)
			break;

		assert(!(header & RAM_SAVE_FLAG_FULL));

		addr = header & RAM_SAVE_ADDR_MASK;

		if (header & RAM_SAVE_FLAG_MEM_SIZE) {
			/* Could save the end of memory here. */
			if (device->version_id >= 4) {
				rv = qemu_ram_read_blocks(qi, addr);
				if (rv)
					return rv;
			}
			continue;
		}

		if (device->version_id >= 4 &&
		    !(header & RAM_SAVE_FLAG_CONTINUE)) {
			rv = qemu_read_string(qi, name, "ram type name");
			if (strcmp(name, "pc.ram") == 0)
				d->is_ram = true;
			else
				d->is_ram = false;
		}

		if (header & RAM_SAVE_FLAG_COMPRESS) {
			uint8_t val;

			rv = qemu_read_8(qi, &val, "compress value", -1);
			if (rv)
				return rv;
			if (d->is_ram) {
				qm.addr = addr | QEMU_ADDR_FLAG_COMPRESSED;
				qm.foffset = val;
			}
		} else if (header & RAM_SAVE_FLAG_PAGE) {
			if (d->is_ram) {
				qm.addr = addr;
				qm.foffset = ftello(qi->f);
			}
			rv = fseek(qi->f, 4096, SEEK_CUR);
			if (rv == -1) {
				fprintf(stderr, "qmem ram seek error: %s\n",
					strerror(errno));
				return -1;
			}
		} else {
			continue;
		}

		if (!d->is_ram)
			continue;

		if (first) {
			start_addr = addr;
			last_addr = addr;
			first = false;
		} else if (!first && last_addr != addr) {
			/* Create a new section */
			rv = qmem_add_section(qi, start_addr,
					      last_addr - start_addr);
			if (rv)
				return rv;
			start_addr = addr;
			last_addr = addr;
		}
		last_addr += 4096;
		rv = qmem_btree_add(&qi->qmem, qm);
		if (rv) {
			fprintf(stderr, "qmem add error: %s (%llx)\n",
				qmem_err_to_str(rv),
				((unsigned long long) addr));
			return -1;
		}
	}

	if (!first)
		return qmem_add_section(qi, start_addr,
					last_addr - start_addr);
	return 0;
}

struct qemu_cpu_common_devinfo {
	struct qemu_device_info info;
	uint32_t halted;
	uint32_t irq;
};

static int qemu_cpu_common_load(struct qemu_info *qi, uint8_t section,
				struct qemu_device_info *device)
{
	struct qemu_cpu_common_devinfo *ccdevice = (void *) device;
	int rv;

	rv = qemu_read_32(qi, &ccdevice->halted, "cpu common halted", -1);
	if (rv)
		return rv;
	rv = qemu_read_32(qi, &ccdevice->irq, "cpu common irq", 01);
	if (rv)
		return rv;
	return 0;
}

static int
qemu_read_msize(struct qemu_info *qi, uint64_t *v, const char *name, int inst)
{
	int rv;

	if (qi->is_machine_64bit) {
		rv = qemu_read_64(qi, v, name, inst);
	} else {
		uint32_t v32;
		rv = qemu_read_32(qi, &v32, name, inst);
		if (!rv)
			*v = v32;
	}
	return rv;
}

struct qemu_xmm {
	uint32_t i[4];
};

static int
qemu_read_xmm(struct qemu_info *qi, struct qemu_xmm *v,
	      const char *name, int inst)
{
	int rv;

	rv = qemu_read_32(qi, &v->i[1], name, inst * 16 + 1);
	if (rv)
		return rv;
	rv = qemu_read_32(qi, &v->i[0], name, inst * 16);
	if (rv)
		return rv;
	rv = qemu_read_32(qi, &v->i[2], name, inst * 16 + 2);
	if (rv)
		return rv;
	rv = qemu_read_32(qi, &v->i[3], name, inst * 16 + 3);
	if (rv)
		return rv;
	return 0;
}

union qemu_fpu_reg {
	unsigned char bytes[10];
	uint64_t mmx;
};

struct qemu_x86_seg {
	uint64_t	base;
	uint32_t	selector;
	uint32_t	limit;
	uint32_t	flags;
};

struct qemu_x86_sysenter {
	uint32_t	cs;
	uint64_t	esp;
	uint64_t	eip;
};

struct qemu_x86_svm {
	uint64_t		hsave;
	uint64_t		vmcb;
	uint64_t		tsc_offset;
	uint8_t			in_vmm : 1;
	uint8_t			guest_if_mask : 1;
	uint8_t			guest_intr_masking : 1;
	uint16_t		cr_read_mask;
	uint16_t		cr_write_mask;
	uint16_t		dr_read_mask;
	uint16_t		dr_write_mask;
	uint32_t		exception_intercept_mask;
	uint64_t		intercept_mask;
};

struct qemu_x86_vmtrr {
	uint64_t		base;
	uint64_t		mask;
};

struct qemu_x86_kvm {
	uint64_t		int_bitmap[4];
	uint64_t		tsc;
	uint32_t		mp_state;
	uint32_t		exception_injected;
	uint8_t			soft_interrupt;
	uint8_t			nmi_injected;
	uint8_t			nmi_pending;
	uint8_t			has_error_code;
	uint32_t		sipi_vector;
	uint64_t		system_time_msr;
	uint64_t		wall_clock_msr;
	uint64_t		xcr0;
	uint64_t		xstate_bv;
	struct qemu_xmm	        ymmh[16];
};

struct qemu_x86_mce {
	uint64_t		mcg_cap;
	uint64_t		mcg_status;
	uint64_t		mcg_ctl;
	uint64_t		mce_banks[10 * 4];
};

struct qemu_cpu_devinfo {
	struct qemu_device_info info;
	uint64_t regs[16];
	uint64_t eip;
	uint64_t eflags;
	uint16_t fpucw;
	uint16_t fpusw;
	uint16_t fpu_free;
	union qemu_fpu_reg fpureg[8];
	struct qemu_x86_seg es;
	struct qemu_x86_seg cs;
	struct qemu_x86_seg ss;
	struct qemu_x86_seg ds;
	struct qemu_x86_seg fs;
	struct qemu_x86_seg gs;
	struct qemu_x86_seg ldt;
	struct qemu_x86_seg tr;
	struct qemu_x86_seg gdt;
	struct qemu_x86_seg idt;
	struct qemu_x86_sysenter sysenter;

	uint64_t cr0;
	uint64_t cr2;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t dr[8];

	bool softmmu;
	bool smm;
	bool a20_masked;
	uint32_t mxcsr;

	struct qemu_xmm xmm[16];

	uint64_t efer;
	uint64_t star;
	uint64_t lstar;
	uint64_t cstar;
	uint64_t fmask;
	uint64_t kernel_gs_base;

	uint32_t smbase;
	uint64_t pat;
	bool global_if;
	bool in_nmi;
	bool in_vmm;

	uint32_t halted;

	struct qemu_x86_svm svm;

	uint8_t cr8;

	uint64_t fixed_mtrr[11];
	struct qemu_x86_vmtrr variable_mtrr[8];

	struct qemu_x86_kvm kvm;
	struct qemu_x86_mce mce;

	uint64_t tsc_aux;

	uint32_t dummy32;
};

#define xstr(s) #s

#define REGGET(name, size) \
	do { \
		rv = qemu_read_ ## size(qi, &d->name, xstr(name), -1); \
		if (rv) \
			return rv; \
	} while(0)

#define SEGGET(name) \
	do { \
		rv = qemu_read_32(qi, &d->name.selector, \
				  xstr(name)".selector", -1);	\
		if (rv) \
			return rv; \
		rv = qemu_read_64(qi, &d->name.base, xstr(name)".base", -1); \
		if (rv) \
			return rv; \
		rv = qemu_read_32(qi, &d->name.limit, \
				  xstr(name)".limit", -1);	\
		if (rv) \
			return rv; \
		rv = qemu_read_32(qi, &d->name.flags, \
				  xstr(name)".flags", -1);	\
		if (rv) \
			return rv; \
	} while(0)

static int qemu_cpu_load(struct qemu_info *qi, uint8_t section,
			 struct qemu_device_info *device)
{
	uint32_t version_id = device->version_id, rhel5_version_id = 0;
	struct qemu_cpu_devinfo *d = (void *) device;
	unsigned int nregs = qi->is_machine_64bit ? 16 : 8;
	unsigned int i;
	uint32_t qemu_hflags;
	int rv;
	uint16_t no_fpu80;

	if (qemu_find_device_name(qi, "__rhel5", NULL) ||
	    (version_id >= 7 && version_id <= 9)) {
		rhel5_version_id = version_id;
		version_id = 7;
	}

	for (i = 0; i < nregs; i++) {
		rv = qemu_read_msize(qi, &d->regs[i], "reg", i);
		if (rv)
			return rv;
	}
	REGGET(eip, msize);
	REGGET(eflags, msize);
	rv = qemu_read_32(qi, &qemu_hflags, "hflags", -1);
	if (rv)
		return rv;
	d->softmmu = !!(qemu_hflags & (1 << 2));
	d->smm = !!(qemu_hflags & (1 << 19));
	d->svm.in_vmm = !!(qemu_hflags & (1 << 21));
	REGGET(fpucw, 16);
	REGGET(fpusw, 16);
	REGGET(fpu_free, 16);
	rv = qemu_read_16(qi, &no_fpu80, "fpu80", -1);
	if (rv)
		return rv;
	for (i = 0; i < 8; i++) {
		rv = qemu_read_64(qi, &d->fpureg[i].mmx, "fpu", i);
		if (rv)
			return rv;
		if (!no_fpu80) {
			rv = qemu_read_8(qi, &d->fpureg[i].bytes[8], "fpu8", i);
			if (rv)
				return rv;
			rv = qemu_read_8(qi, &d->fpureg[i].bytes[9], "fpu9", i);
			if (rv)
				return rv;
		}
	}

	SEGGET(es);
	SEGGET(cs);
	SEGGET(ss);
	SEGGET(ds);
	SEGGET(fs);
	SEGGET(gs);
	SEGGET(ldt);
	SEGGET(tr);
	SEGGET(gdt);
	SEGGET(idt);

	REGGET(sysenter.cs, 32);
	if (version_id <= 6) {
		REGGET(dummy32, 32);
		d->sysenter.esp = d->dummy32;
		REGGET(dummy32, 32);
		d->sysenter.eip = d->dummy32;
	} else {
		REGGET(sysenter.esp, msize);
		REGGET(sysenter.eip, msize);
	}

	REGGET(cr0, msize);
	REGGET(cr2, msize);
	REGGET(cr3, msize);
	REGGET(cr4, msize);
	for (i = 0; i < 8; i++) {
		rv = qemu_read_msize(qi, &d->dr[i], "dr", i);
		if (rv)
			return rv;
	}

	REGGET(dummy32, 32);
	d->a20_masked = d->dummy32 != 0xffffffff;
	REGGET(mxcsr, 32);
	
	for (i = 0; i < nregs; i++) {
		rv = qemu_read_xmm(qi, &d->xmm[i], "xmm", i);
		if (rv)
			return rv;
	}

	if (qi->is_machine_64bit) {
		REGGET(efer, 64);
		REGGET(star, 64);
		REGGET(lstar, 64);
		REGGET(cstar, 64);
		REGGET(fmask, 64);
		REGGET(kernel_gs_base, 64);
	}

	if (version_id == 4)
		goto out;

	REGGET(smbase, 32);
	REGGET(pat, 64);
	rv = qemu_read_32(qi, &qemu_hflags, "hflags2", -1);
	if (rv)
		return rv;
	d->global_if = !!(qemu_hflags & (1 << 0));
	d->in_nmi = !!(qemu_hflags & (1 << 2));
	d->svm.guest_if_mask = !!(qemu_hflags & (1 << 1));
	d->svm.guest_intr_masking = !!(qemu_hflags & (1 << 3));
	
	if (version_id < 6)
		REGGET(halted, 32);

	REGGET(svm.hsave, 64);
	REGGET(svm.vmcb, 64);
	REGGET(svm.tsc_offset, 64);
	REGGET(svm.hsave, 64);
	REGGET(svm.intercept_mask, 64);
	REGGET(svm.cr_read_mask, 16);
	REGGET(svm.cr_write_mask, 16);
	REGGET(svm.dr_read_mask, 16);
	REGGET(svm.dr_write_mask, 16);
	REGGET(svm.exception_intercept_mask, 32);
	REGGET(cr8, 8);

	if (version_id >= 8) {
		for (i = 0; rv == 0 && i < 11; i++)
			rv = qemu_read_64(qi, &d->fixed_mtrr[i],
					  "fixed_mtrr", i);
		for (i = 0; rv == 0 && i < 8; i++) {
			rv = qemu_read_64(qi, &d->variable_mtrr[i].base,
					  "variable_mtrr.base", i);
			rv = qemu_read_64(qi, &d->variable_mtrr[i].mask,
					  "variable_mtrr.mask", i);
		}
		if (rv)
			return rv;
	}

	if (version_id >= 9) {
		uint32_t pending_irq;

		rv = qemu_read_32(qi, &pending_irq, "pending_irq", -1);
		if (rv)
			return rv;
		if (((int) pending_irq) >= 0 && pending_irq <= 255)
			d->kvm.int_bitmap[pending_irq / 64] |=
				((uint32_t) 1) << (pending_irq & 63);
		REGGET(kvm.mp_state, 32);
		REGGET(kvm.tsc, 64);
	} else if (qi->is_kvm) {
		for (i = 0; rv == 0 && i < 4; i++)
			rv = qemu_read_64(qi, &d->kvm.int_bitmap[i],
					  "kvm.in_bitmap", i);
		if (rv)
			return rv;
		REGGET(kvm.tsc, 64);
		if (version_id >= 5)
			REGGET(kvm.mp_state, 32);
	}

	if (version_id >= 11)
		REGGET(kvm.exception_injected, 32);

	if (rhel5_version_id >= 8) {
		REGGET(kvm.system_time_msr, 64);
		REGGET(kvm.wall_clock_msr, 64);
	}
	if (version_id >= 11 || rhel5_version_id >= 9) {
		REGGET(kvm.soft_interrupt, 8);
		REGGET(kvm.nmi_injected, 8);
		REGGET(kvm.nmi_pending, 8);
		REGGET(kvm.has_error_code, 8);
		REGGET(kvm.sipi_vector, 32);
	}

	if (version_id >= 10) {
		REGGET(mce.mcg_cap, 64);
		REGGET(mce.mcg_status, 64);
		REGGET(mce.mcg_ctl, 64);
		for (i = 0; rv == 0 && i < 40; i++)
			rv = qemu_read_64(qi, &d->mce.mce_banks[i],
					  "mce.mce_banks", i);
		if (rv)
			return rv;
	}

	if (version_id >= 11) {
		REGGET(tsc_aux, 64);
		REGGET(kvm.system_time_msr, 64);
		REGGET(kvm.wall_clock_msr, 64);
	}

	if (version_id >= 12) {
		REGGET(kvm.xcr0, 64);
		REGGET(kvm.xstate_bv, 64);
		for (i = 0; i < nregs; i++) {
			rv = qemu_read_xmm(qi, &d->kvm.ymmh[i], "ymm", i);
			if (rv)
				return rv;
		}
	}
out:
	qi->cpu_present = true;
	return 0;
}

static int qemu_rhel5_marker_load(struct qemu_info *qi, uint8_t section,
				  struct qemu_device_info *device)
{
	return 0;
}

static int qemu_kvm_tpr_opt_load(struct qemu_info *qi, uint8_t section,
				 struct qemu_device_info *device)
{
	int rv;

	rv = qemu_skip(qi->f, 144, "kvm-tpr-opt");
	if (rv == -1)
		return rv;
	qi->is_kvm = true;
	return 0;
}

static int qemu_kvmclock_load(struct qemu_info *qi, uint8_t section,
			      struct qemu_device_info *device)
{
	int rv;

	rv = qemu_skip(qi->f, 8, "kvmclock");
	if (rv == -1)
		return rv;
	qi->is_kvm = true;
	return 0;
}

static int qemu_apic_load(struct qemu_info *qi, uint8_t section,
			  struct qemu_device_info *device)
{
	int rv;

	switch (device->version_id) {
	case 1:
		rv = qemu_skip(qi->f, 173, "apic");
		break;
	case 2:
	case 3:
		rv = qemu_skip(qi->f, 181, "apic");
		break;
	default:
		fprintf(stderr, "Unknown qemu timer version: %d\n",
			device->version_id);
		return -1;
	}

	return rv;
}

#define BLK_MIG_FLAG_EOS 2

static int qemu_block_load(struct qemu_info *qi, uint8_t section,
			   struct qemu_device_info *device)
{
	int rv;
	uint64_t header;

	rv = qemu_read_64(qi, &header, "block header", -1);
	if (rv)
		return rv;
	if (header != BLK_MIG_FLAG_EOS) {
		/* What is this? */
		fprintf(stderr, "qemu block header error: %lld\n",
			(long long) header);
		return -1;
	}
	return 0;
}

static int qemu_timer_load(struct qemu_info *qi, uint8_t section,
			   struct qemu_device_info *device)
{
	return qemu_skip(qi->f, 24, "timer");
}

const struct qemu_device_type qemu_device_types[] = {
	{ "cpu_common", qemu_cpu_common_load,
				sizeof(struct qemu_cpu_common_devinfo) },
	{ "cpu", qemu_cpu_load, sizeof(struct qemu_cpu_devinfo) },
	{ "ram", qemu_ram_load, sizeof(struct qemu_ram_devinfo) },
	{ "__rhel5", qemu_rhel5_marker_load, sizeof(struct qemu_device_info) },
	{ "kvm-tpr-opt", qemu_kvm_tpr_opt_load,
				sizeof(struct qemu_device_info) },
	{ "kvmclock", qemu_kvmclock_load, sizeof(struct qemu_device_info) },
	{ "apic", qemu_apic_load, sizeof(struct qemu_device_info) },
	{ "block", qemu_block_load, sizeof(struct qemu_device_info) },
	{ "timer", qemu_timer_load , sizeof(struct qemu_device_info)},
	{}
};

static int
qemu_read_device(struct qemu_info *qi, uint8_t sec)
{
	int rv;
	uint32_t section_id;
	char name[257];
	unsigned int i;
	struct qemu_device_info *device;

	if (sec >= QEMU_VM_SECTION_SUBSECTION)
		return 1; /* Start skipping. */
	rv = qemu_read_32(qi, &section_id, "section id", -1);
	if (rv)
		return rv;

	if (sec == QEMU_VM_SECTION_START || sec == QEMU_VM_SECTION_FULL) {
		rv = qemu_read_string(qi, name, "section name");
		if (rv)
			return rv;

		for (i = 0; qemu_device_types[i].name; i++) {
			if (strcmp(qemu_device_types[i].name, name) == 0)
				break;
		}
		if (!qemu_device_types[i].name)
			/* Tell caller the name wasn't recognized. */
			return 1;

		device = calloc(1, qemu_device_types[i].devinfo_size);
		if (!device) {
			fprintf(stderr, "Out of memory allocating device %s\n",
				name);
			return -1;
		}
		rv = qemu_read_32(qi, &device->instance_id, "instance id", -1);
		if (rv)
			return rv;
		rv = qemu_read_32(qi, &device->version_id, "version id", -1);
		if (rv)
			return rv;

		device->section_id = section_id;
		device->type = &qemu_device_types[i];
		list_add_last(&qi->devices, &device->link);
	} else {
		device = qemu_find_device(qi, section_id);
		if (!device) {
			fprintf(stderr, "Missing device by section: %u\n",
				section_id);
			return -1;
		}
	}

	return device->type->load(qi, sec, device);
}

struct search_tree_entry {
	char flags[256]; /* Marks a possible end. */
	struct search_tree_entry *next_state[256];
};
struct search_tree_entry *devsearchtree;

static struct search_tree_entry *
build_devsearchtree(const struct qemu_device_type *devices)
{
	struct search_tree_entry *base;

	base = calloc(1, sizeof(*base));
	if (!base) {
	out_of_memory:
		fprintf(stderr,
			"Out of memory building qemu dev search tree\n");
		return NULL;
	}
	for (; devices->name; devices++) {
		unsigned int pos = 0, len = strlen(devices->name);
		struct search_tree_entry *d = base;
		unsigned char c = len; /* First byte is length. */

		assert(len < 256);
		for (; pos < len; pos++) {
			if (!d->next_state[c]) {
				d->next_state[c] = calloc(1, sizeof(*d));
				if (!d->next_state[c])
					goto out_of_memory;
			}
			d = d->next_state[c];
			c = devices->name[pos];
		}
		assert(!d->flags[c]);
		d->flags[c] = 1;
	}
	return base;
}

struct search_state {
	unsigned int len;
	struct search_tree_entry *pos;
	struct search_state *next;
};

static int
alloc_search_state(struct search_state **empties, struct search_state **stack,
		   struct search_tree_entry *pos)
{
	struct search_state *ret;

	if (*empties) {
		ret = *empties;
		*empties = ret->next;
	} else {
		ret = calloc(1, sizeof(*ret));
		if (!ret) {
			fprintf(stderr,
				"Out of memory searching qemu dev tree\n");
			return -1;
		}
	}

	ret->pos = pos;
	ret->len = 1;
	ret->next = *stack;
	*stack = ret;
	return 0;
}

static void
free_search_state(struct search_state **empties, struct search_state **stack,
		  struct search_state *state, struct search_state *prev)
{
	if (prev)
		prev->next = state->next;
	else
		*stack = state->next;
	state->next = *empties;
	*empties = state;
}

static int
device_search(struct qemu_info *qi, const struct qemu_device_type *devices)
{
	unsigned char buf[4096];
	struct search_state *empties = NULL, *stack = NULL, *s, *p, *n;
	unsigned int len, pos = 0, rlen = 0;
	struct search_tree_entry *d;
	off_t off;
	uint8_t sec;
	int rv = 0;

	if (!devsearchtree)
		devsearchtree = build_devsearchtree(devices);
	if (!devsearchtree)
		return -1;
	d = devsearchtree;

restart:
	len = fread(buf, 1, sizeof(buf), qi->f);
	while (len > 0) {
		for (pos = 0; pos < len; pos++) {
			unsigned char v = buf[pos];

			if (d->flags[v]) {
				rlen = 1;
				goto out;
			}
			for (s = stack; s; s = s->next) {
				if (s->pos->flags[v]) {
					rlen = s->len + 1;
					goto out;
				}
			}
			for (p = NULL, s = stack; s; p = s, s = n) {
				n = s->next;
				if (s->pos->next_state[v]) {
					s->pos = s->pos->next_state[v];
					s->len++;
				} else {
					free_search_state(&empties, &stack,
							  s, p);
				}
			}
			if (d->next_state[v]) {
				rv = alloc_search_state(&empties, &stack,
							d->next_state[v]);
				if (rv)
					goto out;
			}
		}
		len = fread(buf, 1, sizeof(buf), qi->f);
	}
	rv = 1; /* Not found. */
out:
	while (stack) {
		s = stack;
		stack = s->next;
		free(s);
	}
	while (empties) {
		s = empties;
		empties = s->next;
		free(s);
	}
	if (rv)
		return rv;

	/* Back up to the section type. */
	off = ftello(qi->f) - len + pos - (rlen + 4);
	rv = fseek(qi->f, off, SEEK_SET);
	if (rv) {
		fprintf(stderr, "device search seek error: %s\n",
			strerror(errno));
		return -1;
	}
	rv = qemu_read_8(qi, &sec, "sectype(2)", -1);
	if (rv)
		return rv;
	if (sec == QEMU_VM_SECTION_START || sec == QEMU_VM_SECTION_FULL) {
		/* Go back to the byte we just read. */
		rv = fseek(qi->f, off, SEEK_SET);
		if (rv) {
			fprintf(stderr, "device search seek error: %s\n",
				strerror(errno));
			return -1;
		}
		return 0;
	}
	/* Skip to after the first byte of the found name and keep going. */
	rv = fseek(qi->f, off + 6, SEEK_SET);
	if (rv) {
		fprintf(stderr, "device search seek error: %s\n",
			strerror(errno));
		return -1;
	}
	goto restart;
}

static int
qmem_load(struct qemu_info *qi)
{
	int rv;
	uint32_t magic, version;

	rv = qemu_read_32(qi, &magic, "magic", -1);
	if (rv)
		return rv;
	if (magic != QEMU_VM_FILE_MAGIC) {
		fprintf(stderr, "Bad qemu file magic: %x\n", magic);
		return -1;
	}

	rv = qemu_read_32(qi, &version, "version1", -1);
	if (rv)
		return rv;
	if (version != 3) {
		fprintf(stderr, "Bad qemu file version: %u\n", version);
		return -1;
	}

	while (1) {
		uint8_t section;

		rv = qemu_read_8(qi, &section, "section", -1);
		if (rv)
			return rv;

		rv = qemu_read_device(qi, section);
		if (rv < 0)
			return rv;
		if (rv) {
			rv = device_search(qi, qemu_device_types);
			if (rv < 0)
				return rv;
			if (rv)
				break;
		}
	}

	if (!qi->ram_present) {
		fprintf(stderr, "No RAM present in qemu dump\n");
		return -1;
	}
	if (!qi->cpu_present) {
		fprintf(stderr, "No CPU present in qemu dump\n");
		return -1;
	}

	return 0;
}

static int
qemu_load_64reg_notes(struct qemu_info *qi, struct qemu_cpu_devinfo *d,
		      int cpu, int32_t pid)
{
	struct kd_elf_prstatus64 *pr;
	struct x86_64_pt_regs *r;
	unsigned char data[sizeof(*pr) + sizeof(*r)];
	int rv;

	memset(data, 0, sizeof(data));
	pr = (void *) data;
	r = (void *) (data + sizeof(*pr));

	pr->pr_pid = htole32(pid);

	r->r15 = htole64(d->regs[15]);
	r->r14 = htole64(d->regs[14]);
	r->r13 = htole64(d->regs[13]);
	r->r12 = htole64(d->regs[12]);
	r->rbp = htole64(d->regs[5]);
	r->rbx = htole64(d->regs[3]);
	r->r11 = htole64(d->regs[11]);
	r->r10 = htole64(d->regs[10]);
	r->r9 = htole64(d->regs[9]);
	r->r8 = htole64(d->regs[8]);
	r->rax = htole64(d->regs[0]);
	r->rcx = htole64(d->regs[1]);
	r->rdx = htole64(d->regs[2]);
	r->rsi = htole64(d->regs[6]);
	r->rdi = htole64(d->regs[7]);
	r->orig_rax = htole64(0);

	r->rip = htole64(d->eip);
	r->cs = htole64(d->cs.selector);
	r->eflags = htole64(d->eflags);
	r->rsp = htole64(d->regs[4]);
	r->ss = htole32(d->ss.selector);
	r->fs_base = htole64(d->fs.base);
	r->gs_base = htole64(d->fs.base);
	r->ds = htole32(d->ds.selector);
	r->es = htole32(d->es.selector);
	r->fs = htole32(d->fs.selector);
	r->gs = htole32(d->fs.selector);

	rv = elfc_add_note(qi->elf, NT_PRSTATUS, "CORE", 5, data, sizeof(data));
	if (rv)
		pr_err("Unable to add qemu thread info note: %s\n",
		       strerror(elfc_get_errno(qi->elf)));
	return rv;
}

static int
qemu_load_32reg_notes(struct qemu_info *qi, struct qemu_cpu_devinfo *d,
		      int cpu, int32_t pid)
{
	struct kd_elf_prstatus32 *pr;
	struct i386_pt_regs *r;
	unsigned char data[sizeof(*pr) + sizeof(*r)];
	int rv;

	memset(data, 0, sizeof(data));
	pr = (void *) data;
	r = (void *) (data + sizeof(*pr));

	pr->pr_pid = htole32(pid);

	r->ebx = htole32(d->regs[3]);
	r->ecx = htole32(d->regs[1]);
	r->edx = htole32(d->regs[2]);
	r->esi = htole32(d->regs[6]);
	r->edi = htole32(d->regs[7]);
	r->ebp = htole32(d->regs[5]);
	r->eax = htole32(d->regs[0]);

	r->xds = htole32(d->ds.selector);
	r->xes = htole32(d->es.selector);
	r->xfs = htole32(d->fs.selector);
	r->xgs = htole32(d->fs.selector);

	r->orig_eax = htole32(0);

	r->eip = htole32(d->eip);
	r->xcs = htole32(d->cs.selector);
	r->eflags = htole32(d->eflags);
	r->esp = htole32(d->regs[4]);
	r->xss = htole32(d->ss.selector);

	rv = elfc_add_note(qi->elf, NT_PRSTATUS, "CORE", 5, data, sizeof(data));
	if (rv)
		pr_err("Unable to add qemu thread info note: %s\n",
		       strerror(elfc_get_errno(qi->elf)));
	return rv;
}

static int
qemu_add_thread_notes(struct qemu_info *qi, struct kdt_data *dummy_d,
		      struct vmcoreinfo_data *vmci)
{
	struct qemu_cpu_devinfo *dx86;
	int cpu = 0;
	uint32_t pid;
	int rv;

	dx86 = (void *) qemu_find_device_name(qi, "cpu", NULL);
	while (dx86) {
		if (vmci[7].found && vmci[8].found) {
			uint64_t addr;

			/* current task per cpu offset and task pid offset. */
			if (qi->is_64bit) {
				rv = fetch_vaddr_data_err(dummy_d,
					      dx86->gs.base + vmci[7].val, 8,
					      &addr, "percpu task");
			} else {
				uint32_t taddr;

				rv = fetch_vaddr_data_err(dummy_d,
					      dx86->gs.base + vmci[7].val, 4,
					      &taddr, "percpu task");
				addr = taddr;
			}
			if (rv)
				return rv;
			addr = le64toh(addr);
			rv = fetch_vaddr_data_err(dummy_d,
						  addr + vmci[8].val, 4,
						  &pid, "percpu pid");
			if (rv)
				return rv;
			pid = le32toh(pid);
		} else {
			/* Just dummy it out to something. */
			pid = cpu + 1;
		}

		if (qi->is_64bit)
			rv = qemu_load_64reg_notes(qi, dx86, cpu, pid);
		else
			rv = qemu_load_32reg_notes(qi, dx86, cpu, pid);
		if (rv)
			return rv;
		cpu++;
		dx86 = (void *) qemu_find_device_name(qi, "cpu", &dx86->info);
	}

	return 0;
}

struct elfc *
read_qemumem(char *vmdump, char *extra_vminfo, int machineclass)
{
	int rv;
	struct qemu_info *qi;
	struct vmcoreinfo_data vmci[] = {
		{ "PAGESIZE", 10 },			/* 0 */
		{ "SYMBOL(swapper_pg_dir)", 16 },	/* 1 */
		{ "ADDRESS(phys_pgd_ptr)", 16 },	/* 2 */
		{ "SIZE(list_head)", 10 },		/* 3 */
		{ "SYMBOL(vmcoreinfo_data)", 16 },	/* 4 */
		{ "SYMBOL(idt_table)", 16 },		/* 5 */
		{ "SYMBOL(_stext)", 16 },		/* 6 */
		{ "SYMBOL(per_cpu__current_task)", 16 },/* 7 */
		{ "OFFSET(task_struct.pid)", 10 },	/* 8 */
		{ NULL }
	};
	struct qemu_cpu_devinfo *dx86;
	char buf[100];
	uint64_t textoffset = 0;
	struct kdt_data dummy_d;
	int endc;

	if (!extra_vminfo) {
		fprintf(stderr, "qemu will no work without extravminfo\n");
		return NULL;
	}

	qi = malloc(sizeof(*qi));
	if (!qi) {
		fprintf(stderr, "Unable to allocate qemu mem info\n");
		return NULL;
	}
	memset(qi, 0, sizeof(*qi));
	list_init(&qi->devices);
	qmem_btree_init(&qi->qmem);
	memset(&dummy_d, 0, sizeof(dummy_d));

	qi->f = fopen(vmdump, "r");
	if (!qi->f) {
		fprintf(stderr, "Unable to open %s: %s\n", vmdump,
			strerror(errno));
		rv = -1;
		goto out_err;
	}

	if (machineclass == ELFCLASS32) {
		qi->is_machine_64bit = false;
		dummy_d.arch = &i386_arch;
	} else if (machineclass == ELFCLASS64) {
		qi->is_machine_64bit = true;
		dummy_d.arch = &x86_64_arch;
	} else {
		fprintf(stderr, "For qemu you must set machine size with "
			"--m32 or --m64");
		goto out_err;
	}

	handle_vminfo_notes(NULL, vmci, extra_vminfo);
	if (!vmci[3].found) {
		fprintf(stderr,
			"Error: SIZE(list_head) not in vmcore\n");
		goto out_err;
	}
	if (vmci[3].val == 8) {
		qi->is_64bit = false;
	} else if (vmci[3].val == 16) {
		qi->is_64bit = true;
	} else {
		fprintf(stderr, "Error: SIZE(list_head) not valid: %llu\n",
			(unsigned long long) vmci[3].val);
		goto out_err;
	}

	if (qi->is_64bit && !qi->is_machine_64bit) {
		fprintf(stderr, "Error: Must have a 64-bit machine for "
			"a 64-bit kernel\n");
		goto out_err;
	}

	if (vmci[0].found) {
		qi->page_size = vmci[0].val;
	} else {
		qi->page_size = 4096;
		fprintf(stderr,
			"Warning: Page size not in vminfo notes\n");
	}

	qi->elf = elfc_alloc();
	if (!qi->elf) {
		fprintf(stderr, "Out of memory allocating elfc\n");
		goto out_err;
	}
	rv = elfc_setup(qi->elf, ET_CORE);
	if (rv == -1) {
		fprintf(stderr, "Error setting up elfc: %s\n",
			strerror(elfc_get_errno(qi->elf)));
		goto out_err;
	}
	elfc_setmachine(qi->elf, qi->is_64bit ? EM_X86_64 : EM_386);
	/*
	 * 32-bit architectures often can address more than 32-bits of
	 * physical memory.  So always use 64-bits.
	 */ 
	elfc_setclass(qi->elf, ELFCLASS64);
	elfc_setencoding(qi->elf, ELFDATA2LSB);

	rv = qmem_load(qi);
	if (rv)
		goto out_err;

	dx86 = (void *) qemu_find_device_name(qi, "cpu", NULL);
	assert(dx86); /* Shouldn't be able to happen. */

	dummy_d.pgd = dx86->cr3 & ~4095ULL;
	dummy_d.extra_vminfo = extra_vminfo;

	endc = sprintf(buf, "ADDRESS(phys_pgd_ptr)=%llx\n",
		       (unsigned long long) dummy_d.pgd);

	dummy_d.elf = qi->elf;

	if (vmci[5].found) /* idt_table */
		/*
		 * Calculate the load offset, if any.  idt.base should
		 * have the idt_table address, so this is easy.
		 */
		textoffset = vmci[5].val - dx86->idt.base;

	rv = dummy_d.arch->setup_arch_pelf(qi->elf, &dummy_d,
					   &dummy_d.arch_data);
	if (rv)
		goto out_err;

	if (vmci[4].found) { /* Try to get vmcoreinfo_data from dump. */
		char read_page[4097];

		rv = fetch_vaddr_data_err(&dummy_d, vmci[4].val + textoffset,
				          sizeof(read_page) - 1, read_page,
					  "vmcoreinfo_data");
		if (rv)
			goto out_err;
		read_page[4096] = '\0';
		rv = elfc_add_note(qi->elf, 0, "VMCOREINFO",
				   strlen("VMCOREINFO"),
				   read_page, strlen(read_page));
		if (rv == -1) {
			fprintf(stderr,
				"Error adding elf VMCOREINFO note: %s\n",
				strerror(elfc_get_errno(qi->elf)));
			goto out_err;
		}
	} else if (textoffset && vmci[6].found) {
		/*
		 * Set our own value for _stext and disable the other.
		 * This will let the other code calculate the base offsets
		 * properly.
		 */
		char *pos = strstr(extra_vminfo, "SYMBOL(_stext)");

		*pos = 'W'; /* Change "SYMBOL" to "WYMBOL" */
		endc = sprintf(buf + endc, "SYMBOL(_stext)=%llx\n",
			       (unsigned long long) (vmci[6].val + textoffset));
	}

	rv = elfc_add_note(qi->elf, 0, "VMCOREINFO", 12,
			   buf, strlen(buf) + 1);
	if (rv == -1) {
		fprintf(stderr, "Error adding phys_pgd_ptr note: %s\n",
			strerror(elfc_get_errno(qi->elf)));
		goto out_err;
	}

	rv = qemu_add_thread_notes(qi, &dummy_d, vmci);
	if (rv)
		goto out_err;

	dummy_d.arch->cleanup_arch_data(dummy_d.arch_data);

	return qi->elf;

out_err:
	if (dummy_d.arch_data)
		dummy_d.arch->cleanup_arch_data(dummy_d.arch_data);
	if (qi->elf)
		elfc_free(qi->elf);
	if (qi->f)
		fclose(qi->f);
	qmem_btree_free(&qi->qmem);
	free(qi);
	return NULL;
}
