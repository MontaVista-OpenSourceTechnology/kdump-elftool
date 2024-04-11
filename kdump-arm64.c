/*
 * kdump-arm64.c
 *
 * ARM64 specific code for handling coredumps
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2014 MontaVista Software Inc.
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

#include "kdump-elftool.h"
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <malloc.h>
#include <stdlib.h>

#include "elfc.h"

/*
 * On ARM64, addresses 0x0000000000000000 to 0x0000ffffffffffff are
 * userspace and addresses 0xffff000000000000 to 0xffffffffffffffff
 * are kernel space.  bit 49 is "sign extended".  Bit 49 is also used
 * to tell which pgd to use.  If bit 49 is 0, TTB0 (TTBR0 in the Linux
 * sources) is used and the next 48 bits are translated by the address
 * table.  If bit 49 is 1, then TTB1 (TTBR1) is used.
 */

struct arm64_walk_data {
	struct elfc *pelf;
	uint32_t page_size;
	uint32_t va_bits;
	uint64_t kimage_voffset;
	uint64_t phys_offset;
	int pgtable_levels;
	int is_bigendian;
	uint64_t (*conv64)(void *in);
};

#define MASK(x) ((1ULL << (x)) - 1)

static void
arm64_pgtable_bits(struct arm64_walk_data *awd, int level,
		   unsigned int *pgd_shift, unsigned int *mask_shift)
{
	if (level == 3) {
		switch (awd->page_size) {
		case 4096:
			*pgd_shift = 39;
			*mask_shift = 48;
			break;
		case 16384:
			*pgd_shift = 47;
			*mask_shift = 48;
			break;
		case 65536:
			abort();
			break;
		}
	} else if (level == 2) {
		switch (awd->page_size) {
		case 4096:
			*pgd_shift = 30;
			*mask_shift = 39;
			break;
		case 16384:
			*pgd_shift = 36;
			*mask_shift = 47;
			break;
		case 65536:
			*pgd_shift = 42;
			*mask_shift = 48;
			break;
		}
	} else if (level == 1) {
		switch (awd->page_size) {
		case 4096:
			*pgd_shift = 21;
			*mask_shift = 30;
			break;
		case 16384:
			*pgd_shift = 25;
			*mask_shift = 36;
			break;
		case 65536:
			*pgd_shift = 29;
			*mask_shift = 42;
			break;
		}
	} else {
		switch (awd->page_size) {
		case 4096:
			*pgd_shift = 12;
			*mask_shift = 21;
			break;
		case 16384:
			*pgd_shift = 14;
			*mask_shift = 25;
			break;
		case 65536:
			*pgd_shift = 16;
			*mask_shift = 29;
			break;
		}
	}
}

/*
 * Note that "level" here counts backwards from the way ARM numbers
 * their tables.  A "3" here means a level 0 table, a "0" here means
 * a level 3 table.
 */
static int
arm64_level(struct arm64_walk_data *awd, GElf_Addr vaddr, GElf_Addr tbladdr,
	    GElf_Addr begin_addr, GElf_Addr end_addr, int level,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pgd[8192];
	unsigned int pgd_size;
	unsigned int pgd_shift = 0;
	unsigned int mask_shift = 0;
	int i;
	int rv;
	uint64_t start = begin_addr;
	uint64_t end = end_addr;

	
	arm64_pgtable_bits(awd, level, &pgd_shift, &mask_shift);
	
	pgd_size = (1 << (mask_shift - pgd_shift)) * 8;
	start = (start & MASK(mask_shift)) >> pgd_shift;
	end = (end & MASK(mask_shift)) >> pgd_shift;
	begin_addr &= MASK(pgd_shift);
	end_addr &= MASK(pgd_shift);

	rv = elfc_read_pmem(awd->pelf, tbladdr, pgd, pgd_size);
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx(%d): %s\n", (unsigned long long) tbladdr,
			level, strerror(elfc_get_errno(awd->pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		uint64_t lpgd = awd->conv64(&pgd[i]);
		uint64_t paddr;

		/* Low bit is enable bit. */
		if (!(lpgd & 1))
			/* Page pointer is not valid. */
			continue;

		if (level == 0 && !(lpgd & 2))
			/*
			 * Reserved type for level 3 (we count backwards
			 * from what is in the ARM manual) tables.
			 */
			continue;

		paddr = lpgd & ~((uint64_t)awd->page_size - 1);
		paddr &= MASK(48);

		/*
		 * Next bit says whether it is a next level table or a
		 * page entry, except for level 3 page tables which
		 * are always page entries.
		 */
		if (lpgd & 2 && level != 0)
			rv = arm64_level(awd,
					 vaddr | (((GElf_Addr) i) << pgd_shift),
					 paddr,
					 begin_addr, end_addr, level - 1,
					 handle_page, userdata);
		else
			rv = handle_page(awd->pelf, 
					 paddr,
					 vaddr | (((GElf_Addr) i) << pgd_shift),
					 1 << pgd_shift, userdata);
		if (rv == -1)
			return -1;
	}

	return 0;
}

static int
arm64_walk(struct elfc *pelf, GElf_Addr pgdaddr,
	 GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	 handle_page_f handle_page, void *userdata)
{
	struct arm64_walk_data *awd = arch_data;
	GElf_Addr btop, etop;
	int rv = 0;

	btop = begin_addr & 0xffff000000000000ULL;
	etop = end_addr & 0xffff000000000000ULL;
	begin_addr &= ~0xffff000000000000ULL;
	end_addr &= ~0xffff000000000000ULL;
	if (btop == 0) {
		/*
		 * Here we would need the TTBR0 value, which is not
		 * readily available.  So we just ignore user address
		 * space for now.
		 */
	}
	if (etop) {
		uint64_t estart = begin_addr;

		if (btop == 0)
			estart = 0;

		rv = arm64_level(awd, 0xffff000000000000ULL, pgdaddr,
				 estart, end_addr, awd->pgtable_levels - 1,
				 handle_page, userdata);
	}
	return rv;
}

static int
arm64_vmem_to_pmem(struct elfc *elf, GElf_Addr vaddr, GElf_Addr *paddr,
		   void *arch_data)
{
	int rv = 0;
	struct arm64_walk_data *awd = arch_data;

	if (vaddr > 0xffff000000000000ULL)
		*paddr = vaddr - awd->kimage_voffset;
	else
		rv = elfc_vmem_to_pmem(elf, vaddr, paddr);

	return rv;
}

static int
arm64_task_ptregs(struct kdt_data *d, GElf_Addr task, void *regs)
{
	uint64_t *pt_regs = regs;
	uint32_t offset = d->task_thread + d->arm64_thread_cpu_context;
	int rv;

	if (!d->arm64_thread_cpu_context_found) {
		pr_err("ARM64 thread_cpu_context offset "
		       "missing from vminfo, unable to convert processes "
		       "to gdb threads\n");
		return -1;
	}

#define GETREG(name, num, coffset) do { \
	rv = fetch_vaddr64(d, task + offset + (coffset * 8),		    \
			   pt_regs + num, name);			    \
	if (rv)								    \
		return rv;						    \
	} while(0)

	GETREG("r19", 19, 0);
	GETREG("r20", 20, 1);
	GETREG("r21", 21, 2);
	GETREG("r22", 22, 3);
	GETREG("r23", 23, 4);
	GETREG("r24", 24, 5);
	GETREG("r25", 25, 6);
	GETREG("r26", 26, 7);
	GETREG("r27", 27, 8);
	GETREG("r28", 28, 9);
	GETREG("fp",  29, 10);
	GETREG("lr",  30, 12);
	GETREG("sp",  31, 11);

	/*
	 * We set the PC to the return value of cpu_switch_to,
	 * which is the return value (LR). LR will be the same
	 * at that point, so everything should be correct here.
	 */
	GETREG("pc", 32, 12);

	return 0;
}

enum vmcoreinfo_labels {
	VMCI_NUMBER_VA_BITS,
	VMCI_NUMBER_kimage_voffset,
	VMCI_NUMBER_PHYS_OFFSET,
	VMCI_PAGESIZE,
	/* End actual elements. */
	VMCI_NUM_ELEMENTS
};

static int
arm64_arch_setup(struct elfc *pelf, struct kdt_data *d, void **arch_data)
{
	struct arm64_walk_data *awd;
	struct vmcoreinfo_data vmci[VMCI_NUM_ELEMENTS + 1] = {
		VMCI_NUMBER(VA_BITS),
		VMCI_HEXNUMBER(kimage_voffset),
		VMCI_HEXNUMBER(PHYS_OFFSET),
		VMCI_PAGESIZE(),
		{ NULL }
	};
	int i;

	awd = malloc(sizeof(*awd));
	if (!awd) {
		fprintf(stderr, "Out of memory allocating arm arch data\n");
		return -1;
	}
	memset(awd, 0, sizeof(*awd));

	handle_vminfo_notes(pelf, vmci, d->extra_vminfo);
	for (i = 0; i < VMCI_NUM_ELEMENTS; i++) { 
		if (!vmci[i].found) {
			fprintf(stderr, "%s not present in input file notes, "
				"it is required for operation\n", vmci[i].name);
			return -1;
		}
	}

	awd->page_size = vmci[VMCI_PAGESIZE].val;
	awd->pelf = pelf;
	awd->conv64 = d->conv64;
	awd->va_bits = vmci[VMCI_NUMBER_VA_BITS].val;
	awd->kimage_voffset = vmci[VMCI_NUMBER_kimage_voffset].val;
	awd->phys_offset = vmci[VMCI_NUMBER_PHYS_OFFSET].val;

	switch (awd->page_size) {
	case 4096:
		if (awd->va_bits > 39)
			awd->pgtable_levels = 4;
		else
			awd->pgtable_levels = 3;
		break;

	case 16384:
		if (awd->va_bits > 47)
			awd->pgtable_levels = 4;
		else if (awd->va_bits > 36)
			awd->pgtable_levels = 3;
		else
			awd->pgtable_levels = 2;
		break;

	case 65536:
		if (awd->va_bits > 42)
			awd->pgtable_levels = 3;
		else
			awd->pgtable_levels = 2;
		break;

	default:
		fprintf(stderr, "Invalid page size: %u\n", awd->page_size);
		free(awd);
		return -1;
	}
	
	d->section_size_bits = 30;
	d->max_physmem_bits = 48;

	d->fetch_ptregs = arm64_task_ptregs;
	d->pt_regs_size = 35 * 8;

	*arch_data = awd;

	return 0;
}

static void
arm64_arch_cleanup(void *arch_data)
{
	free(arch_data);
}

struct archinfo arm64_arch = {
	.name = "arm64",
	.elfmachine = EM_AARCH64,
	.default_elfclass = ELFCLASS64,
	.setup_arch_pelf = arm64_arch_setup,
	.cleanup_arch_data = arm64_arch_cleanup,
	.walk_page_table = arm64_walk,
	.vmem_to_pmem = arm64_vmem_to_pmem
};
