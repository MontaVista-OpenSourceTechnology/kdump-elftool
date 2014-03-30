/*
 * kdump-mips.c
 *
 * MIPS specific code for handling coredumps
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

#include "kdump-tool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include "elfc.h"

#define ENTRIES_PER_PGTAB(d, type, pgtab_size)				\
	((1 << d->type ##_order) * (1 << d->page_shift) / (pgtab_size))

#define MAX_SHIFT 16
#define MIN_SHIFT 12
#define MAX_ORDER 1
#define MAX_PGTAB_ENTRIES(pgentry_size) ((1 << MAX_SHIFT) * (1 << MAX_ORDER) / \
					 (pgentry_size))

#define ADDR32_MASK(shift) ((1 << (shift)) - 1)
#define ADDR64_MASK(shift) ((1ULL << (shift)) - 1)

/*
 * Order here does not matter, as long as the required elements are all
 * last.
 */
enum vmcoreinfo_labels {
	VMCI__text,
	VMCI__end,
	VMCI__phys_to_kernel_offset,
	VMCI_CKSEG0,
	VMCI_CKSSEG,
	VMCI_PHYS_OFFSET,
	VMCI_PMD_ORDER,
	VMCI__PAGE_HUGE,
	/* Begin required elements. */
#define VREQ	VMCI_PAGE_SHIFT
	VMCI_PAGE_SHIFT,
	VMCI_PGD_ORDER,
	VMCI_PTE_ORDER,
	VMCI__PAGE_PRESENT,
	VMCI__PFN_SHIFT,
	VMCI_PAGE_OFFSET,
	/* End actual elements. */
	VMCI_NUM_ELEMENTS
};

#define VMCI_ADDR(lbl)						\
	[VMCI_ ## lbl] = { "ADDRESS(" #lbl ")", 16, 0, 0 }
#define VMCI_NUM(lbl)						\
	[VMCI_ ## lbl] = { "NUMBER(" #lbl ")", 10, 0, 0 }

static uint64_t convbe64toh(uint64_t val)
{
	return be64toh(val);
}
static uint64_t convle64toh(uint64_t val)
{
	return le64toh(val);
}
static uint32_t convbe32toh(uint32_t val)
{
	return be32toh(val);
}
static uint32_t convle32toh(uint32_t val)
{
	return le32toh(val);
}

struct mips_walk_data {
	unsigned int page_shift;
	unsigned int page_size;
	unsigned int pgd_order;
	unsigned int pgd_shift;
	int pmd_present;
	unsigned int pmd_order;
	unsigned int pmd_shift;
	unsigned int pte_order;
	unsigned int pfn_shift;
	/* pte_shift is page_shift */
	uint64_t page_present_mask;
	int is_64bit;
	int is_bigendian;
	uint64_t (*conv64)(uint64_t val);
	uint32_t (*conv32)(uint32_t val);
	uint64_t page_mask;

	uint64_t _text;
	uint64_t _end;
	uint64_t phys_to_kernel_offset;
	int mapped_kernel;

	uint64_t _PAGE_HUGE;

	uint64_t CKSEG0;
	uint64_t CKSSEG;

	uint64_t PAGE_OFFSET;
	uint64_t PHYS_OFFSET;
};

static int
mips_virt_to_phys32(const struct mips_walk_data *d, GElf_Addr addr, int offset,
		    uint32_t vaddr, uint32_t *paddr)
{
	/* Convert to a physical address. */
	*paddr = vaddr - d->PAGE_OFFSET + d->PHYS_OFFSET;
	return 0;
}

static int
handle_32pte(struct elfc *pelf, const struct mips_walk_data *d,
	     GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pte[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pte_count = ENTRIES_PER_PGTAB(d, pte, sizeof(uint32_t));
	int i;
	int rv;
	uint32_t start = begin_addr >> d->page_shift;
	uint32_t end = end_addr >> d->page_shift;

	begin_addr &= ADDR32_MASK(d->page_shift);
	end_addr &= ADDR32_MASK(d->page_shift);
	rv = elfc_read_pmem(pelf, pteaddr, pte,
			    pte_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pte_count - 1))
		pte_count = end + 1;

	for (i = start; i < pte_count; i++) {
		uint32_t lpte = d->conv32(pte[i]);

		if (!(lpte & d->page_present_mask))
			continue;

		rv = handle_page(pelf,
				 lpte >> d->pfn_shift << d->page_shift,
				 vaddr | i << d->page_shift,
				 1 << d->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_32pmd(struct elfc *pelf, const struct mips_walk_data *d,
	     GElf_Addr vaddr, GElf_Addr pmdaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d, pmd, sizeof(uint32_t));
	int i;
	int rv;
	uint32_t start = begin_addr >> d->pmd_shift;
	uint32_t end = end_addr >> d->pmd_shift;

	begin_addr &= ADDR32_MASK(d->pmd_shift);
	end_addr &= ADDR32_MASK(d->pmd_shift);
	rv = elfc_read_pmem(pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pmd_count - 1))
		pmd_count = end + 1;

	for (i = start; i < pmd_count; i++) {
		uint32_t lpmd = d->conv32(pmd[i]);

		if (mips_virt_to_phys32(d, pmdaddr, i, lpmd, &lpmd) == -1)
			continue;

		rv = handle_32pte(pelf, d, vaddr | i << d->pmd_shift,
				  lpmd, begin_addr, end_addr,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips32(struct elfc *pelf, const struct mips_walk_data *d,
	    GElf_Addr pgdaddr,
	    GElf_Addr begin_addr, GElf_Addr end_addr,
	    handle_page_f handle_page, void *userdata)
{
	uint32_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d, pgd, sizeof(uint32_t));
	int i;
	int rv;
	GElf_Addr addr, maxaddr;
	uint32_t dir_offset = d->PAGE_OFFSET - d->PHYS_OFFSET;
	uint32_t start, end;

	/*
	 * Add the direct mapping first.
	 */
	maxaddr = elfc_max_paddr(pelf);
	if ((begin_addr < maxaddr + dir_offset) && (end_addr >= dir_offset)) {
		if (begin_addr > dir_offset)
			start = (begin_addr - dir_offset) & d->page_mask;
		else
			start = 0;
		if (end_addr < maxaddr + dir_offset)
			end = end_addr - dir_offset + 1;
		else
			end = maxaddr;
		for (addr = start; addr < end; addr += d->page_size) {
			rv = handle_page(pelf,
					 addr, addr + dir_offset,
					 1 << d->page_shift, userdata);
			if (rv == -1)
				return -1;
		}
	}

	rv = elfc_read_pmem(pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	start = begin_addr >> d->pgd_shift;
	end = end_addr >> d->pgd_shift;
	begin_addr &= ADDR32_MASK(d->pgd_shift);
	end_addr &= ADDR32_MASK(d->pgd_shift);

	for (i = start; i <= end; i++) {
		uint32_t lpgd = d->conv32(pgd[i]);

		if (mips_virt_to_phys32(d, pgdaddr, i, lpgd, &lpgd) == -1)
			continue;

		if (d->pmd_present)
			rv = handle_32pmd(pelf, d, i << d->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else
			rv = handle_32pte(pelf, d, i << d->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
mips_virt_to_phys64(const struct mips_walk_data *d, GElf_Addr addr, int offset,
		    GElf_Addr vaddr, GElf_Addr *paddr)
{
	/* Convert to a physical address. */
	if (d->is_64bit) {
		if (d->mapped_kernel) {
			if ((vaddr >= d->_text) && (vaddr < d->_end)) {
				*paddr = vaddr - d->phys_to_kernel_offset;
				return 0;
			}
		}
		if (vaddr < d->CKSEG0) {
			*paddr = vaddr & 0x000000ffffffffffULL;
			return 0;
		}
		if (vaddr < d->CKSSEG) {
			*paddr = vaddr & 0x1fffffffULL;
			return 0;
		}

		fprintf(stderr, "Unknown virtual address type in "
			"table %llx:%d: %llx\n",
			(unsigned long long) addr, offset,
			(unsigned long long) vaddr);
		return -1;
	} else {
		*paddr = vaddr - d->PAGE_OFFSET + d->PHYS_OFFSET;
	}
	return 0;
}

static int
handle_64pte(struct elfc *pelf, const struct mips_walk_data *d,
	     GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pte[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pte_count = ENTRIES_PER_PGTAB(d, pte, sizeof(uint64_t));
	int i;
	int rv;
	uint64_t start = begin_addr >> d->page_shift;
	uint64_t end = end_addr >> d->page_shift;

	begin_addr &= ADDR64_MASK(d->page_shift);
	end_addr &= ADDR64_MASK(d->page_shift);
	rv = elfc_read_pmem(pelf, pteaddr, pte,
			    pte_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pte_count - 1))
		pte_count = end + 1;

	for (i = start; i < pte_count; i++) {
		uint64_t lpte = d->conv64(pte[i]);

		if (!(lpte & d->page_present_mask))
			continue;

		rv = handle_page(pelf,
				 lpte >> d->pfn_shift << d->page_shift,
				 vaddr | i << d->page_shift,
				 1 << d->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pmd(struct elfc *pelf, const struct mips_walk_data *d,
	     GElf_Addr vaddr, GElf_Addr pmdaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d, pmd, sizeof(uint64_t));
	int i;
	int rv;
	uint64_t start = begin_addr >> d->pmd_shift;
	uint64_t end = end_addr >> d->pmd_shift;

	begin_addr &= ADDR64_MASK(d->pmd_shift);
	end_addr &= ADDR64_MASK(d->pmd_shift);

	rv = elfc_read_pmem(pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pmd_count - 1))
		pmd_count = end + 1;

	for (i = start; i < pmd_count; i++) {
		GElf_Addr lpmd = d->conv64(pmd[i]);

		if ((lpmd & d->_PAGE_HUGE) && (lpmd & d->page_present_mask)) {
			rv = handle_page(pelf,
					 lpmd >> d->pfn_shift << d->page_shift,
					 vaddr | i << d->pmd_shift,
					 1 << d->pmd_shift, userdata);
			if (rv == -1)
				return -1;
		}
		if (mips_virt_to_phys64(d, pmdaddr, i, lpmd, &lpmd) == -1)
			continue;

		rv = handle_64pte(pelf, d, vaddr | i << d->pmd_shift,
				  lpmd, begin_addr, end_addr,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips64(struct elfc *pelf, const struct mips_walk_data *d,
	    GElf_Addr pgdaddr,
	    GElf_Addr begin_addr, GElf_Addr end_addr,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d, pgd, sizeof(uint64_t));
	int i;
	int rv;
	GElf_Addr addr, maxaddr;
	uint64_t start, end;

	/*
	 * Add the default page tables for iomem and kernel.
	 * This is ioremap addresses and the kernel address space.
	 * MIPS uses hardwired TLBs for some of these, and some are
	 * intrinsic to processors.
	 */
	if (d->mapped_kernel &&
	    (begin_addr < d->_end) && (end_addr >= d->_text)) {
		if (begin_addr > d->_text)
			start = begin_addr & d->page_mask;
		else
			start = d->_text;
		if (end_addr < d->_text)
			end = end_addr + 1;
		else
			end = d->_end;
			
		for (addr = d->_text; addr < d->_end; addr += d->page_size) {
			rv = handle_page(pelf,
					 addr - d->phys_to_kernel_offset,
					 addr,
					 1 << d->page_shift, userdata);
			if (rv == -1)
				return -1;
		}
	}
	maxaddr = elfc_max_paddr(pelf);
	if ((begin_addr < maxaddr + d->PAGE_OFFSET) &&
	    (end_addr >= d->PAGE_OFFSET)) {
		if (begin_addr > d->PAGE_OFFSET)
			start = (begin_addr - d->PAGE_OFFSET) & d->page_mask;
		else
			start = 0;
		if (end_addr < maxaddr + d->PAGE_OFFSET)
			end = end_addr - d->PAGE_OFFSET + 1;
		else
			end = maxaddr;
		for (addr = start; addr < end; addr += d->page_size) {
			rv = handle_page(pelf,
					 addr, addr + d->PAGE_OFFSET,
					 1 << d->page_shift, userdata);
			if (rv == -1)
				return -1;
		}
	}
	if (maxaddr > 0x20000000)
		maxaddr = 0x20000000;
	if ((begin_addr < maxaddr + d->CKSEG0) &&
	    (end_addr >= d->CKSEG0)) {
		if (begin_addr > d->CKSEG0)
			start = (begin_addr - d->CKSEG0) & d->page_mask;
		else
			start = 0;
		if (end_addr < maxaddr + d->CKSEG0)
			end = end_addr - d->CKSEG0 + 1;
		else
			end = maxaddr;
		for (addr = start; addr < end; addr += d->page_size) {
			rv = handle_page(pelf,
					 addr, addr + d->CKSEG0,
					 1 << d->page_shift, userdata);
			if (rv == -1)
				return -1;
		}
	}

	rv = elfc_read_pmem(pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = 0; i < pgd_count; i++) {
		GElf_Addr lpgd = d->conv64(pgd[i]);

		if (mips_virt_to_phys64(d, pgdaddr, i, lpgd, &lpgd) == -1)
			continue;

		if (d->pmd_present)
			rv = handle_64pmd(pelf, d, i << d->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else
			rv = handle_64pte(pelf, d, i << d->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
mips_arch_setup(struct elfc *pelf, void **arch_data)
{
	struct mips_walk_data *d;
	struct vmcoreinfo_data vmci[VMCI_NUM_ELEMENTS + 1] = {
		VMCI_ADDR(_text),
		VMCI_ADDR(_end),
		VMCI_ADDR(_phys_to_kernel_offset),
		VMCI_ADDR(CKSEG0),
		VMCI_ADDR(CKSSEG),
		VMCI_ADDR(PAGE_OFFSET),
		VMCI_ADDR(PHYS_OFFSET),
		VMCI_NUM(PMD_ORDER),
		VMCI_NUM(_PAGE_HUGE),
		VMCI_NUM(PAGE_SHIFT),
		VMCI_NUM(PGD_ORDER),
		VMCI_NUM(PTE_ORDER),
		VMCI_NUM(_PAGE_PRESENT),
		VMCI_NUM(_PFN_SHIFT),
	};
	int i;

	d = malloc(sizeof(*d));
	if (!d) {
		fprintf(stderr, "Out of memory allocating mips arch data\n");
		return -1;
	}
	memset(d, 0, sizeof(*d));

	handle_vminfo_notes(pelf, vmci);
	for (i = VREQ; vmci[i].name; i++) { 
		if (!vmci[i].found) {
			fprintf(stderr, "%s not present in input file notes, "
				"it is required for operation\n", vmci[i].name);
			return -1;
		}
	}

	d->page_shift = vmci[VMCI_PAGE_SHIFT].val;
	d->page_size = (1 << d->page_shift);
	d->pgd_order = vmci[VMCI_PGD_ORDER].val;
	d->pte_order = vmci[VMCI_PTE_ORDER].val;
	d->page_present_mask = vmci[VMCI__PAGE_PRESENT].val;
	d->pfn_shift = vmci[VMCI__PFN_SHIFT].val;
	d->_PAGE_HUGE = vmci[VMCI__PAGE_HUGE].val; /* Zero if not set */
	d->PAGE_OFFSET = vmci[VMCI_PAGE_OFFSET].val;
	d->is_64bit = elfc_getclass(pelf) == ELFCLASS64;
	d->is_bigendian = elfc_getencoding(pelf) == ELFDATA2MSB;

	d->pmd_present = vmci[VMCI_PMD_ORDER].found;
	d->pmd_order = vmci[VMCI_PMD_ORDER].val;

	if (d->pgd_order > MAX_ORDER) {
		fprintf(stderr, "pgd_order is %d, only 0 or 1 are supported.\n",
			d->pgd_order);
		return -1;
	}

	if (d->pmd_present && d->pmd_order > MAX_ORDER) {
		fprintf(stderr, "pmd_order is %d, only 0 or 1 are supported.\n",
			d->pmd_order);
		return -1;
	}

	if (d->pte_order > MAX_ORDER) {
		fprintf(stderr, "pte_order is %d, only 0 or 1 are supported.\n",
			d->pte_order);
		return -1;
	}

	if ((d->page_shift > MAX_SHIFT) || (d->page_shift < MIN_SHIFT)) {
		fprintf(stderr, "page_shift is %d, only %d-%d are supported.\n",
			d->page_shift, MIN_SHIFT, MAX_SHIFT);
		return -1;
	}

	d->page_mask = ~((uint64_t) (d->page_size - 1));

	if (d->is_bigendian) {
		d->conv32 = convbe32toh;
		d->conv64 = convbe64toh;
	} else {
		d->conv32 = convle32toh;
		d->conv64 = convle64toh;
	}

	if (d->is_64bit) {
		i = vmci[VMCI__text].found + vmci[VMCI__end].found +
			vmci[VMCI__phys_to_kernel_offset].found;
		if (i != 0) {
			if (i != 3) {
				fprintf(stderr, "All of _text, _end, and"
					" phys_to_kernel_offset not present\n");
				return -1;
			}
			d->_text = vmci[VMCI__text].val;
			d->_end = vmci[VMCI__end].val;
			d->phys_to_kernel_offset =
				vmci[VMCI__phys_to_kernel_offset].val;
			d->mapped_kernel = 1;
		} else
			d->mapped_kernel = 0;

		if (!vmci[VMCI_CKSEG0].found) {
			fprintf(stderr, "CKSEG0 not present in core file\n");
			return -1;
		}
		d->CKSEG0 = vmci[VMCI_CKSEG0].val;

		if (!vmci[VMCI_CKSSEG].found) {
			fprintf(stderr, "CKSSEG not present in core file\n");
			return -1;
		}
		d->CKSSEG = vmci[VMCI_CKSSEG].val;

		if (d->pmd_present) {
			d->pmd_shift = d->page_shift + (d->pte_order ? 10 : 9);
			d->pgd_shift = d->pmd_shift + (d->pmd_order ? 10 : 9);
		} else {
			d->pgd_shift = d->page_shift + (d->pte_order ? 10 : 9);
		}
	} else {
		if (d->pmd_present) {
			d->pmd_shift = d->page_shift + (d->pte_order ? 11 : 10);
			d->pgd_shift = d->pmd_shift + (d->pmd_order ? 11 : 10);
		} else
			d->pgd_shift = d->page_shift + (d->pte_order ? 11 : 10);
		
		if (!vmci[VMCI_PHYS_OFFSET].found) {
			fprintf(stderr,
				"PHYS_OFFSET not present in core file\n");
			return -1;
		}
		d->PHYS_OFFSET = vmci[VMCI_PHYS_OFFSET].val;
	}

	*arch_data = d;
	return 0;
}

static void
mips_arch_cleanup(void *arch_data)
{
	free(arch_data);
}

static int
mips_walk(struct elfc *pelf, GElf_Addr pgd,
	  GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	  handle_page_f handle_page, void *userdata)
{
	const struct mips_walk_data *d = arch_data;
	int rv;

	if (d->is_64bit)
		rv = walk_mips64(pelf, d, pgd, begin_addr, end_addr,
				 handle_page, userdata);
	else
		rv = walk_mips32(pelf, d, pgd, begin_addr, end_addr,
				 handle_page, userdata);

	return rv;
}

struct archinfo mips_arch = {
	.name = "mips",
	.elfmachine = EM_MIPS,
	.default_elfclass = ELFCLASS64,
	.setup_arch_pelf = mips_arch_setup,
	.cleanup_arch_data = mips_arch_cleanup,
	.walk_page_table = mips_walk
};
