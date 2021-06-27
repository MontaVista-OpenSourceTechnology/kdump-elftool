/*
 * kdump-x86_64.c
 *
 * x86_64 specific code for handling coredumps
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

#include "elfc.h"
#include "kdump-x86.h"

#define PHYSADDRMASK		0x0000ffffffffffff

#define PAGESHIFT_4K		12
#define PAGEMASK_4K		((1ULL << PAGESHIFT_4K) - 1)
#define PHYSADDRMASK_4K		(PHYSADDRMASK & ~PAGEMASK_4K)
#define PAGESIZE_4K		(1 << PAGESHIFT_4K)

#define PAGESHIFT_2M		21
#define PAGEMASK_2M		((1ULL << PAGESHIFT_2M) - 1)
#define PHYSADDRMASK_2M		(PHYSADDRMASK & ~PAGEMASK_2M)
#define PAGESIZE_2M		(1 << PAGESHIFT_2M)

#define PAGESHIFT_1G		30
#define PAGEMASK_1G		((1ULL << PAGESHIFT_1G) - 1)
#define PHYSADDRMASK_1G		(PHYSADDRMASK & ~PAGEMASK_1G)
#define PAGESIZE_1G		(1 << PAGESHIFT_1G)

#define PAGESHIFT_L1		39
#define PAGEMASK_L1		((1ULL << PAGESHIFT_L1) - 1)
#define PHYSADDRMASK_L1		(PHYSADDRMASK & ~PAGEMASK_L1)
#define PAGESIZE_L1		(1 << PAGESHIFT_L1)

#define KERNBASE		0xffff000000000000

/*
 * This section of memory is used for mapping a bunch of virtual
 * pages to the same physical page for use by the 16-bit iret
 * from the kernel.  It adds a boatload of sections and virtual
 * memory with no value for a coredump.  Nuke these.
 */
#define ESP_STACK_FIXUPS_START  0xffffff0000000000
#define ESP_STACK_FIXUPS_END    0xffffff7fffffffff

static int
handle_pte(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pteaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pte[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_4K;
	uint64_t end = end_addr >> PAGESHIFT_4K;

        vaddr |= KERNBASE;
        if (vaddr >= ESP_STACK_FIXUPS_START && vaddr <= ESP_STACK_FIXUPS_END)
                return 0;

	begin_addr &= PAGEMASK_4K;
	end_addr &= PAGEMASK_4K;
	rv = elfc_read_pmem(pelf, pteaddr, pte, sizeof(pte));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpte = le64toh(pte[i]);

		if (!(lpte & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_4K);

		/* 4K page */
		rv = handle_page(pelf, 
				 lpte & PHYSADDRMASK_4K,
				 newvaddr,
				 PAGESIZE_4K, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pde(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdeaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pde[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_2M;
	uint64_t end = end_addr >> PAGESHIFT_2M;

	begin_addr &= PAGEMASK_2M;
	end_addr &= PAGEMASK_2M;
	rv = elfc_read_pmem(pelf, pdeaddr, pde, sizeof(pde));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory entry at"
			" %llx: %s\n", (unsigned long long) pdeaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpde = le64toh(pde[i]);

		if (!(lpde & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_2M);
		if (lpde & (1 << 7)) {
			/* 2mb page */
			rv = handle_page(pelf, 
					 lpde & PHYSADDRMASK_2M,
					 newvaddr | KERNBASE,
					 PAGESIZE_2M, userdata);
		} else {
			rv = handle_pte(pelf, newvaddr,
					lpde & PHYSADDRMASK_4K,
					begin_addr, end_addr,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pdp(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdpaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pdp[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_1G;
	uint64_t end = end_addr >> PAGESHIFT_1G;

	begin_addr &= PAGEMASK_1G;
	end_addr &= PAGEMASK_1G;
	rv = elfc_read_pmem(pelf, pdpaddr, pdp, sizeof(pdp));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory pointer at"
			" %llx: %s\n", (unsigned long long) pdpaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpdp = le64toh(pdp[i]);

		if (!(lpdp & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_1G);
		if (lpdp & (1 << 7)) {
			/* 1gb page */
			rv = handle_page(pelf, 
					 lpdp & PHYSADDRMASK_1G,
					 newvaddr | KERNBASE,
					 PAGESIZE_1G, userdata);
		} else {
			rv = handle_pde(pelf, newvaddr,
					lpdp & PHYSADDRMASK_4K,
					begin_addr, end_addr,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
x86_64_task_ptregs(struct kdt_data *d, GElf_Addr task, void *regs)
{
	uint64_t reg = task + d->task_thread;
	struct x86_64_pt_regs *pt_regs = regs;
	int rv;

	if (!d->thread_sp_found) {
		pr_err("x86-specific thread SP offset not found, ptregs cannot "
		       "be extracted.\n");
		return -1;
	}

	rv = fetch_vaddr64(d, reg + d->thread_sp, &pt_regs->rsp, "thread.sp");
	if (rv) {
		pr_err("Unable to fetch SP from task struct\n");
		return rv;
	}

	if (os_major_release < 4 ||
	    (os_major_release == 4 && os_minor_release < 9)) {
		if (!d->x86___thread_sleep_point_found ||
		    !d->x86_context_switch_frame_size_found) {
			pr_err("x86-specific thread symbols not found, ptregs "
			       "cannot be extracted.\n");
			return -1;
		}

		if (d->x86_context_switch_frame_size == 1) {
			pr_err("You must set SIZE(context_switch_frame) in "
			       "your extracted symbols.  See the man page "
			       "for details.\n");
			return -1;
		}

		pt_regs->rbp = pt_regs->rsp + d->x86_context_switch_frame_size;
		pt_regs->rip = d->x86___thread_sleep_point;
		if (d->x86___thread_sleep_caller_found &&
		    d->x86___thread_sleep_caller) {
			uint64_t bp = pt_regs->rbp, val;
			unsigned int count = 100;

			for (count = 100; count > 0; count--, bp += 8) {
				rv = fetch_vaddr64(d, bp, &val, "thread.bp");
				if (rv) {
					pr_err("Unable to fetch BP data stack, stack backtrace may be wrong.\n");
					break;
				}
				if (val == d->x86___thread_sleep_caller) {
					pt_regs->rbp = bp - 8;
					break;
				}
			}
		}
	} else {
		/* Context switch was redone in 4.9. */
		/* Pushed BP register (frame pointer) is at this address. */
		GElf_Addr fr = pt_regs->rsp + (5 * 8);

		/* We back out of __switch_to_asm to it's parent. */
		rv = fetch_vaddr64(d, fr, &pt_regs->rbp, "thread.bp");
		if (rv) {
			pr_err("Unable to fetch BP from stack\n");
			return rv;
		}

		rv = fetch_vaddr64(d, fr + 8, &pt_regs->rip, "thread.ip");
		if (rv) {
			pr_err("Unable to fetch ip from stack\n");
			return rv;
		}

		/* 6 pushes in __switch_to_asm, plus the call. */
		pt_regs->rsp += (7 * 8);
	}

	/* We should only need the EIP, EBP and ESP. */

	return 0;
}

static int
x86_64_arch_setup(struct elfc *pelf, struct kdt_data *d, void **arch_data)
{
	struct x86_64_data *md;

	md = malloc(sizeof(*md));
	if (!md) {
		fprintf(stderr, "Out of memory allocating x86_64 arch data\n");
		return -1;
	}
	memset(md, 0, sizeof(*md));

	d->section_size_bits = 27;
	d->max_physmem_bits = 46; /* Good for 2.6.31 and later */

	d->pt_regs_size = sizeof(struct x86_64_pt_regs);
	d->fetch_ptregs = x86_64_task_ptregs;

	*arch_data = md;

	return 0;
}

static void
x86_64_arch_cleanup(void *arch_data)
{
	free(arch_data);
}

static int
x86_64_walk(struct elfc *pelf, GElf_Addr pgd,
	    GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pml[512];
	uint64_t i;
	int rv;
	uint64_t start = (begin_addr & 0x0000ffffffffffffULL) >> PAGESHIFT_L1;
	uint64_t end = (end_addr & 0x0000ffffffffffffULL) >> PAGESHIFT_L1;

	begin_addr &= PAGEMASK_L1;
	end_addr &= PAGEMASK_L1;
	rv = elfc_read_pmem(pelf, pgd, pml, sizeof(pml));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx: %s\n", (unsigned long long) pgd,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		uint64_t lpml = le64toh(pml[i]);
		if (!(lpml & 0x1))
			continue;

		rv = handle_pdp(pelf, i << PAGESHIFT_L1,
				lpml & PHYSADDRMASK_4K,
				begin_addr, end_addr,
				handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

struct archinfo x86_64_arch = {
	.name = "x86_64",
	.elfmachine = EM_X86_64,
	.default_elfclass = ELFCLASS64,
	.setup_arch_pelf = x86_64_arch_setup,
	.cleanup_arch_data = x86_64_arch_cleanup,
	.walk_page_table = x86_64_walk,
};
