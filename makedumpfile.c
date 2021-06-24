/*
 * makedumpfile.c
 *
 * Handling for reading makedumpfile vmdump files
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
 * A lot of this was lifted from the crash utility's makedumpfile code.
 */

#include "kdump-elftool.h"

#include <stdio.h>
#include <string.h>

struct mdf_addr_info {
	uint64_t addr;
	uint64_t size;
	off_t offset;
};

#define BTREE_NODE_SIZE 10
#define btree_val_t struct mdf_addr_info
#define btree_t mdf_btree_t
#define BTREE_EXPORT_NAME(s) mdf_btree_ ## s
#define BTREE_NAMES_LOCAL static
#define btree_cmp_key mdfmem_cmp_key

int
mdfmem_cmp_key(struct mdf_addr_info val1, struct mdf_addr_info val2)
{
	if (val1.addr < val2.addr)
		return -1;
	else if (val1.addr > val2.addr)
		return 1;
	else
		return 0;
}

/* We only need next, add and search. */
#define BTREE_NEEDS BTREE_NEEDS_NEXT

#include "btree.h"

#undef BTREE_NODE_SIZE
#undef btree_val_t
#undef btree_t
#undef BTREE_EXPORT_NAME
#undef BTREE_NAMES_LOCAL
#undef btree_cmp_key

#define MAKEDUMPFILE_SIG_SIZE		16
#define MAKEDUMPFILE_SIG		"makedumpfile\0\0\0\0"
#define MAKEDUMPFILE_TYPE		1
#define MAKEDUMPFILE_VERSION		1
#define MAKEDUMPFILE_HEADER_SIZE	4096
#define MAKEDUMPFILE_END_FLAG		-1 /* In offset. */

struct makedumpfile_header {
	char    signature[MAKEDUMPFILE_SIG_SIZE]; /* = "makedumpfile\0\0\0\0" */
	int64_t type;
	int64_t version;
};

struct makedumpfile_data_header {
	int64_t offset;
	int64_t buf_size;
};

struct makedumpfile_info {
	struct absio io;
	struct absio *sio;
	mdf_btree_t mdfmem;
};

static int
mdf_read(struct absio *io, off_t addr, size_t size, void *ibuf)
{
	struct makedumpfile_info *mi;
	struct mdf_addr_info mai_s = { .addr = addr }, mai, tmai;
	unsigned char *buf = ibuf;
	size_t csize;
	off_t lpos;
	int rv;

	mi = container_of(io, struct makedumpfile_info, io);
	rv = mdf_btree_search(&mi->mdfmem, mai_s, &mai, BTREE_CLOSEST_PREV);
	if (rv || (mai.addr + mai.size <= addr)) {
		fprintf(stderr, "Unable to find makedumpfile address %llx\n",
			(unsigned long long) addr);
		return -1;
	}
	for (;;) {
		lpos = addr - mai.addr;
		csize = mai.size - lpos;
		if (csize > size)
			csize = size;
		rv = absio_read(mi->sio, mai.offset + lpos, csize, buf);
		if (rv) {
			fprintf(stderr,
				"Unable to read makedumpfile address %llx\n",
				(unsigned long long) addr);
			return -1;
		}
		size -= csize;
		if (!size)
			break;
		lpos = 0;
		buf += csize;
		rv = mdf_btree_next(&mi->mdfmem, mai, &tmai);
		if (rv || mai.addr + mai.size != tmai.addr) {
			fprintf(stderr,
				"Can't find next makedumpfile entry at %llx\n",
				(unsigned long long) mai.addr + mai.size);
			return -1;
		}
	}

	return 0;
}

static void
mdf_free(struct absio *io)
{
	struct makedumpfile_info *mi;

	mi = container_of(io, struct makedumpfile_info, io);
	mi->sio->free(mi->sio);
	mi = container_of(io, struct makedumpfile_info, io);
	mdf_btree_free(&mi->mdfmem);
	free(mi);
}

struct absio *
read_makedumpfile(struct absio *subio)
{
	int rv;
	struct makedumpfile_info *mi;
	struct makedumpfile_header hdr;
	off_t pos;

	mi = malloc(sizeof(*mi));
	if (!mi) {
		fprintf(stderr, "Unable to allocate makedumpfile mem info\n");
		return NULL;
	}
	memset(mi, 0, sizeof(*mi));
	if (mdf_btree_init(&mi->mdfmem)) {
		free(mi);
		fprintf(stderr, "Unable to init makedumpfile btree\n");
		return NULL;
	}

	mi->sio = subio;

	rv = absio_read(mi->sio, 0, sizeof(hdr), &hdr);
	if (rv) {
		fprintf(stderr, "Unable to read makedumpfile header\n");
		goto out_err;
	}

	if (memcmp(hdr.signature, MAKEDUMPFILE_SIG,
		   MAKEDUMPFILE_SIG_SIZE) != 0 ||
			hdr.type == 0 || hdr.version == 0) {
		fprintf(stderr, "File is not a makedumpfile dump\n");
		goto out_err;
	}

	if (be64toh(hdr.type) != MAKEDUMPFILE_TYPE) {
		fprintf(stderr, "File has unknown makedumpfile type: %llx\n",
			(unsigned long long) be64toh(hdr.type));
		goto out_err;
	}

	if (be64toh(hdr.version) != MAKEDUMPFILE_VERSION) {
		fprintf(stderr, "File has unknown version: %llx\n",
			(unsigned long long) be64toh(hdr.type));
		goto out_err;
	}

	pos = MAKEDUMPFILE_HEADER_SIZE;

	for (;;) {
		struct makedumpfile_data_header dhdr;
		struct mdf_addr_info mai;

		rv = absio_read(mi->sio, pos, sizeof(dhdr), &dhdr);
		if (rv) {
			fprintf(stderr,
				"Unable to read makedumpfile data header\n");
			goto out_err;
		}
		dhdr.offset = be64toh(dhdr.offset);
		dhdr.buf_size = be64toh(dhdr.buf_size);

		pos += sizeof(dhdr);
		if (dhdr.offset == MAKEDUMPFILE_END_FLAG)
			break;

		mai.addr = dhdr.offset;
		mai.size = dhdr.buf_size;
		mai.offset = pos;
		rv = mdf_btree_add(&mi->mdfmem, mai);
		if (rv) {
		    fprintf(stderr, "Error adding makedumpfile data: %d\n", rv);
		    goto out_err;
		}

		pos += dhdr.buf_size;
	}

	mi->io.read = mdf_read;
	mi->io.free = mdf_free;

	return &mi->io;
	
out_err:
	mdf_btree_free(&mi->mdfmem);
	free(mi);
	return NULL;
}
