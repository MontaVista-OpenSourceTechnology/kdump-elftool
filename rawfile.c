/*
 * rawfile.c
 *
 * Handling for reading raw files files
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

#include "kdump-elftool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

struct rawio {
    struct absio io;
    FILE *f;
};

static int
rawio_read(struct absio *io, off_t addr, size_t size, void *buf)
{
	int rv;
	struct rawio *rio;

	rio = container_of(io, struct rawio, io);

	rv = fseek(rio->f, addr, SEEK_SET);
	if (rv == -1) {
		fprintf(stderr, "Error seeking raw file to %llx\n",
			(unsigned long long) addr);
		return -1;
	}
	rv = fread(buf, 1, size, rio->f);
	if (rv != size) {
		fprintf(stderr, "Unable to raw read at address %llx\n",
			(unsigned long long) addr);
		return -1;
	}

	return 0;
}

static void
rawio_free(struct absio *io)
{
	struct rawio *rio;

	rio = container_of(io, struct rawio, io);
	fclose(rio->f);
	free(rio);
}

struct absio *
read_rawfile(char *file)
{
	struct rawio *rio;

	rio = malloc(sizeof(*rio));
	if (!rio) {
		fprintf(stderr, "Unable to allocate raw I/O info\n");
		return NULL;
	}
	memset(rio, 0, sizeof(*rio));

	rio->f = fopen(file, "r");
	if (!rio->f) {
		fprintf(stderr, "Unable to open %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}

	rio->io.read = rawio_read;
	rio->io.free = rawio_free;

	return &rio->io;
	
out_err:
	if (rio->f)
		fclose(rio->f);
	free(rio);
	return NULL;
}
