/*
 *  yazc - Yet Another Zip Cracker
 *  Copyright (C) 2012-2018 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include "yazc.h"
#include "libzc.h"

static int do_opencl(int argc, char *argv[])
{
	struct zc_ctx *ctx;
	struct zc_crk_ocl *ocl;

	if (zc_new(&ctx)) {
		yazc_err("zc_new() failed!\n");
		return -1;
	}

	if (zc_crk_opencl_new(ctx, &ocl)) {
		yazc_err("zc_crk_opencl_new() failed!\n");
		goto err1;
	}

	if (zc_crk_opencl_start(ocl, NULL, 0)) {
		yazc_err("zc_crk_opencl_start() failed!\n");
		goto err2;
	}

err2:
	zc_crk_opencl_unref(ocl);
err1:
	zc_unref(ctx);

	return 0;
}

const struct yazc_cmd yazc_cmd_opencl = {
	.name = "opencl",
	.cmd = do_opencl,
	.help = "opencl password cracker",
};
