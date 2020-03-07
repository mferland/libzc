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
#include <getopt.h>
#include <libgen.h>
#include <string.h>

#include "yazc.h"
#include "libzc.h"

#define MAX(a, b) (( a > b) ? a : b)

static const char short_opts[] = "h";
static const struct option long_opts[] = {
	{"help", no_argument, 0, 'h'},
	{NULL, 0, 0, 0}
};

struct zc_ctx *ctx;

static void print_help(const char *cmdname)
{
	fprintf(stderr,
		"Usage:\n"
		"\t%s [options] filename\n"
		"Options:\n"
		"\t-h, --help              show this help\n",
		cmdname);
}

static int do_info(int argc, char *argv[])
{
	const char *filename;
	struct zc_file *file;
	struct zc_info *info;
	int err = EXIT_SUCCESS, c, idx;

	c = getopt_long(argc, argv, short_opts, long_opts, &idx);
	if (c != -1) {
		switch (c) {
		case 'h':
			print_help(basename(argv[0]));
			return EXIT_SUCCESS;
		default:
			err("unexpected getopt_long() value '%c'.\n", c);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		err("missing filename.\n");
		return EXIT_FAILURE;
	}

	filename = argv[optind];

	if (zc_new(&ctx)) {
		err("zc_new() failed!\n");
		return EXIT_FAILURE;
	}

	if (zc_file_new_from_filename(ctx, filename, &file)) {
		err("zc_file_new_from_filename() failed!\n");
		err = EXIT_FAILURE;
		goto err1;
	}

	if (zc_file_open(file)) {
		err("zc_file_open() failed!\n");
		err = EXIT_FAILURE;
		goto err2;
	}

	size_t fn_max_len = 0,
		crypt_max_len = 0,
		offset_begin_max_len = 0,
		offset_end_max_len = 0,
		size_max_len = 0,
		csize_max_len = 0;
	info = zc_file_info_next(file, NULL);
	while (info) {
		char buf[256];
		/* filename */
		size_t tmp1 = strlen(zc_file_info_name(info));
		if (tmp1 > fn_max_len)
			fn_max_len = tmp1;
		/* encrypted header */
		snprintf(buf, sizeof(buf), "%li",
			 zc_file_info_crypt_header_offset(info));
		tmp1 = strlen(buf);
		if (tmp1 > crypt_max_len)
			crypt_max_len = tmp1;
		/* offset begin */
		snprintf(buf, sizeof(buf), "%li",
			 zc_file_info_offset_begin(info));
		tmp1 = strlen(buf);
		if (tmp1 > offset_begin_max_len)
			offset_begin_max_len = tmp1;
		/* offset end */
		snprintf(buf, sizeof(buf), "%li",
			 zc_file_info_offset_end(info));
		tmp1 = strlen(buf);
		if (tmp1 > offset_end_max_len)
			offset_end_max_len = tmp1;
		/* size */
		snprintf(buf, sizeof(buf), "%u",
			 zc_file_info_size(info));
		tmp1 = strlen(buf);
		if (tmp1 > size_max_len)
			size_max_len = tmp1;
		/* compressed size */
		snprintf(buf, sizeof(buf), "%u",
			 zc_file_info_compressed_size(info));
		tmp1 = strlen(buf);
		if (tmp1 > csize_max_len)
			csize_max_len = tmp1;

		info = zc_file_info_next(file, info);
	}

	printf("%-5s %*s %*s %*s %*s %-24s\n",
	       "INDEX",
	       (int)(-MAX(fn_max_len, 8)),
	       "NAME",
	       (int)(-(crypt_max_len +
		       offset_begin_max_len +
		       offset_end_max_len + 2)),
	       "OFFSETS",
	       (int)(-size_max_len),
	       "SIZE",
	       (int)(-csize_max_len),
	       "CSIZE",
	       "ENCRYPTED HEADER");

	info = zc_file_info_next(file, NULL);
	while (info) {
		const uint8_t *ehdr = zc_file_info_enc_header(info);
		printf("%5d %*s %*li %*li %*li %*u %*u %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		       zc_file_info_idx(info),
		       (int)(-MAX(fn_max_len, 8)),
		       zc_file_info_name(info),
		       (int)(-crypt_max_len),
		       zc_file_info_crypt_header_offset(info),
		       (int)(-offset_begin_max_len),
		       zc_file_info_offset_begin(info),
		       (int)(-offset_end_max_len),
		       zc_file_info_offset_end(info),
		       (int)(-MAX(size_max_len, 4)),
		       zc_file_info_size(info),
		       (int)(-MAX(csize_max_len, 5)),
		       zc_file_info_compressed_size(info),
		       ehdr[0], ehdr[1], ehdr[2], ehdr[3], ehdr[4], ehdr[5],
		       ehdr[6], ehdr[7], ehdr[8], ehdr[9], ehdr[10], ehdr[11]);
		info = zc_file_info_next(file, info);
	}

	zc_file_close(file);
err2:
	zc_file_unref(file);
err1:
	zc_unref(ctx);
	return err;
}

const struct yazc_cmd yazc_cmd_info = {
	.name = "info",
	.cmd = do_info,
	.help = "print zip file content info",
};
