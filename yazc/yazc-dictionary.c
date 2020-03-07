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

#include "yazc.h"
#include "libzc.h"

static const char short_opts[] = "d:h";
static const struct option long_opts[] = {
	{"dictionary", required_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{NULL, 0, 0, 0}
};

static void print_help(const char *cmdname)
{
	fprintf(stderr,
		"Usage:\n"
		"\t%s [options] filename\n"
		"Options:\n"
		"\t-d, --dictionary=FILE   read passwords from FILE\n"
		"\t-h, --help              show this help\n",
		cmdname);
}

static int launch_crack(const char *dict_filename, const char *zip_filename)
{
	struct zc_ctx *ctx;
	struct zc_crk_dict *crk;
	char pw[ZC_PW_MAXLEN + 1];
	int err = -1;

	if (zc_new(&ctx)) {
		err("zc_new() failed!\n");
		return -1;
	}

	if (zc_crk_dict_new(ctx, &crk)) {
		err("zc_crk_dict_new() failed!\n");
		goto err1;
	}

	if (zc_crk_dict_init(crk, zip_filename)) {
		err("zc_crk_dict_init() failed!\n");
		goto err2;
	}

	err = zc_crk_dict_start(crk, dict_filename, pw, sizeof(pw));
	if (err > 0)
		printf("Password not found\n");
	else if (err == 0)
		printf("Password is: %s\n", pw);
	else
		err("zc_crk_dict_start failed!\n");

err2:
	zc_crk_dict_unref(crk);

err1:
	zc_unref(ctx);

	return err;
}

static int do_dictionary(int argc, char *argv[])
{
	const char *dict_filename = NULL;
	const char *zip_filename = NULL;
	int err;

	for (;;) {
		int c;
		int idx;
		c = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			dict_filename = optarg;
			break;
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

	zip_filename = argv[optind];

	printf("Dictionary file: %s\n", !dict_filename ? "stdin" : dict_filename);
	printf("Filename: %s\n", zip_filename);

	err = launch_crack(dict_filename, zip_filename);

	return err;
}

const struct yazc_cmd yazc_cmd_dictionary = {
	.name = "dictionary",
	.cmd = do_dictionary,
	.help = "dictionary password cracker",
};
