/*
 *  yazc - ZIP password recovery application
 *  Copyright (C) 2012-2026 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "bruteforce.h"
#include "log.h"
#include "vulkan.h"
#include "yazc.h"

enum { OPT_MIN_LENGTH = 256, OPT_LIST_DEVICES };

struct vulkan_opts {
	const char *filename;
	const char *charset;
	char generated_charset[ZC_CHARSET_MAXLEN + 1];
	size_t min_length;
	size_t max_length;
	uint32_t device_index;
	bool stats;
};

static const char short_opts[] = "c:l:d:aAnsSh";
static const struct option long_opts[] = {
	{ "charset", required_argument, NULL, 'c' },
	{ "length", required_argument, NULL, 'l' },
	{ "min-length", required_argument, NULL, OPT_MIN_LENGTH },
	{ "device", required_argument, NULL, 'd' },
	{ "list-devices", no_argument, NULL, OPT_LIST_DEVICES },
	{ "alpha", no_argument, NULL, 'a' },
	{ "alpha-caps", no_argument, NULL, 'A' },
	{ "numeric", no_argument, NULL, 'n' },
	{ "special", no_argument, NULL, 's' },
	{ "stats", no_argument, NULL, 'S' },
	{ "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

static void print_help(const char *name)
{
	fprintf(stderr,
		"Usage:\n"
		"\t%s [options] filename\n"
		"\t%s --list-devices\n"
		"\n"
		"The '%s' subcommand tests an inclusive password-length range "
		"using Vulkan compute.\n"
		"\n"
		"Options:\n"
		"\t-c, --charset=CHARSET   use character set CHARSET\n"
		"\t-a, --alpha             use characters [a-z]\n"
		"\t-A, --alpha-caps        use characters [A-Z]\n"
		"\t-n, --numeric           use characters [0-9]\n"
		"\t-s, --special           use special characters\n"
		"\t-l, --length=N          maximum password length (default: %d)\n"
		"\t    --min-length=N      minimum password length (default: 1)\n"
		"\t-d, --device=N          use compute device N (default: 0)\n"
		"\t    --list-devices      list compute-capable Vulkan devices\n"
		"\t-S, --stats             print statistics\n"
		"\t-h, --help              show this help\n",
		name, name, name, ZC_PW_DEFAULT_MAXLEN);
}

static int parse_size(const char *value, size_t min, size_t max, size_t *out)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !*value || *end || parsed < min || parsed > max)
		return -1;
	*out = parsed;
	return 0;
}

static int parse_device(const char *value, uint32_t *out)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !*value || *end || parsed > UINT32_MAX)
		return -1;
	*out = parsed;
	return 0;
}

static int launch_crack(const struct vulkan_opts *opts)
{
	struct zc_vulkan_config config = {
		.charset = opts->charset,
		.min_length = opts->min_length,
		.max_length = opts->max_length,
		.device_index = opts->device_index,
	};
	struct zc_vulkan *ctx;
	char password[ZC_PW_MAXLEN + 1];
	struct timeval begin;
	struct timeval end;
	int result;

	if (zc_vulkan_new(&ctx)) {
		cli_err("Vulkan support is unavailable.\n");
		return EXIT_FAILURE;
	}
	if (zc_vulkan_init(ctx, opts->filename, &config)) {
		cli_err("failed to initialize the Vulkan brute-force attack.\n");
		zc_vulkan_destroy(ctx);
		return EXIT_FAILURE;
	}

	if (opts->stats) {
		printf("Vulkan device: %s\n", zc_vulkan_device_name(ctx));
		printf("Minimum length: %zu\n", opts->min_length);
		printf("Maximum length: %zu\n", opts->max_length);
		printf("Character set: %s\n", zc_vulkan_charset(ctx));
		printf("Filename: %s\n", opts->filename);
	}

	gettimeofday(&begin, NULL);
	result = zc_vulkan_start(ctx, password, sizeof(password));
	gettimeofday(&end, NULL);
	if (opts->stats) {
		double gpu_seconds;
		uint64_t passwords_tested = zc_vulkan_passwords_tested(ctx);

		print_runtime_stats(&begin, &end);
		print_password_rate(&begin, &end, passwords_tested);
		if (!zc_vulkan_gpu_runtime(ctx, &gpu_seconds)) {
			printf("GPU compute runtime: %.6f secs.\n", gpu_seconds);
			printf("GPU compute rate: %.3f passwords/second\n",
			       gpu_seconds > 0.0 ?
			       passwords_tested / gpu_seconds : 0.0);
		}
	}

	if (result > 0)
		printf("Password not found\n");
	else if (result == 0)
		printf("Password is: %s\n", password);
	else
		cli_err("Vulkan brute-force attack failed.\n");

	zc_vulkan_destroy(ctx);
	return result < 0 ? EXIT_FAILURE : result;
}

static int do_vulkan(int argc, char *argv[])
{
	struct vulkan_opts opts = {
		.min_length = ZC_PW_MINLEN,
		.max_length = ZC_PW_DEFAULT_MAXLEN,
	};
	bool list_devices = false;
	unsigned int charset_flags = 0;

	for (;;) {
		int option = getopt_long(argc, argv, short_opts, long_opts, NULL);

		if (option == -1)
			break;
		switch (option) {
		case 'c':
			opts.charset = optarg;
			break;
		case 'l':
			if (parse_size(optarg, ZC_PW_MINLEN, ZC_PW_MAXLEN,
				       &opts.max_length)) {
				cli_err("maximum password length must be between %d and %d.\n",
					ZC_PW_MINLEN, ZC_PW_MAXLEN);
				return EXIT_FAILURE;
			}
			break;
		case 'a':
			charset_flags |= YAZC_CHARSET_LOWER;
			break;
		case 'A':
			charset_flags |= YAZC_CHARSET_UPPER;
			break;
		case 'n':
			charset_flags |= YAZC_CHARSET_NUMERIC;
			break;
		case 's':
			charset_flags |= YAZC_CHARSET_SPECIAL;
			break;
		case OPT_MIN_LENGTH:
			if (parse_size(optarg, ZC_PW_MINLEN, ZC_PW_MAXLEN,
				       &opts.min_length)) {
				cli_err("minimum password length must be between %d and %d.\n",
					ZC_PW_MINLEN, ZC_PW_MAXLEN);
				return EXIT_FAILURE;
			}
			break;
		case 'd':
			if (parse_device(optarg, &opts.device_index)) {
				cli_err("device must be a non-negative integer.\n");
				return EXIT_FAILURE;
			}
			break;
		case OPT_LIST_DEVICES:
			list_devices = true;
			break;
		case 'S':
			opts.stats = true;
			break;
		case 'h':
			print_help(basename(argv[0]));
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (list_devices) {
		int result = zc_vulkan_list_devices(stdout);

		if (result > 0)
			puts("No compute-capable Vulkan devices found.");
		else if (result < 0)
			cli_err("failed to enumerate Vulkan devices.\n");
		return result < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}
	if (!opts.charset) {
		if (!charset_flags) {
			cli_err("no character set provided or specified.\n");
			return EXIT_FAILURE;
		}
		if (!yazc_make_charset(charset_flags, opts.generated_charset,
				       sizeof(opts.generated_charset))) {
			cli_err("generating character set failed.\n");
			return EXIT_FAILURE;
		}
		opts.charset = opts.generated_charset;
	}
	if (opts.min_length > opts.max_length) {
		cli_err("minimum length must not exceed maximum length.\n");
		return EXIT_FAILURE;
	}
	if (optind >= argc) {
		cli_err("missing filename.\n");
		return EXIT_FAILURE;
	}
	if (optind + 1 != argc) {
		cli_err("unexpected argument '%s'.\n", argv[optind + 1]);
		return EXIT_FAILURE;
	}
	opts.filename = argv[optind];
	return launch_crack(&opts);
}

const struct yazc_cmd yazc_cmd_vulkan = {
	.name = "vulkan",
	.cmd = do_vulkan,
	.help = "Vulkan brute-force password cracker",
};
