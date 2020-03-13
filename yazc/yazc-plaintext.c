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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>

#include "yazc.h"
#include "libzc.h"

static const char short_opts[] = "t:oSh";
static const struct option long_opts[] = {
	{"threads", required_argument, 0, 't'},
	{"offset", no_argument, 0, 'o'},
	{"stats", no_argument, 0, 'S'},
	{"help", no_argument, 0, 'h'},
	{NULL, 0, 0, 0}
};

static struct zc_ctx *ctx;
struct filed {
	const char *name;           /* file name */
	int fd;                     /* file descriptor */
	off_t txt_begin;            /* begin offset of the plain or cipher text */
	off_t txt_end;              /* end offset of the plain or cipher text */
	off_t file_begin;           /* offset of the first byte for the
                                       file we are using in the encrypted
                                       archive */
	void *map;
};

static struct filed cipher = {NULL, 0, 0, 0, -1, NULL};
static struct filed plain = {NULL, 0, 0, 0, -1, NULL};
static long thread_count;
static bool stats = false;

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage:\n"
		"\t%s [options] PLAIN ENTRY CIPHER ENTRY\n"
		"\t%s [options] -o PLAIN OFFSETS CIPHER OFFSETS BEGIN\n"
		"\n"
		"The plaintext subcommand uses a known vulnerability in the pkzip\n"
		"stream cipher to find the internal representation of the encryption\n"
		"key. To use this attack type you need at least 13 known plaintext\n"
		"bytes from any file in the archive.\n"
		"\n"
		"Example 1:\n"
		"\t %s -o plain.zip 100 650 cipher.zip 112 662 64\n"
		"\n"
		"Use plaintext bytes 100 to 650 and map them to ciphertext bytes\n"
		"112 to 662. Use these bytes to reduce the number of keys and perform\n"
		"the attack. Once the intermediate key is found, decrypt the rest of\n"
		"the cipher (begins at offset 64) to get the internal representation.\n"
		"\n"
		"Example 2:\n"
		"\t %s plain.zip file1.bin cipher.zip file2.bin\n"
		"\n"
		"Use plaintext bytes from the file1.bin entry in plain.zip and map them\n"
		"to file2.bin from cipher.zip.\n"
		"Options:\n"
		"\t-t, --threads=NUM       spawn NUM threads\n"
		"\t-o, --offset            use offsets instead of entry names\n"
		"\t-S, --stats             print statistics\n"
		"\t-h, --help              show this help\n",
		name, name, name, name);
}

static int parse_offset(const char *tok, off_t *offset)
{
	char *endptr;
	long int val = strtol(tok, &endptr, 0);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
	    (errno != 0 && val == 0))
		return -1;
	if (endptr == tok)
		return -1;
	if (val < 0)
		return -1;
	*offset = val;
	return 0;
}

enum text_src {
	SRC_PLAIN = 0,
	SRC_CIPHER,
	SRC_NUM
};

static int parse_entry_opts(char *argv[])
{
	struct zc_ctx *ctx;
	struct zc_file *f;
	char *filename, *entry;
	int err = 0, matches = 0;

	if (zc_new(&ctx))
		return -1;

	for (int src = SRC_PLAIN; src < SRC_NUM; ++src) {
		filename = argv[optind++];
		entry = argv[optind++];

		dbg("%s: %s %s\n",
		    src == SRC_PLAIN ? "plaintext" : "ciphertext",
		    filename,
		    entry);

		err = zc_file_new_from_filename(ctx, filename, &f);
		if (err)
			goto err1;

		err = zc_file_open(f);
		if (err) {
			zc_file_unref(f);
			goto err1;
		}

		struct zc_info *info = zc_file_info_next(f, NULL);
		while (info) {
			if (strcmp(zc_file_info_name(info), entry) != 0)
				/* filenames do not match */
				goto next;

			if ((src == SRC_PLAIN && zc_file_info_crypt_header_offset(info) != -1) ||
			    (src == SRC_CIPHER && zc_file_info_crypt_header_offset(info) == -1))
				/* plaintext is encrypted or ciphertext is not encrypted ? */
				goto next;

			/* found match */
			struct filed *fd = src == SRC_PLAIN ? &plain : &cipher;
			fd->txt_begin = zc_file_info_offset_begin(info);
			fd->txt_end = zc_file_info_offset_end(info);
			fd->file_begin = zc_file_info_crypt_header_offset(info);
			fd->name = filename;
			matches++;
			dbg("found match: %s %lld %lld %lld\n",
			    entry,
			    (long long)fd->txt_begin,
			    (long long)fd->txt_end,
			    (long long)fd->file_begin);
			break;
		next:
			dbg("skipping %s\n", zc_file_info_name(info));
			info = zc_file_info_next(f, info);
			continue;
		}
		zc_file_close(f);
		zc_file_unref(f);
	}
err1:
	zc_unref(ctx);
	if (err)
		return err;
	return matches == 2 ? 0 : -1;
}

static int parse_offset_opts(char *argv[])
{
	plain.name = argv[optind++];
	if (parse_offset(argv[optind++], &plain.txt_begin))
	    return -1;
	if (parse_offset(argv[optind++], &plain.txt_end))
	    return -1;

	cipher.name = argv[optind++];
	if (parse_offset(argv[optind++], &cipher.txt_begin))
	    return -1;
	if (parse_offset(argv[optind++], &cipher.txt_end))
	    return -1;
	if (parse_offset(argv[optind], &cipher.file_begin))
	    return -1;

	dbg("plaintext: %s %lld %lld\n",
	    plain.name,
	    (long long)plain.txt_begin,
	    (long long)plain.txt_end);
	dbg("ciphertext: %s %lld %lld %lld\n",
	    cipher.name,
	    (long long)cipher.txt_begin,
	    (long long)cipher.txt_end,
	    (long long)cipher.file_begin);

	return 0;
}

static bool validate_offsets()
{
	if (plain.txt_begin >= plain.txt_end ||
	    cipher.txt_begin >= cipher.txt_end)
		return false;
	if (plain.txt_end - plain.txt_begin < 13 ||
	    cipher.txt_end - cipher.txt_begin < 13)
		return false;
	if (plain.txt_end - plain.txt_begin != cipher.txt_end - cipher.txt_begin)
		return false;
	if (cipher.file_begin > cipher.txt_begin)
		return false;
	if (cipher.txt_begin - cipher.file_begin < 12)
		return false;
	return true;
}

static off_t offset_in_file(const struct filed *file)
{
	return file->file_begin == -1 ? file->txt_begin : file->file_begin;
}

static size_t size_of_map(const struct filed *file)
{
	return file->txt_end - offset_in_file(file) + 1;
}

static int mmap_text_buf(struct filed *file)
{
	int fd;
	void *map;
	struct stat filestat;

	fd = open(file->name, O_RDONLY);
	if (fd < 0) {
		err("open() failed: %s.\n", strerror(errno));
		return -1;
	}

	if (fstat(fd, &filestat) < 0) {
		err("fstat() failed: %s.\n", strerror(errno));
		goto error;
	}

	if (filestat.st_size == 0) {
		err("file %s is empty.\n", file->name);
		goto error;
	}

	if (file->txt_end >= filestat.st_size) {
		err("end offset (%lld) goes past the end of the file.\n", (long long)file->txt_end);
		goto error;
	}

	map = mmap(NULL, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		err("mmap() failed: %s.\n", strerror(errno));
		goto error;
	}

	file->fd = fd;
	file->map = map;

	return 0;

error:
	if (close(fd))
		err("close() failed: %s\n", strerror(errno));
	return -1;
}

static int unmap_text_buf(struct filed *file)
{
	if (munmap(file->map, size_of_map(file)) < 0)
		err("munmap() failed: %s.\n", strerror(errno));
	if (close(file->fd))
		err("close() failed: %s.\n", strerror(errno));
	return 0;
}

static int do_plaintext(int argc, char *argv[])
{
	const char *arg_threads = NULL;
	bool arg_use_offsets = false;
	struct zc_crk_ptext *ptext;
	struct timeval begin, end;
	int err = 0;

	for (;;) {
		int c, idx;
		c = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (c == -1)
			break;
		switch (c) {
		case 'o':
			arg_use_offsets = true;
			break;
		case 't':
			arg_threads = optarg;
			break;
		case 'S':
			stats = true;
			break;
		case 'h':
			usage(basename(argv[0]));
			return EXIT_SUCCESS;
		default:
			err("unexpected getopt_long() value '%c'.\n", c);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc)
		goto missing;

	/* number of concurrent threads */
	if (arg_threads) {
		thread_count = atol(arg_threads);
		if (thread_count < 1) {
			err("number of threads can't be less than one.\n");
			return EXIT_FAILURE;
		}
	} else
		thread_count = -1;	/* auto */

	if (arg_use_offsets) {
		/* parse raw offsets */
		if (argc - optind < 7)
			goto missing;

		if (parse_offset_opts(argv)) {
			err("error parsing offsets.\n");
			return EXIT_FAILURE;
		}
	} else {
		/* get offsets from entry names */
		if (argc - optind < 4)
			goto missing;

		if (parse_entry_opts(argv)) {
			err("error parsing entries.\n");
			return EXIT_FAILURE;
		}
	}

	if (!validate_offsets()) {
		err("offsets validation failed.\n");
		return EXIT_FAILURE;
	}

	if (mmap_text_buf(&plain) < 0) {
		err("mapping plaintext data failed.\n");
		return EXIT_FAILURE;
	}

	if (mmap_text_buf(&cipher) < 0) {
		err("mapping ciphertext data failed.\n");
		goto error1;
	}

	zc_new(&ctx);
	if (!ctx) {
		err("zc_new() failed!\n");
		goto error2;
	}

	err = zc_crk_ptext_new(ctx, &ptext);
	if (err < 0) {
		err("zc_crk_ptext_new() failed!\n");
		goto error3;
	}

	err = zc_crk_ptext_set_text(ptext,
				    &((const uint8_t *)plain.map)[plain.txt_begin],
				    &((const uint8_t *)cipher.map)[cipher.txt_begin],
				    size_of_map(&plain));
	if (err < 0) {
		err("zc_crk_ptext_set_text() failed!\n");
		goto error4;
	}

	zc_crk_ptext_force_threads(ptext, thread_count);

	printf("Key2 reduction...");
	fflush(stdout);
	gettimeofday(&begin, NULL);
	err = zc_crk_ptext_key2_reduction(ptext);
	if (err < 0) {
		printf("\n");
		err("reducing key2 candidates failed.\n");
		goto error4;
	}
	printf(" done! %zu keys found.\n", zc_crk_ptext_key2_count(ptext));

	printf("Attack running...");
	fflush(stdout);
	struct zc_key out_key;
	err = zc_crk_ptext_attack(ptext, &out_key);
	if (err < 0) {
		printf("\n");
		err("attack failed! Wrong plaintext?\n");
		goto error4;
	}
	printf(" done!\n");

	printf("Intermediate key: 0x%x 0x%x 0x%x\n",
	       out_key.key0, out_key.key1, out_key.key2);

	struct zc_key int_rep;
	err = zc_crk_ptext_find_internal_rep(&out_key,
					     &((const uint8_t *)cipher.map)[cipher.file_begin],
					     cipher.txt_begin - cipher.file_begin,
					     &int_rep);
	if (err < 0) {
		err("finding internal representation failed.\n");
		goto error4;
	}

	printf("Internal key representation: 0x%x 0x%x 0x%x\n",
	       int_rep.key0, int_rep.key1, int_rep.key2);

	printf("Recovering original password...");
	fflush(stdout);
	char pw[14];
	err = zc_crk_ptext_find_password(ptext, &int_rep, pw, sizeof(pw));
	if (err < 0) {
		err(" failed!\n");
		err = EXIT_FAILURE;
		goto error4;
	}

	gettimeofday(&end, NULL);

	printf("\nOriginal password: ");
	for (int i = 0; i < err; ++i) {
		if (isprint(pw[i]))
			printf("%c ", pw[i]);
		else
			printf("0x%x ", pw[i]);
	}
	printf("\n");

	if (stats)
		printf("Runtime: %f secs.\n", (double)(end.tv_usec - begin.tv_usec) / 1000000 +
		       (double)(end.tv_sec - begin.tv_sec));

	err = EXIT_SUCCESS;

error4:
	zc_crk_ptext_unref(ptext);
error3:
	zc_unref(ctx);
error2:
	unmap_text_buf(&cipher);
error1:
	unmap_text_buf(&plain);
	return err;

missing:
	err("missing argument.\n");
	usage(basename(argv[0]));
	return EXIT_FAILURE;
}

const struct yazc_cmd yazc_cmd_plaintext = {
	.name = "plaintext",
	.cmd = do_plaintext,
	.help = "plaintext attack",
};
