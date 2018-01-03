/*
 *  yazc - Yet Another Zip Cracker
 *  Copyright (C) 2012-2017 Marc Ferland
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

#include "yazc.h"
#include "libzc.h"

static const char short_opts[] = "t:h";
static const struct option long_opts[] = {
    {"threads", required_argument, 0, 't'},
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
static size_t thread_count;

static void print_help(const char *name)
{
    fprintf(stderr,
            "Usage:\n"
            "\t%s [options] PLAIN:OFF1:OFF2 CIPHER:OFF1:OFF2:BEGIN\n"
            "\n"
            "The plaintext subcommand uses a known vulnerability in the pkzip\n"
            "stream cipher to find the internal representation of the encryption\n"
            "key. To use this attack type you need at least 13 known plaintext\n"
            "bytes from any file in the archive.\n"
            "\n"
            "Example:\n"
            "\t %s plain.bin:100:650 archive.zip:112:662:64\n"
            "\n"
            "Use plaintext bytes 100 to 650 and map them to ciphertext bytes\n"
            "112 to 662. Use these bytes to reduce the number of keys and perform\n"
            "the attack. Once the intermediate key is found, decrypt the rest of\n"
            "the cipher (begins at offset 64) to get the internal representation.\n"
            "\n"
            "Options:\n"
            "\t-t, --threads=NUM       spawn NUM threads\n"
            "\t-h, --help              show this help\n",
            name, name);
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

static int parse_opt(char *opt, int count, const char **filename, off_t *off1, off_t *off2, off_t *off3)
{
    char *saveptr = NULL, *token;
    int err = -1;

    if (!opt)
        return -1;

    token = strtok_r(opt, ":", &saveptr);
    if (!token)
        return -1;
    *filename = token;

    for (int i = 0; i < count; ++i) {
        token = strtok_r(NULL, ":", &saveptr);
        if (!token)
            return -1;
        switch (i) {
        case 0:
            err = parse_offset(token, off1);
            break;
        case 1:
            err = parse_offset(token, off2);
            break;
        case 2:
            err = parse_offset(token, off3);
            break;
        }
        if (err)
            return -1;
    }

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
        yazc_err("open() failed: %s.\n", strerror(errno));
        return -1;
    }

    if (fstat(fd, &filestat) < 0) {
        yazc_err("fstat() failed: %s.\n", strerror(errno));
        goto error;
    }

    if (filestat.st_size == 0) {
        yazc_err("file %s is empty.\n", file->name);
        goto error;
    }

    map = mmap(NULL, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        yazc_err("mmap() failed: %s.\n", strerror(errno));
        goto error;
    }

    file->fd = fd;
    file->map = map;

    return 0;

error:
    if (close(fd))
        yazc_err("close() failed: %s\n", strerror(errno));
    return -1;
}

static int unmap_text_buf(struct filed *file)
{
    if (munmap(file->map, size_of_map(file)) < 0)
        yazc_err("munmap() failed: %s.\n", strerror(errno));
    if (close(file->fd))
        yazc_err("close() failed: %s.\n", strerror(errno));
    return 0;
}

static int do_plaintext(int argc, char *argv[])
{
    const char *arg_threads = NULL;
    struct zc_crk_ptext *ptext;
    int err = 0;

    for (;;) {
        int c, idx;
        c = getopt_long(argc, argv, short_opts, long_opts, &idx);
        if (c == -1)
            break;
        switch (c) {
        case 't':
            arg_threads = optarg;
            break;
        case 'h':
            print_help(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            yazc_err("unexpected getopt_long() value '%c'.\n", c);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        yazc_err("missing arguments.\n");
        print_help(basename(argv[0]));
        return EXIT_FAILURE;
    }

    /* number of concurrent threads */
    if (arg_threads) {
        thread_count = atoi(arg_threads);
        if (thread_count < 1) {
            yazc_err("number of threads can't be less than one.\n");
            return EXIT_FAILURE;
        }
    } else
        thread_count = 1;

    if (parse_opt(argv[optind], 2, &plain.name,
                  &plain.txt_begin, &plain.txt_end, NULL) < 0) {
        yazc_err("parsing plaintext file offsets failed.\n");
        return EXIT_FAILURE;
    }

    if (parse_opt(argv[optind + 1], 3, &cipher.name,
                  &cipher.txt_begin, &cipher.txt_end, &cipher.file_begin) < 0) {
        yazc_err("parsing cipher file offsets failed.\n");
        return EXIT_FAILURE;
    }

    if (!validate_offsets()) {
        yazc_err("offsets validation failed.\n");
        return EXIT_FAILURE;
    }

    if (mmap_text_buf(&plain) < 0) {
        yazc_err("mapping plaintext data failed.\n");
        return EXIT_FAILURE;
    }

    if (mmap_text_buf(&cipher) < 0) {
        yazc_err("mapping ciphertext data failed.\n");
        goto error1;
    }

    zc_new(&ctx);
    if (!ctx) {
        yazc_err("zc_new() failed!\n");
        goto error2;
    }

    err = zc_crk_ptext_new(ctx, &ptext);
    if (err < 0) {
        yazc_err("zc_crk_ptext_new() failed!\n");
        goto error3;
    }

    err = zc_crk_ptext_set_text(ptext,
                                &((const uint8_t *)plain.map)[plain.txt_begin],
                                &((const uint8_t *)cipher.map)[cipher.txt_begin],
                                size_of_map(&plain));
    if (err < 0) {
        yazc_err("zc_crk_ptext_set_text() failed!\n");
        goto error4;
    }

    printf("Key2 reduction...");
    fflush(stdout);
    err = zc_crk_ptext_key2_reduction(ptext);
    if (err < 0) {
        printf("\n");
        yazc_err("reducing key2 candidates failed.\n");
        goto error4;
    }
    printf(" done! %zu keys found.\n", zc_crk_ptext_key2_count(ptext));

    printf("Attack running...");
    fflush(stdout);
    struct zc_key out_key;
    err = zc_crk_ptext_attack(ptext, &out_key, thread_count);
    if (err < 0) {
        printf("\n");
        yazc_err("attack failed! Wrong plaintext?\n");
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
        yazc_err("finding internal representation failed.\n");
        goto error4;
    }

    printf("Internal key representation: 0x%x 0x%x 0x%x\n",
           int_rep.key0, int_rep.key1, int_rep.key2);

    printf("Recovering original password...");
    fflush(stdout);
    char pw[14];
    err = zc_crk_ptext_find_password(ptext, &int_rep, pw, sizeof(pw));
    if (err < 0) {
        yazc_err(" failed!\n");
        err = EXIT_FAILURE;
        goto error4;
    }

    printf("\nOriginal password: ");
    for (int i = 0; i < err; ++i) {
        if (isprint(pw[i]))
            printf("%c ", pw[i]);
        else
            printf("0x%x ", pw[i]);
    }
    printf("\n");

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
}

const struct yazc_cmd yazc_cmd_plaintext = {
    .name = "plaintext",
    .cmd = do_plaintext,
    .help = "plaintext attack",
};
