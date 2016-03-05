/*
 *  yazc - Yet Another Zip Cracker
 *  Copyright (C) 2013  Marc Ferland
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

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "yazc.h"
#include "libzc.h"

#define VDATA_CAPACITY 5
#define PW_LEN_DEFAULT 8

#define PWSET_LOWER 1
#define PWSET_UPPER (1 << 1)
#define PWSET_NUMB  (1 << 2)
#define PWSET_SPEC  (1 << 3)

static struct zc_validation_data vdata[VDATA_CAPACITY];
static size_t vdata_size;
static const char *filename;
static struct zc_crk_pwcfg pwcfg;
static size_t thread_count;

struct charset {
    const char *set;
    int len;
};

static const struct charset lowercase_set = {
    .set = "abcdefghijklmnopqrstuvwxyz",
    .len = 26,
};

static const struct charset uppercase_set = {
    .set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    .len = 26
};

static const struct charset number_set = {
    .set = "0123456789",
    .len = 10
};

static const struct charset special_set = {
    .set = "!:$%&/()=?{[]}+-*~#@|;",
    .len = 22
};

static const char short_opts[] = "c:i:l:aAnst:h";
static const struct option long_opts[] = {
    {"charset", required_argument, 0, 'c'},
    {"initial", required_argument, 0, 'i'},
    {"length", required_argument, 0, 'l'},
    {"alpha", no_argument, 0, 'a'},
    {"alpha-caps", no_argument, 0, 'A'},
    {"numeric", no_argument, 0, 'n'},
    {"special", no_argument, 0, 's'},
    {"threads", required_argument, 0, 't'},
    {"help", no_argument, 0, 'h'},
    {NULL, 0, 0, 0}
};

static void print_help(const char *name)
{
    fprintf(stderr,
            "Usage:\n"
            "\t%s [options] filename\n"
            "\n"
            "The '%s' subcommand tests every password combination until the\n"
            "right one is found.\n"
            "\n"
            "Options:\n"
            "\t-c, --charset=CHARSET   use character set CHARSET\n"
            "\t-i, --initial=STRING    initial password\n"
            "\t-l, --length=NUM        maximum password length\n"
            "\t-a, --alpha             use characters [a-z]\n"
            "\t-A, --alpha-caps        use characters [A-Z]\n"
            "\t-n, --numeric           use characters [0-9]\n"
            "\t-s, --special           use special characters\n"
            "\t-t, --threads=NUM       spawn NUM threads\n"
            "\t-h, --help              show this help\n",
            name, name);
}

static char *make_charset(int flags, char* buf, size_t buflen)
{
    size_t len = 0;

    if (flags & PWSET_LOWER)
        len += lowercase_set.len;
    if (flags & PWSET_UPPER)
        len += uppercase_set.len;
    if (flags & PWSET_NUMB)
        len += number_set.len;
    if (flags & PWSET_SPEC)
        len += special_set.len;

    if (len > buflen)
       return NULL;
    memset(buf, 0, buflen);

    if (flags & PWSET_LOWER)
        strncat(buf, lowercase_set.set, lowercase_set.len);
    if (flags & PWSET_UPPER)
        strncat(buf, uppercase_set.set, uppercase_set.len);
    if (flags & PWSET_NUMB)
        strncat(buf, number_set.set, number_set.len);
    if (flags & PWSET_SPEC)
        strncat(buf, special_set.set, special_set.len);
    return buf;
}

static int launch_crack(void)
{
    struct zc_ctx *ctx;
    struct zc_crk_bforce *crk;
    char pw[ZC_PW_MAXLEN + 1];

    if (zc_new(&ctx)) {
        yazc_err("zc_new() failed!\n");
        return EXIT_FAILURE;
    }

    vdata_size = fill_validation_data(ctx, filename, vdata, VDATA_CAPACITY);
    if (vdata_size == 0)
        goto err1;

    if (zc_crk_bforce_new(ctx, &crk)) {
        yazc_err("zc_crk_bforce_new() failed!\n");
        goto err1;
    }

    zc_crk_bforce_set_vdata(crk, vdata, vdata_size);
    if (zc_crk_bforce_set_pwcfg(crk, &pwcfg)) {
        yazc_err("zc_crk_bforce_set_pwcfg failed!\n");
        goto err2;
    }

    zc_crk_bforce_set_filename(crk, filename);

    printf("Worker threads: %lu\n", thread_count);
    printf("Maximum length: %lu\n", pwcfg.stoplen);
    printf("Character set: %s\n", zc_crk_bforce_sanitized_charset(crk));
    printf("Filename: %s\n", filename);

    int err = zc_crk_bforce_start(crk, thread_count, pw, sizeof(pw));
    if (err > 0)
        printf("Password not found\n");
    else if (err == 0)
        printf("Password is: %s\n", pw);
    else
        yazc_err("zc_crk_bforce_start failed!\n");

err2:
    zc_crk_bforce_unref(crk);

err1:
    zc_unref(ctx);
    return err;
}

static int do_bruteforce(int argc, char *argv[])
{
    const char *arg_set = NULL;
    const char *arg_initial = NULL;
    const char *arg_threads = NULL;
    const char *arg_stoplen = NULL;
    int arg_charset_flag = 0;

    for (;;) {
        int c;
        int idx;
        c = getopt_long(argc, argv, short_opts, long_opts, &idx);
        if (c == -1)
            break;
        switch (c) {
        case 'c':
            arg_set = optarg;
            break;
        case 'i':
            arg_initial = optarg;
            break;
        case 'l':
            arg_stoplen = optarg;
            break;
        case 'a':
            arg_charset_flag |= PWSET_LOWER;
            break;
        case 'A':
            arg_charset_flag |= PWSET_UPPER;
            break;
        case 'n':
            arg_charset_flag |= PWSET_NUMB;
            break;
        case 's':
            arg_charset_flag |= PWSET_SPEC;
            break;
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
        yazc_err("missing filename.\n");
        return EXIT_FAILURE;
    }

    filename = argv[optind];

    /* password stop length */
    if (arg_stoplen) {
        pwcfg.stoplen = atoi(arg_stoplen);
        if (pwcfg.stoplen < ZC_PW_MINLEN || pwcfg.stoplen > ZC_PW_MAXLEN) {
            yazc_err("maximum password length must be between %d and %d.\n", ZC_PW_MINLEN, ZC_PW_MAXLEN);
            return EXIT_FAILURE;
        }
    } else
        pwcfg.stoplen = PW_LEN_DEFAULT;

    /* number of concurrent threads */
    if (arg_threads) {
        thread_count = atoi(arg_threads);
        if (thread_count < 1) {
            yazc_err("number of threads can't be less than one.\n");
            return EXIT_FAILURE;
        }
    } else
        thread_count = 1;

    /* character set */
    if (!arg_set) {
        if (!arg_charset_flag) {
            yazc_err("no character set provided or specified.\n");
            return EXIT_FAILURE;
        }
        char *tmp = make_charset(arg_charset_flag, pwcfg.set, ZC_CHARSET_MAXLEN);
        if (!tmp) {
            yazc_err("generating character set failed.\n");
            return EXIT_FAILURE;
        }
        strncpy(pwcfg.set, tmp, ZC_CHARSET_MAXLEN);
    } else
        strncpy(pwcfg.set, arg_set, ZC_CHARSET_MAXLEN);

    /* character set length */
    pwcfg.setlen = strnlen(pwcfg.set, ZC_CHARSET_MAXLEN);

    /* initial password */
    if (arg_initial)
        strncpy(pwcfg.initial, arg_initial, ZC_PW_MAXLEN);
    else
        memset(pwcfg.initial, 0, ZC_PW_MAXLEN);

    int err = launch_crack();

    return err;
}

const struct yazc_cmd yazc_cmd_bruteforce = {
    .name = "bruteforce",
    .cmd = do_bruteforce,
    .help = "bruteforce password cracker",
};
