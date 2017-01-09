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

#include <stdio.h>
#include <getopt.h>
#include <libgen.h>

#include "yazc.h"
#include "libzc.h"

#define VDATA_ALLOC 5
#define PW_BUF_LEN 64

static const char short_opts[] = "d:h";
static const struct option long_opts[] = {
    {"dictionary", required_argument, 0, 'd'},
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
            "\t-d, --dictionary=FILE   read passwords from FILE\n"
            "\t-h, --help              show this help\n",
            cmdname);
}

static int launch_crack(const char *dict_filename, const char *zip_filename)
{
    struct zc_pwdict *pwdict;
    struct zc_validation_data vdata[VDATA_ALLOC];
    size_t vdata_size;
    char pw[PW_BUF_LEN];
    int err;

    vdata_size = fill_validation_data(ctx, zip_filename,
                                      vdata, VDATA_ALLOC);
    if (vdata_size == 0)
        return EXIT_FAILURE;

    err = zc_pwdict_new_from_filename(ctx, dict_filename, &pwdict);
    if (err != 0)
        return EXIT_FAILURE;

    err = zc_pwdict_open(pwdict);
    if (err != 0) {
        zc_pwdict_unref(pwdict);
        return EXIT_FAILURE;
    }

    do {
        err = zc_pwdict_read_one_pw(pwdict, pw, PW_BUF_LEN);
        if (err == 0 && zc_crk_test_one_pw(pw, vdata, vdata_size)) {
            if (zc_file_test_password_ext(zip_filename, pw)) {
                printf("Password is: %s\n", pw);
                break;
            }
        }
    } while (err == 0);

    zc_pwdict_close(pwdict);
    zc_pwdict_unref(pwdict);

    return 0;
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
            yazc_err("unexpected getopt_long() value '%c'.\n", c);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        yazc_err("missing filename.\n");
        return EXIT_FAILURE;
    }

    zip_filename = argv[optind];

    printf("Dictionary file: %s\n", !dict_filename ? "stdin" : dict_filename);
    printf("Filename: %s\n", zip_filename);

    if (zc_new(&ctx)) {
        yazc_err("zc_new() failed!\n");
        return EXIT_FAILURE;
    }

    err = launch_crack(dict_filename, zip_filename);

    zc_unref(ctx);

    return err;
}

const struct yazc_cmd yazc_cmd_dictionary = {
    .name = "dictionary",
    .cmd = do_dictionary,
    .help = "dictionary password cracker",
};
