/*
 *  yazc - Yet Another Zip Cracker
 *  Copyright (C) 2015  Marc Ferland
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
            yazc_err("unexpected getopt_long() value '%c'.\n", c);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        yazc_err("missing filename.\n");
        return EXIT_FAILURE;
    }

    filename = argv[optind];

    if (zc_new(&ctx)) {
        yazc_err("zc_new() failed!\n");
        return EXIT_FAILURE;
    }

    if (zc_file_new_from_filename(ctx, filename, &file)) {
        yazc_err("zc_file_new_from_filename() failed!\n");
        err = EXIT_FAILURE;
        goto err1;
    }

    if (zc_file_open(file)) {
        yazc_err("zc_file_open() failed!\n");
        err = EXIT_FAILURE;
        goto err2;
    }

    if (zc_info_new_from_file(file, &info)) {
        yazc_err("zc_info_new_from_file() failed!\n");
        err = EXIT_FAILURE;
        goto err3;
    }

    size_t fn_max_len = 0;
    zc_info_reset(info);
    while (zc_info_next(info)) {
        size_t tmp1 = strlen(zc_info_get_filename(info));
        if (tmp1 > fn_max_len)
            fn_max_len = tmp1;
    }

    printf("%5s %*s %11s %11s %11s %11s %24s\n",
           "Idx",
           (int)(MAX(fn_max_len, 8)),
           "Filename",
           "Encoded Hdr",
           "Data Begin",
           "Data End",
           "Data Size",
           "Encoded Hdr Content");

    while (zc_info_next(info)) {
        const uint8_t *ehdr = zc_info_get_enc_header(info);
        printf("%5d %*s %11li %11li %11li %11u %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
               zc_info_get_idx(info),
               (int)(MAX(fn_max_len, 8)),
               zc_info_get_filename(info),
               zc_info_get_enc_header_offset(info),
               zc_info_get_data_offset_begin(info),
               zc_info_get_data_offset_end(info),
               zc_info_get_data_size(info),
               ehdr[0], ehdr[1], ehdr[2], ehdr[3], ehdr[4], ehdr[5],
               ehdr[6], ehdr[7], ehdr[8], ehdr[9], ehdr[10], ehdr[11]);
    }

    zc_info_free(info);
err3:
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
