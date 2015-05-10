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
#include <libgen.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#include "yazc.h"
#include "config.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

static const char options_s[] = "+hV";
static const struct option options[] = {
    {"help", no_argument, NULL, 'h' },
    {"version", no_argument, NULL, 'V' },
    {NULL, 0, 0, 0}
};

static const struct yazc_cmd yazc_cmd_help;

static const struct yazc_cmd *yazc_cmds[] = {
    &yazc_cmd_help,
    &yazc_cmd_bruteforce,
    &yazc_cmd_dictionary,
    &yazc_cmd_plaintext,
    &yazc_cmd_info,
};

static int help(int UNUSED(argc), char *argv[])
{
    size_t i;

    printf("yazc - Crack password protected zip files\n"
           "Usage:\n"
           "\t%s command [command_options]\n\n"
           "Options:\n"
           "\t-V, --version     show version\n"
           "\t-h, --help        show this help\n\n"
           "Commands:\n", basename(argv[0]));

    for (i = 0; i < ARRAY_SIZE(yazc_cmds); ++i) {
        if (yazc_cmds[i]->help)
            printf("  %-12s %s\n", yazc_cmds[i]->name, yazc_cmds[i]->help);
    }

    return EXIT_SUCCESS;
}

static const struct yazc_cmd yazc_cmd_help = {
    .name = "help",
    .cmd = help,
    .help = "Show help message",
};

void yazc_log(const char *UNUSED(file), int UNUSED(line), const char *fn,
              const char *format, ...)
{
    va_list args;

    va_start(args, format);
    fprintf(stderr, "yazc: %s: ", fn);
    vfprintf(stderr, format, args);
    va_end(args);
}

void yazc_err(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, format, args);
    va_end(args);
}

int main(int argc, char *argv[])
{
    const char *cmd;
    bool found = false;
    size_t i;

    for (;;) {
        int c;

        c = getopt_long(argc, argv, options_s, options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            help(argc, argv);
            return EXIT_SUCCESS;
        case 'V':
            puts("yazc version " VERSION);
            return EXIT_SUCCESS;
        case '?':
            return EXIT_FAILURE;
        default:
            yazc_err("unexpected getopt_long() value '%c'.\n", c);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        yazc_err("missing command.\n");
        goto fail;
    }

    cmd = argv[optind];

    for (i = 0; i < ARRAY_SIZE(yazc_cmds); i++) {
        if (strcmp(yazc_cmds[i]->name, cmd) != 0)
            continue;
        found = true;
        break;
    }

    if (!found) {
        yazc_err("invalid command '%s'.\n", cmd);
        goto fail;
    }

    return yazc_cmds[i]->cmd(--argc, ++argv);

fail:
    help(argc, argv);
    return EXIT_FAILURE;
}
