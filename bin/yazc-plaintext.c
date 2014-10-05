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
#include <errno.h>

#include "yazc.h"
#include "libzc.h"
#include "crc32.h"

static const char short_opts[] = "h";
static const struct option long_opts[] = 
{
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

static int do_plaintext(int argc, char *argv[])
{
   const char *filename = NULL;
   int err = 0;

   for (;;)
   {
      int c;
      int idx;
      c = getopt_long(argc, argv, short_opts, long_opts, &idx);
      if (c == -1)
         break;
      switch (c)
      {
      case 'h':
         print_help(basename(argv[0]));
         return EXIT_SUCCESS;
      default:
         fprintf(stderr, "Error: unexpected getopt_long() value '%c'.\n", c);
         return EXIT_FAILURE;
      }
   }

   if (optind >= argc)
   {
      fputs("Error: missing filename\n", stderr);
      return EXIT_FAILURE;
   }

   filename = argv[optind];
   printf("Filename: %s\n", filename);
   
   zc_new(&ctx);
   if (ctx == NULL)
   {
      fputs("Error: zc_new() failed!\n", stderr);
      return EXIT_FAILURE;
   }

   zc_unref(ctx);

   return err;
}

const struct yazc_cmd yazc_cmd_compat_plaintext = {
	.name = "plaintext",
	.cmd = do_plaintext,
	.help = "plaintext attack",
};
