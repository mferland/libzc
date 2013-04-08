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

#include "yazc.h"
#include "libzc.h"

static const char short_opts[] = "c:anst:";
static const struct option long_opts[] = {
   {"charset", required_argument, 0, 'c'},
   {"alpha", no_argument, 0, 'a'},
   {"numeric", no_argument, 0, 'n'},
   {"special", no_argument, 0, 's'},
   {"threads", required_argument, 0, 't'},
   {NULL, 0, 0, 0}
};

static void print_help(const char *cmdname)
{
   fprintf(stderr,
           "Usage:\n"
           "\t%s [options] filename\n"
           "Options:\n"
           "\t-c, --charset=CHARSET   Use character set CHARSET\n"
           "\t-a, --alpha             Use characters [A-Za-z]\n"
           "\t-n, --numeric           Use characters [0-9]\n"
           "\t-s, --special           Use special characters TODO\n"
           "\t-t, --threads=NUM       Spawn NUM threads\n",
           cmdname);
}

static int do_bruteforce(int argc, char *argv[])
{
   struct zc_ctx *ctx;
   struct zc_file *file;

   /* for (;;) */
   /* { */
      
   /* } */
   print_help(basename(argv[0]));
   return EXIT_SUCCESS;
}

const struct yazc_cmd yazc_cmd_compat_bruteforce = {
	.name = "bruteforce",
	.cmd = do_bruteforce,
	.help = "bruteforce password cracker",
};
