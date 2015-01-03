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
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "yazc.h"
#include "libzc.h"

static const char short_opts[] = "h";
static const struct option long_opts[] =
{
   {"help", no_argument, 0, 'h'},
   {NULL, 0, 0, 0}
};

static struct zc_ctx *ctx;
static const char *file_ptext = NULL;
static const char *file_cipher = NULL;
static size_t plain_begin = 0;
static size_t plain_end = 0;
static size_t cipher_begin = 0;
static size_t cipher_end = 0;
static size_t cipher_remain = 0;

static void print_help(const char *cmdname)
{
   fprintf(stderr,
           "Usage:\n"
           "\t%s plain:begin:end cipher:begin:end:upto \n"
           "\n"
           "Example:\n"
           "cleartext.bin contains 250 cleartext bytes from offset 100 to\n"
           "350. These are mapped to archive.zip from 340 to 590. The encrypted\n"
           "stream in archive.zip is followed up to offset 300.\n"
           "   yazc plaintext cleartext.bin:100:350 archive.zip:340:590:300\n"
           "Options:\n"
           "\t-h, --help              show this help\n",
           cmdname);
}

static int parse_offset(const char *tok, size_t *offset)
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

static int parse_opt(char *opt, int count, const char **filename, size_t *off1, size_t *off2, size_t *off3)
{
   char *saveptr, *token;
   int err;

   token = strtok_r(opt, ":", &saveptr);
   if (token == NULL)
      return -1;
   *filename = token;

   for (int i = 0; i < count; ++i)
   {
      token = strtok_r(NULL, ":", &saveptr);
      if (token == NULL)
         return -1;
      switch (i)
      {
      case 0: err = parse_offset(token, off1); break;
      case 1: err = parse_offset(token, off2); break;
      case 2: err = parse_offset(token, off3); break;
      }
      if (err < 0)
         return -1;
   }

   /* TODO: remove */
   printf("filename: %s\n", *filename);
   printf("off1: %d\n", off1 != NULL ? *off1 : 0);
   printf("off2: %d\n", off2 != NULL ? *off2 : 0);
   printf("off3: %d\n", off3 != NULL ? *off3 : 0);

   return 0;
}

static int do_plaintext(int argc, char *argv[])
{
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

   if (optind + 1 >= argc)
   {
      fputs("Error: incorrect arguments\n", stderr);
      print_help(basename(argv[0]));
      return EXIT_FAILURE;
   }

   /* parse plaintext source */
   /* TODO: remove */
   printf("Plaintext: %s\n", argv[optind]);
   printf("Cipher: %s\n", argv[optind + 1]);

   err = parse_opt(argv[optind], 2, &file_ptext,
                   &plain_begin, &plain_end, NULL);
   if (err < 0)
   {
      fprintf(stderr, "Error parsing plaintext file offsets.\n");
      return EXIT_FAILURE;
   }

   err = parse_opt(argv[optind + 1], 3, &file_cipher,
                   &cipher_begin, &cipher_end, &cipher_remain);
   if (err < 0)
   {
      fprintf(stderr, "Error parsing cipher file offsets.\n");
      return EXIT_FAILURE;
   }

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
