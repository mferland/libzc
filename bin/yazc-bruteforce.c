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
#include <pthread.h>

#include "yazc.h"
#include "libzc.h"

#define VDATA_SIZE 5

struct charset
{
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
   .set = "!:$%&/()=?{[]}+-*~#",// TODO: add more!
   .len = 19
};

struct arguments
{
   struct zc_validation_data vdata[VDATA_SIZE];
   const char *charset;
   const char *filename;
   size_t maxlength;
   struct zc_ctx *ctx;
   size_t threads;
};

struct thread_info
{
   pthread_t thread_id;
   int thread_num;
   const struct arguments *args;
};

static const char short_opts[] = "c:m:anst:h";
static const struct option long_opts[] = {
   {"charset", required_argument, 0, 'c'},
   {"max-length", required_argument, 0, 'm'},
   {"alpha", no_argument, 0, 'a'},
   {"numeric", no_argument, 0, 'n'},
   {"special", no_argument, 0, 's'},
   {"threads", required_argument, 0, 't'},
   {"help", no_argument, 0, 'h'},
   {NULL, 0, 0, 0}
};

static void print_help(const char *cmdname)
{
   fprintf(stderr,
           "Usage:\n"
           "\t%s [options] filename\n"
           "Options:\n"
           "\t-c, --charset=CHARSET   use character set CHARSET\n"
           "\t-m, --max-length=NUM    maximum password length\n"
           "\t-a, --alpha             use characters [A-Za-z]\n"
           "\t-n, --numeric           use characters [0-9]\n"
           "\t-s, --special           use special characters TODO\n"
           "\t-t, --threads=NUM       spawn NUM threads\n"
           "\t-h, --help              show this help\n",
           cmdname);
}

static int compare_char(const void *a, const void *b)
{
   char tmp = *(char *)a - *(char*)b;
   if (tmp > 0)
      return 1;
   else if (tmp < 0)
      return -1;
   else
      return 0;
}

static char *unique(char *str)
{
   const size_t len = strlen(str);
   size_t i, j = 0;
   for (i = 0; i < len; ++i)
   {
      if (str[i] != str[j])
      {
         str[j + 1] = str[i];
         ++j;
      }
   }
   str[j + 1] = '\0';
   return str;
}

static char *sanitize_charset(char *charset)
{
   qsort(charset, strlen(charset), sizeof(char), compare_char);
   unique(charset);
   return charset;
}

static const char *make_charset(bool alpha, bool num, bool special)
{
   char *str;
   size_t len = 0;
   if (alpha)
      len += lowercase_set.len * 2;
   if (num)
      len += number_set.len;
   if (special)
      len += special_set.len;

   str = calloc(1, len + 1);
   if (str == NULL)
      return NULL;

   if (alpha)
   {
      strncat(str, lowercase_set.set, lowercase_set.len);
      strncat(str, uppercase_set.set, uppercase_set.len);
   }
   if (num)
      strncat(str, number_set.set, number_set.len);
   if (special)
      strncat(str, special_set.set, special_set.len);
   return str;
}

static void *worker(void *args)
{
   struct thread_info *tinfo = (struct thread_info *)args;
   printf("thread %d\n", tinfo->thread_num);
   return 0;
}

static int start_worker_threads(struct thread_info *tinfo, const struct arguments *args)
{
   size_t i;
   int err;
   for (i = 0; i < args->threads; ++i)
   {
      tinfo[i].thread_num = i + 1;
      tinfo[i].args = args;
      err = pthread_create(&tinfo[i].thread_id, NULL, worker, &tinfo[i]);
      if (err != 0)
      {
         fprintf(stderr, "Error: pthread_create() failed");
         return -1;
      }
   }
   return 0;
}

static int wait_worker_threads(struct thread_info *tinfo, struct arguments *args)
{
   // TODO: cleanup queue
   return 0;
}

static int read_validation_data(struct zc_ctx *ctx, struct arguments *args)
{
   struct zc_file *file = NULL;
   int err;

   zc_file_new_from_filename(ctx, args->filename, &file);
   if (!file)
   {
      fputs("Error: zc_file_new_from_filename() failed!\n", stderr);
      return -1;
   }

   err = zc_file_open(file);
   if (err)
   {
      fprintf(stderr, "Error: cannot open %s\n", args->filename);
      zc_file_unref(file);
      return -1;
   }

   err = zc_file_read_validation_data(file, &args->vdata[0], VDATA_SIZE);
   if (err < 1)
      fprintf(stderr, "Error: file is not encrypted\n");
   
   zc_file_close(file);
   zc_file_unref(file);
   return err < 1 ? -1 : 0;
}

static int launch_crack(struct arguments *args)
{
   struct zc_ctx *ctx = NULL;
   struct thread_info *tinfo = NULL;
   
   zc_new(&ctx);
   if (!ctx)
   {
      fputs("Error: zc_new() failed!\n", stderr);
      return EXIT_FAILURE;
   }

   if (read_validation_data(ctx, args) != 0)
      return EXIT_FAILURE;

   tinfo = calloc(1, sizeof(struct thread_info) * args->threads);
   start_worker_threads(tinfo, args);
   //wait_worker_threads();

   zc_unref(ctx);
   return EXIT_SUCCESS;
}

static int do_bruteforce(int argc, char *argv[])
{
   char *charset = NULL;
   const char *threads = NULL;
   const char *maxlength = NULL;
   bool alpha = false;
   bool numeric = false;
   bool special = false;
   struct arguments args;
   int err;

   for (;;)
   {
      int c;
      int idx;
      c = getopt_long(argc, argv, short_opts, long_opts, &idx);
      if (c == -1)
         break;
      switch (c)
      {
      case 'c':
         charset = optarg;
         break;
      case 'm':
         maxlength = optarg;
         break;
      case 'a':
         alpha = true;
         break;
      case 'n':
         numeric = true;
         break;
      case 's':
         special = true;
         break;
      case 't':
         threads = optarg;
         break;
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
      fprintf(stderr, "Error: missing filename\n");
      return EXIT_FAILURE;
   }

   // TODO: support multiple zip
   args.filename = argv[optind];

   if (maxlength != NULL)
   {
      args.maxlength = atoi(maxlength);
      if (args.maxlength < 1 || args.maxlength > 16)
      {
         fprintf(stderr, "Error: maximum password length must be between 1 and 16\n");
         return EXIT_FAILURE;
      }
   }
   else
      args.maxlength = 8;

   if (threads != NULL)
   {
      args.threads = atoi(threads);
      if (args.threads < 1)
      {
         fprintf(stderr, "Error: number of threads can't be less than one\n");
         return EXIT_FAILURE;
      }
   }
   else
      args.threads = 1;

   if (charset != NULL)
   {
      args.charset = sanitize_charset(charset);
      if (args.charset == NULL)
      {
         fprintf(stderr, "Error: couldn't sanitize character set\n");
         return EXIT_FAILURE;
      }
   }
   else
   {
      if (!alpha && !numeric && !special)
      {
         fprintf(stderr, "Error: no character set provided or specified\n");
         return EXIT_FAILURE;
      }
      args.charset = make_charset(alpha, numeric, special); // free()
   }

   printf("maxlen: %ld\n", args.maxlength);
   printf("threads: %ld\n", args.threads);
   printf("charset: %s\n", args.charset);
   printf("filename: %s\n", args.filename);

   err = launch_crack(&args);

   return err;
}

const struct yazc_cmd yazc_cmd_compat_bruteforce = {
	.name = "bruteforce",
	.cmd = do_bruteforce,
	.help = "bruteforce password cracker",
};
