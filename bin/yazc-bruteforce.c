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
#include <unistd.h>
#include <errno.h>

#include "yazc.h"
#include "libzc.h"
#include "cleanupqueue.h"

#define VDATA_ALLOC 5
#define PW_LEN_MIN 1
#define PW_LEN_MAX 16
#define PW_LEN_DEFAULT 8

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
   .set = "!:$%&/()=?{[]}+-*~#@|;",
   .len = 22
};

struct arguments
{
   struct zc_validation_data vdata[VDATA_ALLOC];
   char *charset;
   size_t vdata_size;
   const char *filename;
   char *initial;
   size_t maxlength;
   struct zc_ctx *ctx;
   size_t workers;
};

static struct arguments args;
static struct cleanup_node *cleanup_nodes = NULL;
static struct cleanup_queue *cleanup_queue = NULL;

static const char short_opts[] = "c:l:aAnst:h";
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

static void print_help(const char *cmdname)
{
   fprintf(stderr,
           "Usage:\n"
           "\t%s [options] filename\n"
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

static char *make_charset(bool alpha, bool alphacaps, bool num, bool special)
{
   char *str;
   size_t len = 0;
   
   if (alpha)
      len += lowercase_set.len;
   if (alphacaps)
      len += uppercase_set.len;
   if (num)
      len += number_set.len;
   if (special)
      len += special_set.len;

   str = calloc(1, len + 1);
   if (str == NULL)
      return NULL;

   if (alpha)
      strncat(str, lowercase_set.set, lowercase_set.len);
   if (alphacaps)
      strncat(str, uppercase_set.set, uppercase_set.len);
   if (num)
      strncat(str, number_set.set, number_set.len);
   if (special)
      strncat(str, special_set.set, special_set.len);
   return str;
}

static bool pw_in_charset(const char *pw, const char *set)
{
   int i = 0;
   while (pw[i] != '\0')
   {
      if (index(set, pw[i]) == NULL)
         return false;
      ++i;
   }
   return true;
}

static bool pw_len_valid(const char *pw, size_t max_len)
{
   return (strlen(pw) <= max_len);
}

static char *make_initial_pw(const char *set)
{
   char *str = calloc(1, 2);
   if (str == NULL)
      return NULL;
   str[0] = set[0];
   return str;
}

static void worker_cleanup_handler(void *t)
{
   struct cleanup_node *node = (struct cleanup_node *)t;
   zc_crk_bforce_unref(node->crk);
   cleanup_queue_put(cleanup_queue, node);
}

static void *worker(void *t)
{
   pthread_cleanup_push(worker_cleanup_handler, t);
   
   struct cleanup_node *node = (struct cleanup_node *)t;
   char pw[PW_LEN_MAX + 1];
   int err;

   do
   {
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
      err = zc_crk_bforce_start(node->crk, pw, sizeof(pw));
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
      
      if (err)
         break;

      if (zc_file_test_password(args.filename, pw))
      {
         printf("Password is: %s\n", pw);
         node->found = true;
         break;
      }
      
      err = zc_crk_bforce_skip(node->crk, pw, sizeof(pw));
   } while (err == 0);
   
   pthread_cleanup_pop(1);
   return NULL;
}

static int init_worker_pwgen(int thread_num, struct zc_pwgen **pwgen)
{
   struct zc_pwgen *tmp = NULL;
   const char *worker_pw = NULL;
   int err;
   
   err = zc_pwgen_new(args.ctx, &tmp);
   if (err)
      return err;
   
   err = zc_pwgen_init(tmp, args.charset, args.maxlength);
   if (err)
      goto error;
   
   zc_pwgen_reset(tmp, args.initial);

   if (thread_num > 1)
   {
      /* advance the pwgen to this thread's first pw */
      zc_pwgen_set_step(tmp, 1);
      for (int i = 0; i < thread_num - 1 ; ++i)
      {
         size_t count;
         worker_pw = zc_pwgen_generate(tmp, &count);
         if (worker_pw == NULL)
         {
            fputs("Error: Too many threads for password range\n", stderr);
            err = EINVAL;
            goto error;
         }
      }
      zc_pwgen_reset(tmp, worker_pw);
   }
   
   zc_pwgen_set_step(tmp, args.workers);
   *pwgen = tmp;
   return 0;

error:
   zc_pwgen_unref(tmp);
   *pwgen = NULL;
   return err;
}

static int init_worker(struct cleanup_node *node)
{
   struct zc_crk_bforce *crk;
   struct zc_pwgen *pwgen;
   int err;

   err = init_worker_pwgen(node->thread_num, &pwgen);
   if (err)
      return err;

   err = zc_crk_bforce_new(args.ctx, &crk);
   if (err)
   {
      zc_pwgen_unref(pwgen);
      return err;
   }
   zc_crk_bforce_set_vdata(crk, args.vdata, args.vdata_size);
   zc_crk_bforce_set_pwgen(crk, pwgen);
   zc_pwgen_unref(pwgen);

   node->crk = crk;

   return 0;
}

static int start_worker_threads(void)
{
   size_t i;
   int err;
   
   for (i = 0; i < args.workers; ++i)
   {
      cleanup_nodes[i].thread_num = i + 1;
      cleanup_nodes[i].active = true;
      cleanup_nodes[i].found = false;
      err = init_worker(&cleanup_nodes[i]);
      if (err)
         fatal("failed to initialise worker\n");
      err = pthread_create(&cleanup_nodes[i].thread_id, NULL, worker, &cleanup_nodes[i]);
      if (err != 0)
         fatal("pthread_create() failed\n");
   }
   return 0;
}

static int wait_worker_threads(void)
{
   sleep(2);                    /* if we cancel too early cleanup
                                 * handlers are not called
                                 * pthread/kernel/glibc BUG? */
   return cleanup_queue_wait(cleanup_queue, cleanup_nodes, args.workers);
}

static int launch_crack(void)
{
   int err;
   
   zc_new(&args.ctx);
   if (!args.ctx)
   {
      fputs("Error: zc_new() failed!\n", stderr);
      return EXIT_FAILURE;
   }

   args.vdata_size = fill_validation_data(args.ctx, args.filename,
                                          args.vdata, VDATA_ALLOC);
   if (args.vdata_size == 0)
   {
      err = -1;
      goto cleanup;
   }

   err = cleanup_queue_new(&cleanup_queue);
   if (err)
      goto cleanup;

   cleanup_nodes = calloc(args.workers, sizeof(struct cleanup_node));
   if (cleanup_nodes == NULL)
   {
      cleanup_queue_destroy(cleanup_queue);
      goto cleanup;
   }
   
   err = start_worker_threads();
   if (!err)
      err = wait_worker_threads();

   free(cleanup_nodes);
   cleanup_nodes = NULL;
   cleanup_queue_destroy(cleanup_queue);

cleanup:
   zc_unref(args.ctx);
   return err;
}

static int do_bruteforce(int argc, char *argv[])
{
   char *charset = NULL;
   char *initial = NULL;
   const char *threads = NULL;
   const char *maxlength = NULL;
   bool alpha = false;
   bool alphacaps = false;
   bool numeric = false;
   bool special = false;
   int err;

   memset(&args, 0, sizeof(struct cleanup_node));

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
      case 'i':
         initial = optarg;
         break;
      case 'l':
         maxlength = optarg;
         break;
      case 'a':
         alpha = true;
         break;
      case 'A':
         alphacaps = true;
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
      fputs("Error: missing filename\n", stderr);
      return EXIT_FAILURE;
   }

   // TODO: support multiple zip
   args.filename = argv[optind];

   if (maxlength != NULL)
   {
      args.maxlength = atoi(maxlength);
      if (args.maxlength < PW_LEN_MIN || args.maxlength > PW_LEN_MAX)
      {
         fprintf(stderr, "Error: maximum password length must be between %d and %d\n", PW_LEN_MIN, PW_LEN_MAX);
         return EXIT_FAILURE;
      }
   }
   else
      args.maxlength = PW_LEN_DEFAULT;

   if (threads != NULL)
   {
      args.workers = atoi(threads);
      if (args.workers < 1)
      {
         fputs("Error: number of threads can't be less than one\n", stderr);
         return EXIT_FAILURE;
      }
   }
   else
      args.workers = 1;

   if (charset != NULL)
   {
      args.charset = sanitize_charset(charset);
      if (args.charset == NULL)
      {
         fputs("Error: couldn't sanitize character set\n", stderr);
         return EXIT_FAILURE;
      }
   }
   else
   {
      if (!alpha && !alphacaps && !numeric && !special)
      {
         fputs("Error: no character set provided or specified\n", stderr);
         return EXIT_FAILURE;
      }
      args.charset = make_charset(alpha, alphacaps, numeric, special);
      if (args.charset == NULL)
      {
         fputs("Error: make_charset() failed\n", stderr);
         return EXIT_FAILURE;
      }
   }

   if (initial != NULL)
   {
      if (!pw_in_charset(initial, args.charset) || !pw_len_valid(initial, args.maxlength))
      {
         fputs("Error: invalid initial password\n", stderr);
         if (charset == NULL)
            free(args.charset);
         return EXIT_FAILURE;
      }
      args.initial = initial;
   }
   else
   {
      args.initial = make_initial_pw(args.charset);
      if (args.initial == NULL)
      {
         if (charset == NULL)
            free(args.charset);
         return EXIT_FAILURE;
      }
   }

   printf("Worker threads: %ld\n", args.workers);
   printf("Maximum length: %ld\n", args.maxlength);
   printf("Character set: %s\n", args.charset);
   printf("Filename: %s\n", args.filename);
   printf("Initial password: %s\n", args.initial);

   err = launch_crack();

   if (charset == NULL)
      free(args.charset);
   if (initial == NULL)
      free(args.initial);

   return err;
}

const struct yazc_cmd yazc_cmd_compat_bruteforce = {
	.name = "bruteforce",
	.cmd = do_bruteforce,
	.help = "bruteforce password cracker",
};
