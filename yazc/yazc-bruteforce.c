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

struct arguments {
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
static pthread_barrier_t barrier;

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

static int compare_char(const void *a, const void *b)
{
    char tmp = *(char *)a - *(char *)b;
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
    for (i = 0; i < len; ++i) {
        if (str[i] != str[j]) {
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
    if (!str)
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
    while (pw[i] != '\0') {
        if (!index(set, pw[i]))
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
    if (!str)
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
    pthread_barrier_wait(&barrier);
    pthread_cleanup_push(worker_cleanup_handler, t);

    struct cleanup_node *node = (struct cleanup_node *)t;
    char pw[PW_LEN_MAX + 1];
    int err;

    do {
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
        err = zc_crk_bforce_start(node->crk, pw, sizeof(pw));
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        if (err)
            break;

        if (zc_file_test_password(args.filename, pw)) {
            printf("Password is: %s\n", pw);
            node->found = true;
            break;
        }

        err = zc_crk_bforce_skip(node->crk, pw, sizeof(pw));
    } while (err == 0);

    pthread_cleanup_pop(1);
    return NULL;
}

static int init_worker(struct cleanup_node *node)
{
    struct zc_crk_bforce *crk;

    if (zc_crk_bforce_new(args.ctx, &crk))
        return -1;
    zc_crk_bforce_set_vdata(crk, args.vdata, args.vdata_size);
    zc_crk_bforce_set_pwgen_cfg(crk, args.charset, args.maxlength,
                                node->thread_num, args.initial, args.workers);
    node->crk = crk;

    return 0;
}

static int start_worker_threads(void)
{
    size_t i;
    int err;

    err = pthread_barrier_init(&barrier, NULL, args.workers);
    if (err)
        fatal("pthread_barrier_init() failed: %s\n", strerror(err));

    for (i = 0; i < args.workers; ++i) {
        cleanup_nodes[i].thread_num = i + 1;
        cleanup_nodes[i].active = true;
        cleanup_nodes[i].found = false;
        err = init_worker(&cleanup_nodes[i]);
        if (err)
            fatal("failed to initialise worker\n");
        err = pthread_create(&cleanup_nodes[i].thread_id, NULL, worker, &cleanup_nodes[i]);
        if (err)
            fatal("pthread_create() failed: %s\n", strerror(err));
    }
    return 0;
}

static void wait_worker_threads(void)
{
    cleanup_queue_wait(cleanup_queue, cleanup_nodes, args.workers);
    pthread_barrier_destroy(&barrier);
}

static int launch_crack(void)
{
    int err = EXIT_SUCCESS;

    if (zc_new(&args.ctx)) {
        yazc_err("zc_new() failed!\n");
        return EXIT_FAILURE;
    }

    args.vdata_size = fill_validation_data(args.ctx, args.filename,
                                           args.vdata, VDATA_ALLOC);
    if (args.vdata_size == 0)
        goto err1;

    if (cleanup_queue_new(&cleanup_queue)) {
        err = EXIT_FAILURE;
        goto err2;
    }

    cleanup_nodes = calloc(args.workers, sizeof(struct cleanup_node));
    if (!cleanup_nodes)
        goto err3;

    if (start_worker_threads())
        err = EXIT_FAILURE;
    else
        wait_worker_threads();

err3:
    free(cleanup_nodes);
    cleanup_nodes = NULL;

err2:
    cleanup_queue_destroy(cleanup_queue);

err1:
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

    memset(&args, 0, sizeof(struct cleanup_node));

    for (;;) {
        int c;
        int idx;
        c = getopt_long(argc, argv, short_opts, long_opts, &idx);
        if (c == -1)
            break;
        switch (c) {
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
            yazc_err("unexpected getopt_long() value '%c'.\n", c);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        yazc_err("missing filename.\n");
        return EXIT_FAILURE;
    }

    // TODO: support multiple zip
    args.filename = argv[optind];

    if (maxlength) {
        args.maxlength = atoi(maxlength);
        if (args.maxlength < PW_LEN_MIN || args.maxlength > PW_LEN_MAX) {
            yazc_err("maximum password length must be between %d and %d.\n", PW_LEN_MIN, PW_LEN_MAX);
            return EXIT_FAILURE;
        }
    } else
        args.maxlength = PW_LEN_DEFAULT;

    if (threads) {
        args.workers = atoi(threads);
        if (args.workers < 1) {
            yazc_err("number of threads can't be less than one.\n");
            return EXIT_FAILURE;
        }
    } else
        args.workers = 1;

    if (charset) {
        args.charset = sanitize_charset(charset);
        if (!args.charset) {
            yazc_err("couldn't sanitize character set.\n");
            return EXIT_FAILURE;
        }
    } else {
        if (!alpha && !alphacaps && !numeric && !special) {
            yazc_err("no character set provided or specified.\n");
            return EXIT_FAILURE;
        }
        args.charset = make_charset(alpha, alphacaps, numeric, special);
        if (!args.charset) {
            yazc_err("make_charset() failed.\n");
            return EXIT_FAILURE;
        }
    }

    if (initial) {
        if (!pw_in_charset(initial, args.charset) || !pw_len_valid(initial, args.maxlength)) {
            yazc_err("invalid initial password.\n");
            if (!charset)
                free(args.charset);
            return EXIT_FAILURE;
        }
        args.initial = initial;
    } else {
        args.initial = make_initial_pw(args.charset);
        if (!args.initial) {
            if (!charset)
                free(args.charset);
            return EXIT_FAILURE;
        }
    }

    printf("Worker threads: %ld\n", args.workers);
    printf("Maximum length: %ld\n", args.maxlength);
    printf("Character set: %s\n", args.charset);
    printf("Filename: %s\n", args.filename);
    printf("Initial password: %s\n", args.initial);

    int err = launch_crack();

    if (!charset)
        free(args.charset);
    if (!initial)
        free(args.initial);

    return err;
}

const struct yazc_cmd yazc_cmd_bruteforce = {
    .name = "bruteforce",
    .cmd = do_bruteforce,
    .help = "bruteforce password cracker",
};
