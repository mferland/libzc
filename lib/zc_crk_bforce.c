/*
 *  zc - zip crack library
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

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "crc32.h"
#include "zip.h"
#include "list.h"
#include "libzc.h"
#include "libzc_private.h"

#define KEY0 0x12345678
#define KEY1 0x23456789
#define KEY2 0x34567890

/* bruteforce cracker */
struct zc_crk_bforce {
    struct zc_ctx *ctx;
    int refcount;

    /* validation data */
    const struct zc_validation_data *vdata;
    size_t vdata_size;

    char *filename;

    /* password generator config from user */
    struct zc_crk_pwcfg cfg;

    struct list_head workers_head;
    struct list_head cleanup_head;
    pthread_barrier_t barrier;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct pwgen {
    /* password generator config - per thread */
    struct zc_crk_pwcfg cfg;
    /* password generator state */
    char *pw;
    char char_ascii[ZC_PW_MAXLEN + 1];
    char char_indexes[ZC_PW_MAXLEN];
};

struct worker {
    struct list_head workers;
    struct list_head cleanup;
    pthread_t thread_id;
    bool found;
    struct pwgen gen;
    struct zc_crk_bforce *crk;
};

static void init_char_ascii(struct pwgen *gen)
{
    gen->pw = gen->char_ascii + gen->cfg.stoplen - gen->cfg.ilen;
    strncpy(gen->pw, gen->cfg.initial, gen->cfg.ilen);
}

static void init_char_indexes(struct pwgen *gen)
{
    const size_t first_valid_index = gen->cfg.stoplen - gen->cfg.ilen;
    size_t i, j;

    for (i = 0; i < first_valid_index; ++i)
        gen->char_indexes[i] = -1;

    for (i = first_valid_index, j = 0; j < gen->cfg.ilen; ++i, ++j)
        gen->char_indexes[i] = index(gen->cfg.set, gen->pw[j]) - gen->cfg.set;
}

static const char *pwgen_generate(struct pwgen *gen, size_t *count)
{
    int quotient = gen->cfg.step;
    const char *pw_orig = gen->pw;
    char *char_idx = &gen->char_indexes[gen->cfg.stoplen - 1];
    char *char_ascii = &gen->char_ascii[gen->cfg.stoplen - 1];
    int iteration = 0;

    while (1) {
        *char_idx += quotient;
        quotient = *char_idx / gen->cfg.setlen;
        *char_idx = *char_idx - quotient * gen->cfg.setlen;

        *char_ascii = gen->cfg.set[(unsigned char) * char_idx];

        if (quotient > 0 && char_ascii == gen->char_ascii) {
            gen->pw = NULL;
            *count = 0;
            return NULL;           /* overflow */
        }

        iteration++;
        if (quotient == 0)
            break;

        --char_idx;
        --char_ascii;

        if (char_ascii < gen->pw)
            gen->pw = char_ascii;
    }

    /* return 0 if the pw len changed, the pw is only one char or the
     * first char changed */
    if (gen->pw != pw_orig ||
        gen->pw == &gen->char_ascii[gen->cfg.stoplen - 1] ||
        iteration == (&gen->char_ascii[gen->cfg.stoplen - 1] - gen->pw + 1))
        *count = 0;
    else
        *count = char_ascii - gen->pw;

    return gen->pw;
}

static int pwgen_skip(struct pwgen *gen)
{
    size_t tmp;
    if (!pwgen_generate(gen, &tmp))
        return -1;
    return 0;
}

static inline void update_keys(char c, struct zc_key *ksrc, struct zc_key *kdst)
{
    kdst->key0 = crc32(ksrc->key0, c);
    kdst->key1 = (ksrc->key1 + (kdst->key0 & 0x000000ff)) * MULT + 1;
    kdst->key2 = crc32(ksrc->key2, kdst->key1 >> 24);
}

static inline void set_default_encryption_keys(struct zc_key *k)
{
    k->key0 = KEY0;
    k->key1 = KEY1;
    k->key2 = KEY2;
}

static inline void init_encryption_keys(const char *pw, struct zc_key *k)
{
    size_t i = 0;
    set_default_encryption_keys(k);
    while (pw[i] != '\0') {
        update_keys(pw[i], k, k);
        ++i;
    }
}

static inline size_t init_key_cache(const char *pw, struct zc_key *key_cache,
                                    size_t idem_char)
{
    /* do {} while() assuming password is never empty */
    do {
        update_keys(pw[idem_char], &key_cache[idem_char], &key_cache[idem_char + 1]);
        ++idem_char;
    } while (pw[idem_char] != '\0');
    return idem_char;
}

static inline void reset_encryption_keys(const struct zc_key *base, struct zc_key *k)
{
    *k = *base;
}

static inline uint8_t decrypt_byte(uint32_t k)
{
    uint16_t tmp =  k | 2;
    return ((tmp * (tmp ^ 1)) >> 8);
}

static inline uint8_t decrypt_header(const uint8_t *encrypted_header, struct zc_key *k)
{
    int i;
    uint8_t c;

    for (i = 0; i < ZIP_ENCRYPTION_HEADER_LENGTH - 1; ++i) {
        c = encrypted_header[i] ^ decrypt_byte(k->key2);
        update_keys(c, k, k);
    }

    /* Returns the last byte of the decrypted header */
    return encrypted_header[i] ^ decrypt_byte(k->key2);
}

ZC_EXPORT bool zc_crk_test_one_pw(const char *pw, const struct zc_validation_data *vdata, size_t nmemb)
{
    struct zc_key key;
    struct zc_key base_key;
    size_t i;

    init_encryption_keys(pw, &base_key);
    for (i = 0; i < nmemb; ++i) {
        reset_encryption_keys(&base_key, &key);
        if (decrypt_header(vdata[i].encryption_header, &key) == vdata[i].magic)
            continue;
        return false;
    }
    return true;
}

ZC_EXPORT int zc_crk_bforce_new(struct zc_ctx *ctx, struct zc_crk_bforce **crk)
{
    struct zc_crk_bforce *tmp;
    int err;

    tmp = calloc(1, sizeof(struct zc_crk_bforce));
    if (!tmp)
        return -1;

    err = pthread_mutex_init(&tmp->mutex, NULL);
    if (err) {
        err(ctx, "pthread_mutex_init() failed: %s\n", strerror(err));
        free(tmp);
        return -1;
    }

    err = pthread_cond_init(&tmp->cond, NULL);
    if (err) {
        err(ctx, "pthread_cond_init() failed: %s\n", strerror(err));
        pthread_mutex_destroy(&tmp->mutex);
        free(tmp);
        return -1;
    }

    tmp->ctx = ctx;
    tmp->refcount = 1;

    INIT_LIST_HEAD(&tmp->workers_head);
    INIT_LIST_HEAD(&tmp->cleanup_head);

    *crk = tmp;

    dbg(ctx, "cracker %p created\n", tmp);
    return 0;
}

ZC_EXPORT struct zc_crk_bforce *zc_crk_bforce_ref(struct zc_crk_bforce *crk)
{
    if (!crk)
        return NULL;
    crk->refcount++;
    return crk;
}

ZC_EXPORT struct zc_crk_bforce *zc_crk_bforce_unref(struct zc_crk_bforce *crk)
{
    if (!crk)
        return NULL;
    crk->refcount--;
    if (crk->refcount > 0)
        return crk;
    dbg(crk->ctx, "cracker %p released\n", crk);
    if (crk->filename)
        free(crk->filename);
    pthread_cond_destroy(&crk->cond);
    pthread_mutex_destroy(&crk->mutex);
    free(crk);
    return NULL;
}

ZC_EXPORT int zc_crk_bforce_set_vdata(struct zc_crk_bforce *crk, const struct zc_validation_data *vdata, size_t nmemb)
{
    if (!vdata || nmemb == 0)
        return -1;
    crk->vdata = vdata;
    crk->vdata_size = nmemb;
    return 0;
}

ZC_EXPORT void zc_crk_bforce_set_filename(struct zc_crk_bforce *crk, const char *filename)
{
    if (crk->filename)
        free(crk->filename);
    crk->filename = strdup(filename);
}

ZC_EXPORT const char *zc_crk_bforce_sanitized_charset(const struct zc_crk_bforce *crk)
{
    return crk->cfg.set;
}

static size_t unique(char *str, size_t len)
{
    if (len <= 1)
        return len;

    size_t j = 0;
    for (size_t i = 1; i < len; ++i) {
        if (str[i] != str[j])
            str[++j] = str[i];
    }

    return j + 1;
}

static int compare_char(const void *a, const void *b)
{
    return (*(char *)a - *(char *)b);
}

static size_t sanitize_set(char *set, size_t len)
{
    qsort(set, len, sizeof(char), compare_char);
    size_t newlen = unique(set, len);
    set[newlen] = '\0';
    return newlen;
}

static bool pw_in_set(const char *pw, const char *set, size_t len)
{
    size_t i = 0;
    while (pw[i]) {
        if (!memchr(set, pw[i], len))
            return false;
        ++i;
    }
    return true;
}

ZC_EXPORT int zc_crk_bforce_set_pwcfg(struct zc_crk_bforce *crk, const struct zc_crk_pwcfg *cfg)
{
    /* basic sanity checks */
    if (cfg->setlen == 0 ||
        cfg->setlen > ZC_CHARSET_MAXLEN  ||
        cfg->stoplen == 0 ||
        cfg->stoplen > ZC_PW_MAXLEN)
        return -1;

    /* local copy */
    memcpy(&crk->cfg, cfg, sizeof(struct zc_crk_pwcfg));

    /* sanitize character set */
    crk->cfg.setlen = sanitize_set(crk->cfg.set, crk->cfg.setlen);

    size_t ilen = strnlen(cfg->initial, ZC_PW_MAXLEN);
    if (!ilen) {
        /* no initial password set, use first character */
        crk->cfg.initial[0] = crk->cfg.set[0];
        crk->cfg.initial[1] = '\0';
        crk->cfg.ilen = 1;
    } else {
        if (ilen > cfg->stoplen)
            return -1;
        if (!pw_in_set(cfg->initial, cfg->set, cfg->setlen))
            return -1;
        crk->cfg.ilen = ilen;
    }

    return 0;
}

static int do_work(struct worker *w)
{
    struct zc_key key;
    struct zc_key key_cache[ZC_PW_MAXLEN];
    const struct zc_crk_bforce *crk = w->crk;
    size_t idem_char = 0;

    memset(key_cache, 0, sizeof(struct zc_key) * ZC_PW_MAXLEN);

    set_default_encryption_keys(key_cache);

    do {
        size_t lastidx = init_key_cache(w->gen.pw, key_cache, idem_char);
        size_t matches = 0;
        for (size_t i = 0; i < crk->vdata_size; ++i) {
            /* reset key to last key_cache entry */
            key = key_cache[lastidx];
            if (decrypt_header(crk->vdata[i].encryption_header, &key) == crk->vdata[i].magic) {
                ++matches;
                continue;
            }
            break;
        }

        /* all files match, potential valid password */
        if (matches == crk->vdata_size)
            return 0;

        pwgen_generate(&w->gen, &idem_char);
    } while (w->gen.pw);

    return -1;                  /* out of passwords */
}

static void worker_cleanup_handler(void *p)
{
    struct worker *w = (struct worker *)p;
    pthread_mutex_lock(&w->crk->mutex);
    list_del(&w->workers);
    list_add(&w->cleanup, &w->crk->cleanup_head);
    pthread_cond_signal(&w->crk->cond);
    pthread_mutex_unlock(&w->crk->mutex);
}

static void *worker(void *p)
{
    struct worker *w = (struct worker *)p;
    int err;

    pthread_cleanup_push(worker_cleanup_handler, w);
    pthread_barrier_wait(&w->crk->barrier);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    do {
        err = do_work(w);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

        if (err)
            break;

        /* false positive? */
        if (zc_file_test_password(w->crk->filename, w->gen.pw)) {
            w->found = true;
            break;
        }

        err = pwgen_skip(&w->gen);
        pthread_testcancel();
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    } while (err == 0);

    pthread_cleanup_pop(1);
    return NULL;
}

static void dealloc_workers(struct zc_crk_bforce *crk)
{
    struct worker *w, *wtmp;
    list_for_each_entry_safe(w, wtmp,  &crk->workers_head, workers) {
        list_del(&w->workers);
        free(w);
    }
}

static int alloc_workers(struct zc_crk_bforce *crk, size_t workers)
{
    for (size_t i = 0; i < workers; ++i) {
        struct worker *w = calloc(1, sizeof(struct worker));
        if (!w)
            return -1;

        w->found = false;
        w->crk = crk;

        /* copy password generator config from user */
        memcpy(&w->gen.cfg, &crk->cfg, sizeof(struct zc_crk_pwcfg));

        /* initialise password generator */
        init_char_ascii(&w->gen);
        init_char_indexes(&w->gen);

        /* position ourselves on the first password - modifies pw generator */
        w->gen.cfg.step = 1;
        for (size_t j = 0; j < i; ++j) {
            size_t count;
            if (!pwgen_generate(&w->gen, &count)) {
                free(w);
                dealloc_workers(crk);
                err(crk->ctx, "offset too big for password range.\n");
                return -1;
            }
        }
        w->gen.cfg.step = workers;

        list_add(&w->workers, &crk->workers_head);
    }

    return 0;
}

static void start_workers(struct zc_crk_bforce *crk)
{
    struct worker *w;

    pthread_mutex_lock(&crk->mutex);
    list_for_each_entry(w, &crk->workers_head, workers) {
        int err = pthread_create(&w->thread_id, NULL, worker, w);
        if (err)
            fatal("pthread_create() failed");
    }
    pthread_mutex_unlock(&crk->mutex);
}

/* called while holding mutex */
static void cancel_workers(struct zc_crk_bforce *crk)
{
    struct worker *w;

    list_for_each_entry(w, &crk->workers_head, workers) {
        int err = pthread_cancel(w->thread_id);
        if (err)
            fatal("pthread_cancel() failed");
    }
}

static int wait_workers(struct zc_crk_bforce *crk, size_t workers, char *pw, size_t len)
{
    int ret = 1;
    int workers_left = workers;

    if (!len)
        return -1;

    /* waits for workers on the 'cleanup' list */
    while (workers_left) {
        pthread_mutex_lock(&crk->mutex);
        while (list_empty(&crk->cleanup_head))
            pthread_cond_wait(&crk->cond, &crk->mutex);
        struct worker *w, *tempw;
        list_for_each_entry_safe(w, tempw, &crk->cleanup_head, cleanup) {
            list_del(&w->cleanup);
            pthread_join(w->thread_id, NULL);
            if (w->found) {
                ret = 0;
                memset(pw, 0, len);
                strncpy(pw, w->gen.pw, len - 1);
                cancel_workers(crk);
            }
            free(w);
            --workers_left;
        }
        pthread_mutex_unlock(&crk->mutex);
    }

    return ret;
}

ZC_EXPORT int zc_crk_bforce_start(struct zc_crk_bforce *crk, size_t workers, char *pwbuf, size_t pwbuflen)
{
    int err;

    if (!workers || !crk->vdata_size || !crk->filename)
        return -1;

    if (alloc_workers(crk, workers))
        fatal("failed to allocate workers\n");

    err = pthread_barrier_init(&crk->barrier, NULL, workers);
    if (err)
        fatal("pthread_barrier_init() failed");

    start_workers(crk);
    err = wait_workers(crk, workers, pwbuf, pwbuflen);
    if (err < 0)
        fatal("failed to wait for workers\n");

    pthread_barrier_destroy(&crk->barrier);

    return err;
}
