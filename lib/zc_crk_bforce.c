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
#include <setjmp.h>

#include "crc32.h"
#include "zip.h"
#include "list.h"
#include "libzc.h"
#include "pwstream.h"
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

    /* initial password */
    char ipw[ZC_PW_MAXLEN + 1];
    size_t ipwlen;
    size_t maxlen;

    /* character set */
    char set[ZC_CHARSET_MAXLEN + 1];
    size_t setlen;

    /* password streams */
    struct pwstream **pws;
    size_t pwslen;

    struct list_head workers_head;
    struct list_head cleanup_head;
    pthread_barrier_t barrier;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct worker {
    struct list_head workers;
    struct list_head cleanup;
    pthread_t thread_id;
    size_t id;
    char pw[ZC_PW_MAXLEN + 1];
    bool found;
    jmp_buf env;
    struct zc_crk_bforce *crk;
};

static inline void update_keys(char c, struct zc_key *ksrc, struct zc_key *kdst)
{
    kdst->key0 = crc32(ksrc->key0, c);
    kdst->key1 = (ksrc->key1 + (kdst->key0 & 0xff)) * MULT + 1;
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

static inline void reset_encryption_keys(const struct zc_key *base, struct zc_key *k)
{
    *k = *base;
}

static inline uint8_t decrypt_byte(uint32_t k)
{
    uint32_t tmp =  (k | 2) & 0xffff;
    return ((tmp * (tmp ^ 1)) >> 8) & 0xff;
}

static inline uint8_t decrypt_header(const uint8_t *hdr, struct zc_key *k, uint8_t magic)
{
    uint8_t c;

    for (size_t i = 0; i < ZIP_ENCRYPTION_HEADER_LENGTH - 1; ++i) {
        c = hdr[i] ^ decrypt_byte(k->key2);
        update_keys(c, k, k);
    }

    /* Returns the last byte of the decrypted header */
    return hdr[ZIP_ENCRYPTION_HEADER_LENGTH - 1] ^ decrypt_byte(k->key2) ^ magic;
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
    return (*(char *)a - * (char *)b);
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
    for (size_t i = 0; pw[i] != '\0'; ++i) {
        if (!memchr(set, pw[i], len))
            return false;
    }
    return true;
}

static inline bool try_decrypt(const struct zc_crk_bforce *crk, const struct zc_key *base)
{
    struct zc_key key;
    for (size_t i = 0; i < crk->vdata_size; ++i) {
        reset_encryption_keys(base, &key);
        if (decrypt_header(crk->vdata[i].encryption_header, &key, crk->vdata[i].magic))
            return false;
    }
    return true;
}

static inline bool test_password(const struct zc_crk_bforce *crk, const char *pw)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    if (zc_file_test_password(crk->filename, pw))
        return true;
    pthread_testcancel();
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    return false;
}

static void fill_limits(struct pwstream *pws, struct entry *limit, size_t count,
                        size_t stream)
{
    for (size_t i = 0, j = count - 1; i < count; ++i, --j)
        limit[i] = *pwstream_get_entry(pws, stream, j);
}

static void do_work_recurse(const struct zc_crk_bforce *crk, size_t level,
                            size_t level_count, char *pw, struct zc_key *cache,
                            struct entry *limit, jmp_buf env)
{
    size_t i = level_count - level;
    int first = limit[0].initial;
    int last = limit[0].stop + 1;
    if (level == 1) {
        for (int p = first; p < last; ++p) {
            pw[i] = crk->set[p];
            update_keys(pw[i], &cache[i], &cache[i + 1]);
            if (try_decrypt(crk, &cache[level_count])) {
                if (test_password(crk, pw))
                    longjmp(env, 1);
            }
        }
    } else {
        for (int p = first; p < last; ++p) {
            pw[i] = crk->set[p];
            update_keys(pw[i], &cache[i], &cache[i + 1]);
            do_work_recurse(crk, level - 1, level_count, pw, cache, &limit[1], env);
        }
    }
    limit[0].initial = limit[0].start;
}

static bool do_work(const struct zc_crk_bforce *crk, struct pwstream *pws,
                    size_t stream, char *pw, jmp_buf env)
{
    size_t level = pwstream_get_pwlen(pws);
    struct zc_key cache[level + 1];
    struct entry limit[level];

    fill_limits(pws, limit, level, stream);
    memset(cache, 0, sizeof(struct zc_key) * (level + 1));
    set_default_encryption_keys(cache);

    int ret = setjmp(env);
    if (!ret)
        do_work_recurse(crk, level, level, pw, cache, limit, env);
    return (ret == 1);
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

    pthread_cleanup_push(worker_cleanup_handler, w);
    pthread_barrier_wait(&w->crk->barrier);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    for (size_t i = 0; i < w->crk->pwslen; ++i) {
        if (pwstream_is_empty(w->crk->pws[i], w->id))
            continue;

        if (do_work(w->crk, w->crk->pws[i], w->id, w->pw, w->env)) {
            w->found = true;
            goto exit;
        }
    }

exit:
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
        if (!w) {
            dealloc_workers(crk);
            return -1;
        }

        w->found = false;
        w->crk = crk;
        w->id = i;
        list_add(&w->workers, &crk->workers_head);
    }

    return 0;
}

static void start_workers(struct zc_crk_bforce *crk)
{
    struct worker *w;

    pthread_mutex_lock(&crk->mutex);
    list_for_each_entry(w, &crk->workers_head, workers) {
        if (pthread_create(&w->thread_id, NULL, worker, w))
            fatal("pthread_create() failed");
    }
    pthread_mutex_unlock(&crk->mutex);
}

/* called while holding mutex */
static void cancel_workers(struct zc_crk_bforce *crk)
{
    struct worker *w;

    list_for_each_entry(w, &crk->workers_head, workers) {
        if (pthread_cancel(w->thread_id))
            fatal("pthread_cancel() failed");
    }
}

static int wait_workers(struct zc_crk_bforce *crk, size_t workers, char *pw, size_t len)
{
    int ret = 1;
    int workers_left = workers;

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
                strncpy(pw, w->pw, len);
                cancel_workers(crk);
            }
            free(w);
            --workers_left;
        }
        pthread_mutex_unlock(&crk->mutex);
    }

    return ret;
}

static void dealloc_pwstreams(struct zc_crk_bforce *crk)
{
    for (size_t l = 0; l < crk->pwslen; ++l) {
        if (crk->pws[l])
            pwstream_free(crk->pws[l]);
    }
    free(crk->pws);
}

static void fill_initial_pwstream(size_t *initial, const char *ipw, size_t ipwlen,
                                  const char *set, size_t setlen)
{
    for (size_t i = ipwlen - 1, j = 0; j < ipwlen; --i, ++j)
        initial[j] = (const char *)memchr(set, ipw[i], setlen) - set;
}

/* when generating the first streams, take into account the
 * initial password provided */
static int alloc_first_pwstream(struct pwstream **pws, const char *ipw, size_t ipwlen,
                                const char *set, size_t setlen, size_t workers)
{
    struct pwstream *tmp;
    size_t initial[ipwlen];

    if (pwstream_new(&tmp))
        return -1;

    fill_initial_pwstream(initial, ipw, ipwlen, set, setlen);
    pwstream_generate(tmp, setlen, ipwlen, workers, initial);

    *pws = tmp;

    return 0;
}

static int alloc_pwstreams(struct zc_crk_bforce *crk, size_t workers)
{
    const char *ipw = crk->ipw;
    size_t ipwlen = crk->ipwlen;
    size_t maxlen = crk->maxlen;
    size_t to_alloc = maxlen - ipwlen + 1;
    const char *set = crk->set;
    size_t setlen = crk->setlen;

    crk->pws = calloc(1, sizeof(struct pwstream *) * to_alloc);
    if (!crk->pws)
        return -1;

    if (alloc_first_pwstream(&crk->pws[0], ipw, ipwlen, set, setlen, workers)) {
        free(crk->pws);
        return -1;
    }

    crk->pwslen = 1;
    for (size_t i = 1; i < to_alloc; ++i) {
        if (pwstream_new(&crk->pws[i])) {
            dealloc_pwstreams(crk);
            return -1;
        }
        crk->pwslen++;
        pwstream_generate(crk->pws[i], setlen, ipwlen + i, workers, NULL);
    }

    return 0;
}

ZC_EXPORT bool zc_crk_test_one_pw(const char *pw, const struct zc_validation_data *vdata, size_t nmemb)
{
    struct zc_key key;
    struct zc_key base_key;
    size_t i;

    init_encryption_keys(pw, &base_key);
    for (i = 0; i < nmemb; ++i) {
        reset_encryption_keys(&base_key, &key);
        if (decrypt_header(vdata[i].encryption_header, &key, vdata[i].magic))
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

ZC_EXPORT int zc_crk_bforce_set_pwcfg(struct zc_crk_bforce *crk, const struct zc_crk_pwcfg *cfg)
{
    /* basic sanity checks */
    if (cfg->setlen == 0 ||
        cfg->setlen > ZC_CHARSET_MAXLEN  ||
        cfg->maxlen == 0 ||
        cfg->maxlen > ZC_PW_MAXLEN)
        return -1;

    memcpy(crk->ipw, cfg->initial, ZC_PW_MAXLEN + 1);
    memcpy(crk->set, cfg->set, ZC_CHARSET_MAXLEN + 1);
    crk->maxlen = cfg->maxlen;
    crk->setlen = sanitize_set(crk->set, cfg->setlen);
    crk->ipwlen = strnlen(crk->ipw, ZC_PW_MAXLEN);

    if (!crk->ipwlen) {
        /* no initial password supplied, use first set character */
        crk->ipw[0] = crk->set[0];
        crk->ipw[1] = '\0';
        crk->ipwlen = 1;
        return 0;
    }

    if (crk->ipwlen > crk->maxlen)
        return -1;
    if (!pw_in_set(crk->ipw, crk->set, crk->setlen))
        return -1;

    return 0;
}

ZC_EXPORT int zc_crk_bforce_set_vdata(struct zc_crk_bforce *crk,
                                      const struct zc_validation_data *vdata, size_t nmemb)
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
    return crk->set;
}

ZC_EXPORT int zc_crk_bforce_start(struct zc_crk_bforce *crk, size_t workers,
                                  char *pw, size_t len)
{
    int err;

    if (!workers || !len)
        return -1;

    if (alloc_pwstreams(crk, workers))
        fatal("failed to allocate password streams");

    if (alloc_workers(crk, workers))
        fatal("failed to allocate workers\n");

    err = pthread_barrier_init(&crk->barrier, NULL, workers);
    if (err)
        fatal("pthread_barrier_init() failed");

    start_workers(crk);
    err = wait_workers(crk, workers, pw, len);
    if (err < 0)
        fatal("failed to wait for workers\n");

    pthread_barrier_destroy(&crk->barrier);
    dealloc_pwstreams(crk);

    return err;
}
