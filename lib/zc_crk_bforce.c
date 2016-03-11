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

    /* password generator config from user */
    struct zc_crk_pwcfg cfg;

    struct pwstream **pws;

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
    unsigned int id;
    char pw[ZC_PW_MAXLEN + 1];
    bool found;
    jmp_buf env;
    struct zc_crk_bforce *crk;
};

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

static inline bool try_decrypt(const struct zc_crk_bforce *crk, const struct zc_key *base)
{
    struct zc_key key;
    size_t i;
    for (i = 0; i < crk->vdata_size; ++i) {
        reset_encryption_keys(base, &key);
        if (decrypt_header(crk->vdata[i].encryption_header, &key) != crk->vdata[i].magic)
            return false;
    }
    return true;
}

static inline bool test_password_mt(const struct zc_crk_bforce *crk, const char *pw)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    if (zc_file_test_password(crk->filename, pw))
        return true;
    pthread_testcancel();
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    return false;
}

static inline bool test_password(const struct zc_crk_bforce *crk, const char *pw)
{
    return zc_file_test_password(crk->filename, pw);
}

/* static bool do_work_1(const struct zc_crk_bforce *crk, char *ret) */
/* { */
/*     struct zc_key base; */
/*     char pw[2] = {0}; */

/*     for (size_t p = 0; p < crk->cfg.setlen; ++p) { */
/*         pw[0] = crk->cfg.set[p]; */
/*         init_encryption_keys(pw, &base); */
/*         if (try_decrypt(crk, &base)) { */
/*             if (test_password(crk, pw)) { */
/*                 strcpy(ret, pw); */
/*                 return true; */
/*             } */
/*         } */
/*     } */
/*     return false; */
/* } */

/* static bool do_work_2(const struct zc_crk_bforce *crk, char *ret) */
/* { */
/*     struct zc_key cache[3]; */
/*     char pw[3] = {0}; */

/*     memset(cache, 0, sizeof(struct zc_key) * 3); */

/*     set_default_encryption_keys(cache); */

/*     for (size_t p0 = 0; p0 < crk->cfg.setlen; ++p0) { */
/*         pw[0] = crk->cfg.set[p0]; */
/*         update_keys(pw[0], cache, &cache[1]); */

/*         for (size_t p1 = 0; p1 < crk->cfg.setlen; ++p1) { */
/*             pw[1] = crk->cfg.set[p1]; */
/*             update_keys(pw[1], &cache[1], &cache[2]); */

/*             if (try_decrypt(crk, &cache[2])) { */
/*                 if (test_password(crk, pw)) { */
/*                     strcpy(ret, pw); */
/*                     return true; */
/*                 } */
/*             } */
/*         } */
/*     } */
/*     return false; */
/* } */

static void fill_limits(struct pwstream *pws, unsigned int *limit, size_t count,
                        unsigned int stream)
{
    for (size_t i = 0, j = count - 1; i < count * 2; i += 2, --j) {
        limit[i] = pwstream_get_start_idx(pws, stream, j);
        limit[i + 1] = pwstream_get_stop_idx(pws, stream, j) + 1;
    }
}

#define for_each_char_begin(limit, set, pw, cache, level)               \
    for (size_t p ##level = limit[level * 2]; p ##level < limit[level * 2 + 1]; ++p ##level) { \
        pw[level] = set[p ##level];                                     \
        update_keys(pw[level], &cache[level], &cache[level + 1]);       \

#define for_each_char_end }

/* for (size_t p0 = limit[0]; p0 < limit[1]; p0++) { */
/*     pw[0] = crk->cfg.set[p0]; */
/*     update_keys(pw[0], cache, &cache[1]); */

/*     for (size_t p1 = limit[2]; p1 < limit[3]; p1++) { */
/*         pw[1] = crk->cfg.set[p1]; */
/*         update_keys(pw[1], &cache[1], &cache[2]); */

/*         for (size_t p2 = limit[4]; p2 < limit[5]; p2++) { */
/*             pw[2] = crk->cfg.set[p2]; */
/*             update_keys(pw[2], &cache[2], &cache[3]); */

/*             if (try_decrypt(crk, &cache[3])) { */
/*                 if (test_password_mt(crk, pw)) { */
/*                     strcpy(ret, pw); */
/*                     return true; */
/*                 } */
/*             } */
/*         } */
/*     } */
/* } */

static void do_work_recurse(const struct zc_crk_bforce *crk, size_t level,
                            size_t level_count, char *pw, struct zc_key *cache,
                            unsigned int *limit, jmp_buf env)
{
    if (level == 0) {
        if (try_decrypt(crk, &cache[level_count])) {
            if (test_password_mt(crk, pw))
                longjmp(env, 1);
        }
    } else {
        int i = level_count - level;
        int first = limit[i * 2];
        int last = limit[i * 2 + 1];
        for (int p = first; p < last; ++p) {
            pw[i] = crk->cfg.set[p];
            update_keys(pw[i], &cache[i], &cache[i + 1]);
            do_work_recurse(crk, level - 1, level_count, pw, cache, limit, env);
        }
    }
}

static bool do_work_3(const struct zc_crk_bforce *crk, struct pwstream *pws,
                      unsigned int stream, char *pw, jmp_buf env)
{
    struct zc_key cache[4];
    unsigned int limit[6];

    fill_limits(pws, limit, 3, stream);

    memset(cache, 0, sizeof(struct zc_key) * 4);

    set_default_encryption_keys(cache);

    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 0) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 1) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 2) */
    /*     if (try_decrypt(crk, &cache[3])) { */
    /*         if (test_password_mt(crk, pw)) { */
    /*             strcpy(ret, pw); */
    /*             return true; */
    /*         } */
    /*     } */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */

    /* return false; */
    int ret = setjmp(env);
    if (!ret)
        do_work_recurse(crk, 3, 3, pw, cache, limit, env);
    return ret == 1 ? true : false;
}

static bool do_work_4(const struct zc_crk_bforce *crk, struct pwstream *pws,
                      unsigned int stream, char *pw, jmp_buf env)
{
    struct zc_key cache[5];
    unsigned int limit[8];

    fill_limits(pws, limit, 4, stream);

    memset(cache, 0, sizeof(struct zc_key) * 5);

    set_default_encryption_keys(cache);

    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 0) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 1) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 2) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 3) */
    /*     if (try_decrypt(crk, &cache[4])) { */
    /*         if (test_password_mt(crk, pw)) { */
    /*             strcpy(ret, pw); */
    /*             return true; */
    /*         } */
    /*     } */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */

    /* return false; */
    int ret = setjmp(env);
    if (!ret)
        do_work_recurse(crk, 4, 4, pw, cache, limit, env);
    return ret == 1 ? true : false;
}

static bool do_work_5(const struct zc_crk_bforce *crk, struct pwstream *pws,
                      unsigned int stream, char *pw, jmp_buf env)
{
    struct zc_key cache[6];
    unsigned int limit[10];

    fill_limits(pws, limit, 5, stream);

    memset(cache, 0, sizeof(struct zc_key) * 6);

    set_default_encryption_keys(cache);

    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 0) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 1) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 2) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 3) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 4) */
    /*     if (try_decrypt(crk, &cache[5])) { */
    /*         if (test_password_mt(crk, pw)) { */
    /*             strcpy(ret, pw); */
    /*             return true; */
    /*         } */
    /*     } */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */

    /* return false; */
    int ret = setjmp(env);
    if (!ret)
        do_work_recurse(crk, 5, 5, pw, cache, limit, env);
    return ret == 1 ? true : false;
}

static bool do_work_6(const struct zc_crk_bforce *crk, struct pwstream *pws,
                      unsigned int stream, char *pw, jmp_buf env)
{
    struct zc_key cache[7];
    unsigned int limit[12];

    fill_limits(pws, limit, 6, stream);

    memset(cache, 0, sizeof(struct zc_key) * 7);

    set_default_encryption_keys(cache);

    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 0) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 1) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 2) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 3) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 4) */
    /* for_each_char_begin(limit, crk->cfg.set, pw, cache, 5) */
    /*     if (try_decrypt(crk, &cache[6])) { */
    /*         if (test_password_mt(crk, pw)) { */
    /*             strcpy(ret, pw); */
    /*             return true; */
    /*         } */
    /*     } */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */
    /* for_each_char_end */

    /* return false; */
    int ret = setjmp(env);
    if (!ret)
        do_work_recurse(crk, 6, 6, pw, cache, limit, env);
    return ret == 1 ? true : false;
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

    /* TODO: pwstream_is_empty */
    /* if (!pwstream_is_empty(w->crk->pws[0], w->id)) { */
    /*     if (do_work_1(w->crk, w->crk->pws[0], w->id, w->pw)) { */
    /*         w->found = true; */
    /*         goto exit; */
    /*     } */
    /* } */

    if (do_work_3(w->crk, w->crk->pws[2], w->id, w->pw, w->env)) {
        w->found = true;
        goto exit;
    }

    if (do_work_4(w->crk, w->crk->pws[3], w->id, w->pw, w->env)) {
        w->found = true;
        goto exit;
    }

    if (do_work_5(w->crk, w->crk->pws[4], w->id, w->pw, w->env)) {
        w->found = true;
        goto exit;
    }

    if (do_work_6(w->crk, w->crk->pws[5], w->id, w->pw, w->env)) {
        w->found = true;
        goto exit;
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
        if (!w)
            goto error;

        w->found = false;
        w->crk = crk;
        w->id = i;

        /* TODO: Create 'find_nearest' function to position each
         * stream. See python code. */

        list_add(&w->workers, &crk->workers_head);
    }

    return 0;

error:
    dealloc_workers(crk);
    return -1;
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
                strncpy(pw, w->pw, len - 1);
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
    size_t count = crk->cfg.stoplen - crk->cfg.ilen + 1;
    for (size_t l = 0; l < count; ++l) {
        if (crk->pws[l])
            pwstream_free(crk->pws[l]);
    }
    free(crk->pws);
}

static int alloc_pwstreams(struct zc_crk_bforce *crk, size_t workers)
{
    size_t first = crk->cfg.ilen;
    size_t last = crk->cfg.stoplen;
    size_t to_alloc = last - first + 1;

    crk->pws = calloc(1, sizeof(struct pwstream*) * to_alloc);
    if (!crk->pws)
        return -1;

    for (size_t i = 0; i < to_alloc; ++i) {
        if (pwstream_new(&crk->pws[i])) {
            dealloc_pwstreams(crk);
            return -1;
        }
        pwstream_generate(crk->pws[i], crk->cfg.setlen, first + i, workers);
    }

    return 0;
}

ZC_EXPORT int zc_crk_bforce_start(struct zc_crk_bforce *crk, size_t workers,
                                  char *pwbuf, size_t pwbuflen)
{
    int err;

    if (!workers || !crk->vdata_size || !crk->filename)
        return -1;

    if (alloc_pwstreams(crk, workers))
        fatal("failed to allocate password streams");

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
    dealloc_pwstreams(crk);

    return err;
}
