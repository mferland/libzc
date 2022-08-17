/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2021 Marc Ferland
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "list.h"
#include "pool.h"
#include "crc32.h"
#include "libzc_private.h"
#include "ptext_private.h"

#define PREKEY1 0x57d2770       /* the only key1 value possible before
                                 * 0x12345678, found by exhaustive
                                 * search */
#define PASS_MAX_LEN 13
#define RECOVERED_KEYS_BUF_LEN (PASS_MAX_LEN + 2) /* includes internal rep and PREKEY1 */
#define NB_WORK_UNITS 256

struct final_private {
	uint8_t pw[PASS_MAX_LEN];
	struct zc_key k[PASS_MAX_LEN + 1];  /* 14 --> store the internal rep at index 0 */
	/* struct zc_key saved; */
	int len_under_test;
	const uint8_t (*lsbk0_lookup)[4];
	const uint8_t *lsbk0_count;
	struct threadpool *pool;
	struct zc_key internal_rep;
	pthread_mutex_t mutex;
	bool found;
};

static void inplace_reverse(uint8_t *str, size_t len)
{
	uint8_t *end = &str[len - 1];
	while (str < end) {
		uint8_t tmp = *str;
		*str++ = *end;
		*end-- = tmp;
	}
}

/**
 * Zero-out pw and keys
 */
static void reset(struct final_private *f)
{
	memset(f->pw, 0, PASS_MAX_LEN);
	memset(&f->k[1], 0, PASS_MAX_LEN * sizeof(struct zc_key));
}

/**
 * From 'k' msb and 'km1' lsb (previous key from 'k'), find the key
 * (key being the byte that went through the crc32 function).
 */
static uint8_t recover_input_byte_from_crcs(uint32_t km1, uint32_t k)
{
	return (lsb(km1) ^ crc_32_invtab[msb(k)] ^ 0x00) & 0xff;
}

/**
 * From 'pw', calculate the internal representation of the key and
 * compare it with 'k'.
 */
static int compare_pw_with_key(const uint8_t *pw, size_t len,
			       const struct zc_key *k)
{
	struct zc_key tmp;

	update_default_keys_from_array(&tmp, pw, len);

	return (k->key0 == tmp.key0 &&
		k->key1 == tmp.key1 &&
		k->key2 == tmp.key2) ? 0 : -1;
}

static int compare_revpw_with_key(const uint8_t *pw, size_t len,
				  const struct zc_key *k)
{
	uint8_t revpw[PASS_MAX_LEN];

	for (int i = len - 1, j = 0; i >= 0; --i, ++j)
		revpw[j] = pw[i];

	return compare_pw_with_key(revpw, len, k);
}

/**
 * passwords length 1->4
 */
static int try_key_1_4(struct final_private *f)
{
	for (int len = 1; len <= 4; ++len) {
		/* recover k0 msb */
		f->k[len].key0 = crc32inv(f->k[len - 1].key0, 0x0);

		/* recover bytes */
		uint32_t prev = KEY0;
		for (int j = 0, k = len - 1; j < len; ++j, --k) {
			f->pw[j] = recover_input_byte_from_crcs(prev, f->k[k].key0);
			prev = crc32(prev, f->pw[j]);
		}

		if (compare_pw_with_key(f->pw, len, f->k) == 0)
			return len;
	}
	return -1;
}

/**
 * From k1 MSBs found earlier, recover full k1 and k0 LSBs. For
 * example, from:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x1c?????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x2b?????? key2 = 0x4ccb4379
 * key0 = 0x???????? key1 = 0xb3?????? key2 = 0xa253270a
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * recover:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x??????97 key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x??????a2 key1 = 0x1cd05dd7 key2 = 0x3d945e94
 * key0 = 0x??????23 key1 = 0x2b7993bc key2 = 0x4ccb4379
 * key0 = 0x??????96 key1 = 0xb303049c key2 = 0xa253270a
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 */
static bool recover_key1_key0lsb(struct zc_key *k,
				 const uint8_t (*lsbk0_lookup)[4],
				 const uint8_t *lsbk0_count,
				 uint32_t level)
{
	if (level == 0)
		return k->key1 == KEY1;

	uint32_t key1 = k->key1;
	uint32_t key1m1 = (k + 1)->key1;
	uint32_t key1m2 = (k + 2)->key1;
	uint32_t rhs_step1 = (key1 - 1) * MULTINV;
	uint32_t rhs_step2 = (rhs_step1 - 1) * MULTINV;
	uint8_t diff = msb(rhs_step2 - mask_msb(key1m2));

	for (uint32_t i = 0; i < lsbk0_count[diff]; ++i) {
		uint32_t lsbkey0i = lsbk0_lookup[diff][i];
		if (mask_msb(rhs_step1 - lsbkey0i) == mask_msb(key1m1)) {
			(k + 1)->key1 = rhs_step1 - lsbkey0i;
			k->key0 = (k->key0 & 0xffffff00) | lsbkey0i; /* set LSB */
			if (recover_key1_key0lsb(k + 1, lsbk0_lookup, lsbk0_count, level - 1))
				return true;
		}
	}
	return false;
}

/**
 * From the internal representation, we can calculate key1_0, key2_0,
 * and key2_-1. See equation 2 in Biham & Kocher.
 */
static void key_56_step1(struct zc_key *k)
{
	/* recover full key2_0 */
	k[1].key2 = crc32inv(k[0].key2, msb(k[0].key1));

	/* recover full key1_0 */
	k[1].key1 = ((k[0].key1 - 1) * MULTINV) - lsb(k[0].key0);

	/* recover full key2_-1 */
	k[2].key2 = crc32inv(k[1].key2, msb(k[1].key1));
}

/**
 * From full key2_0, key1_0 and key2_-1 recover the other full key2
 * values and k1 MSBs.
 *
 * For example, from:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x????????
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x????????
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * recover key2 MSBs:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x4ccb43?? <--
 * key0 = 0x???????? key1 = 0x???????? key2 = 0xa253???? <--
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * then recover k1 MSBs and the full key2 values:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x1c?????? key2 = 0x3d945e94 <--
 * key0 = 0x???????? key1 = 0x2b?????? key2 = 0x4ccb4379 <--
 * key0 = 0x???????? key1 = 0xb3?????? key2 = 0xa253270a <--
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 */
static void key_56_step2(struct zc_key *k, int start)
{
	uint32_t prev = KEY2;

	/* recover key2_-2 (24 bits msb) */
	k[3].key2 = crc32inv(k[2].key2, 0x0);

	/* recover key2_-3 (16 bits msb) */
	k[4].key2 = crc32inv(k[3].key2, 0x0);

	/* recover key2_-4 (8 bits msb) */
	/* TODO: k[5] is already known if key is only 5 chars */
	k[5].key2 = crc32inv(k[4].key2, 0x0);

	/* recover full key1 values */
	for (int i = start; i >= 2; --i) {
		k[i].key1 = (uint32_t)recover_input_byte_from_crcs(prev, k[i].key2) << 24;
		prev = crc32(prev, msb(k[i].key1));
		/* do not overwrite key2_-1, since we know the full value */
		if (i > 2)
			k[i].key2 = prev;
	}
}

static bool verify_against_key2m1(const struct zc_key *k)
{
	return crc32(k[3].key2, msb(k[2].key1)) == k[2].key2;
}

static int try_key_5_6(struct final_private *f)
{
	struct zc_key *k = f->k;

	key_56_step1(k);

	for (int i = 4; i <= 5; ++i) {
		key_56_step2(k, i);

		if (!verify_against_key2m1(k))
			continue;

		set_default_encryption_keys(&k[i + 1]);
		k[i + 2].key1 = PREKEY1;

		if (!recover_key1_key0lsb(&k[1], f->lsbk0_lookup, f->lsbk0_count, i))
			continue;

		/* recover bytes */
		for (int j = 0; j < i + 1; ++j) {
			f->pw[j] = recover_input_byte_from_crcs(k[j + 1].key0, k[j].key0);
			k[j + 1].key0 = crc32inv(k[j].key0, f->pw[j]);
		}

		if (compare_revpw_with_key(f->pw, i + 1, &f->k[0]) < 0)
			continue;

		inplace_reverse(f->pw, i + 1);
		return i + 1;
	}

	return -1;
}

static int recover(struct zc_key *recovered,
		   uint8_t *recovered_pw,
		   size_t from,
		   const uint8_t (*lsbk0_lookup)[4],
		   const uint8_t *lsbk0_count,
		   const struct zc_key *internal_rep)
{
	struct zc_key *k = &recovered[from];
	uint8_t *pw = &recovered_pw[from];

	key_56_step1(k);
	key_56_step2(k, 5);

	/* verify against key2_-1 */
	if (!verify_against_key2m1(k))
		return -1;

	set_default_encryption_keys(&k[6]);
	k[7].key1 = PREKEY1;
	if (!recover_key1_key0lsb(&k[1], lsbk0_lookup, lsbk0_count, 5))
		return -1;

	for (int j = 0; j < 6; ++j) {
		pw[j] = recover_input_byte_from_crcs(k[j + 1].key0, k[j].key0);
		k[j + 1].key0 = crc32inv(k[j].key0, pw[j]);
	}

	if (compare_revpw_with_key(recovered_pw, from + 6, internal_rep))
		return -1;

	/* got it! */
	inplace_reverse(recovered_pw, from + 6);
	return 0;
}

struct final_work_unit {
	size_t start, len;
	struct list_head list;
};

static void set_password_found(struct final_private *final, uint8_t *pw)
{
	pthread_mutex_lock(&final->mutex);
	final->found = true;
	memcpy(final->pw, pw, PASS_MAX_LEN);
	pthread_mutex_unlock(&final->mutex);
}

static void recover_prev_key(const struct zc_key *k, uint8_t c,
			     struct zc_key *prev)
{
	prev->key2 = crc32inv(k->key2, msb(k->key1));
	prev->key1 = ((k->key1 - 1) * MULTINV) - lsb(k->key0);
	prev->key0 = crc32inv(k->key0, c);
}

static int recover_7(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		if (recover(recovered,
			    pw,
			    1,
			    final->lsbk0_lookup,
			    final->lsbk0_count,
			    &final->internal_rep) < 0) {
			/* not found, go on to the next character */
			c++;
		} else {
			/* found! set global flag and break out */
			set_password_found(final, pw);
			return TPECANCELSIBLINGS;
		}
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_8(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			if (recover(recovered,
				    pw,
				    2,
				    final->lsbk0_lookup,
				    final->lsbk0_count,
				    &final->internal_rep) < 0) {
				/* not found, go on to the next character */
				continue;
			} else {
				/* found! set global flag and break out */
				set_password_found(final, pw);
				return TPECANCELSIBLINGS;
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_9(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			for (int j = 0; j < 256; ++j) {
				pw[2] = j;
				recover_prev_key(&recovered[2], j, &recovered[3]);
				if (recover(recovered,
					    pw,
					    3,
					    final->lsbk0_lookup,
					    final->lsbk0_count,
					    &final->internal_rep) < 0) {
					/* not found, go on to the next character */
					continue;
				} else {
					/* found! set global flag and break out */
					set_password_found(final, pw);
					return TPECANCELSIBLINGS;
				}
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_10(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			for (int j = 0; j < 256; ++j) {
				pw[2] = j;
				recover_prev_key(&recovered[2], j, &recovered[3]);
				for (int k = 0; k < 256; ++k) {
					pw[3] = k;
					recover_prev_key(&recovered[3], k, &recovered[4]);
					if (recover(recovered,
						    pw,
						    4,
						    final->lsbk0_lookup,
						    final->lsbk0_count,
						    &final->internal_rep) < 0) {
						/* not found, go on to the next character */
						continue;
					} else {
						/* found! set global flag and break out */
						set_password_found(final, pw);
						return TPECANCELSIBLINGS;
					}
				}
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_11(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			for (int j = 0; j < 256; ++j) {
				pw[2] = j;
				recover_prev_key(&recovered[2], j, &recovered[3]);
				for (int k = 0; k < 256; ++k) {
					pw[3] = k;
					recover_prev_key(&recovered[3], k, &recovered[4]);
					for (int l = 0; l < 256; ++l) {
						pw[4] = l;
						recover_prev_key(&recovered[4], k, &recovered[5]);
						if (recover(recovered,
							    pw,
							    5,
							    final->lsbk0_lookup,
							    final->lsbk0_count,
							    &final->internal_rep) < 0) {
							/* not found, go on to the next character */
							continue;
						} else {
							/* found! set global flag and break out */
							set_password_found(final, pw);
							return TPECANCELSIBLINGS;
						}
					}
				}
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_12(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			for (int j = 0; j < 256; ++j) {
				pw[2] = j;
				recover_prev_key(&recovered[2], j, &recovered[3]);
				for (int k = 0; k < 256; ++k) {
					pw[3] = k;
					recover_prev_key(&recovered[3], k, &recovered[4]);
					for (int l = 0; l < 256; ++l) {
						pw[4] = l;
						recover_prev_key(&recovered[4], k, &recovered[5]);
						for (int m = 0; m < 256; ++m) {
							pw[5] = m;
							recover_prev_key(&recovered[5], k, &recovered[6]);
							if (recover(recovered,
								    pw,
								    6,
								    final->lsbk0_lookup,
								    final->lsbk0_count,
								    &final->internal_rep) < 0) {
								/* not found, go on to the next character */
								continue;
							} else {
								/* found! set global flag and break out */
								set_password_found(final, pw);
								return TPECANCELSIBLINGS;
							}
						}
					}
				}
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static int recover_13(void *in, struct list_head *list, int id)
{
	struct zc_key recovered[RECOVERED_KEYS_BUF_LEN];
	uint8_t pw[PASS_MAX_LEN] = { 0 };
	struct final_work_unit *unit = list_entry(list, struct final_work_unit, list);
	struct final_private *final = (struct final_private *)in;
	(void)id;

	recovered[0] = final->internal_rep;

	int c = unit->start, c_end = unit->start + unit->len;
	do {
		pw[0] = c;
		recover_prev_key(&recovered[0], c, &recovered[1]);
		for (int i = 0; i < 256; ++i) {
			pw[1] = i;
			recover_prev_key(&recovered[1], i, &recovered[2]);
			for (int j = 0; j < 256; ++j) {
				pw[2] = j;
				recover_prev_key(&recovered[2], j, &recovered[3]);
				for (int k = 0; k < 256; ++k) {
					pw[3] = k;
					recover_prev_key(&recovered[3], k, &recovered[4]);
					for (int l = 0; l < 256; ++l) {
						pw[4] = l;
						recover_prev_key(&recovered[4], k, &recovered[5]);
						for (int m = 0; m < 256; ++m) {
							pw[5] = m;
							recover_prev_key(&recovered[5], k, &recovered[6]);
							for (int n = 0; n < 256; ++n) {
								pw[6] = n;
								recover_prev_key(&recovered[6], k, &recovered[7]);
								if (recover(recovered,
									    pw,
									    7,
									    final->lsbk0_lookup,
									    final->lsbk0_count,
									    &final->internal_rep) < 0) {
									/* not found, go on to the next character */
									continue;
								} else {
									/* found! set global flag and break out */
									set_password_found(final, pw);
									return TPECANCELSIBLINGS;
								}
							}
						}
					}
				}
			}
		}
		c++;
	} while (c < c_end);

	return TPEEXIT;
}

static void init_work_units(struct final_work_unit *unit,
			    size_t len)
{
	size_t nbchar_per_thread = 256 / len;
	size_t rem = 256 % len;

	if (!rem) {
		size_t i;
		int start;
		for (i = 0, start = 0; i < len; ++i, start += nbchar_per_thread) {
			unit[i].start = start;
			unit[i].len = nbchar_per_thread;
		}
	} else {
		int start = 0;
		for (size_t i = 0; i < len; ++i) {
			unit[i].start = start;
			unit[i].len = nbchar_per_thread;
			if (rem) {
				start += nbchar_per_thread + 1;
				unit[i].len++;
				rem--;
			} else
				start += nbchar_per_thread;
		}
	}
}

static int try_key(struct final_private *final, int i)
{
	struct threadpool_ops ops;
	struct final_work_unit *u;
	size_t nbthreads = threadpool_get_nbthreads(final->pool);
	size_t nbunits = 256 < nbthreads ? 256 : nbthreads;

	final->found = false;

	ops.in = final;

	switch (i) {
	case 7: ops.do_work = recover_7; break;
	case 8: ops.do_work = recover_8; break;
	case 9: ops.do_work = recover_9; break;
	case 10: ops.do_work = recover_10; break;
	case 11: ops.do_work = recover_11; break;
	case 12: ops.do_work = recover_12; break;
	case 13: ops.do_work = recover_13; break;
	default:
		/* TODO: panic */
		return -1;
	}

	threadpool_set_ops(final->pool, &ops);

	u = calloc(nbunits, sizeof(struct final_work_unit));
	if (!u) {
		perror("calloc() failed");
		return -1;
	}

	pthread_mutex_init(&final->mutex, NULL);
	init_work_units(u, nbunits);

	threadpool_submit_start(final->pool);
	for (size_t i = 0; i < nbunits; ++i)
		threadpool_submit_work(final->pool, &u[i].list);
	threadpool_submit_end(final->pool);

	threadpool_wait(final->pool);

	pthread_mutex_destroy(&final->mutex);

	return final->found ? i : -1;
}

static int try_key_7_13(struct final_private *f)
{
	int ret;

	for (int i = 7; i <= 13; ++i) {
		ret = try_key(f, i);
		if (ret == i)
			return i;
		else if (ret < 0)
			continue;
	}

	return -1;
}

ZC_EXPORT int zc_crk_ptext_find_password(struct zc_crk_ptext *ptext,
					 const struct zc_key *internal_rep,
					 char *out,
					 size_t len)
{
	struct final_private f;
	int ret;

	if (len < PASS_MAX_LEN)
		return -1;

	if (internal_rep->key0 == KEY0 &&
	    internal_rep->key1 == KEY1 &&
	    internal_rep->key2 == KEY2)
		return 0;               /* password has 0 bytes */

	/* initialise final structure */
	f.lsbk0_lookup = ptext->lsbk0_lookup;
	f.lsbk0_count = ptext->lsbk0_count;
	f.k[0] = *internal_rep;
	f.internal_rep = *internal_rep;
	f.pool = ptext->pool;

	ret = try_key_1_4(&f);
	if (ret > 0)
		goto found;

	reset(&f);
	ret = try_key_5_6(&f);
	if (ret > 0)
		goto found;

	reset(&f);
	ret = try_key_7_13(&f);
	if (ret > 0)
		goto found;

	/* password not found */
	return -1;

found:
	memset(out, 0, len);
	memcpy(out, f.pw, ret);
	return ret;
}
