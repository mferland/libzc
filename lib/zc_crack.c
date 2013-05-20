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

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "crc32.h"
#include "zip.h"
#include "libzc.h"
#include "libzc_private.h"

#define KEY0 0x12345678
#define KEY1 0x23456789
#define KEY2 0x34567890

struct encryption_keys
{
   unsigned int key0;
   unsigned int key1;
   unsigned int key2;
};

struct zc_cracker
{
   struct zc_pwgen *gen;
   struct encryption_keys key;
   struct zc_validation_data *vdata;
   size_t vdata_size;
   struct zc_ctx *ctx;
   int refcount;
};

static inline void update_keys(char c, struct encryption_keys *k)
{
   k->key0 = crc32(k->key0, c);
   k->key1 = (k->key1 + (k->key0 & 0x000000ff)) * 134775813 + 1;
   k->key2 = crc32(k->key2, k->key1 >> 24);
}

static inline void set_default_encryption_keys(struct encryption_keys *k)
{
   k->key0 = KEY0;
   k->key1 = KEY1;
   k->key2 = KEY2;
}

static inline void init_encryption_keys(const char *pw, struct encryption_keys *k)
{
   int i = 0;
   set_default_encryption_keys(k);
   while (pw[i] != '\0')
   {
      update_keys(pw[i], k);
      ++i;
   }
}

static inline void init_encryption_keys_from_base(const char *pw, struct encryption_keys *key_table,
                                                  struct encryption_keys *k, size_t idem_char)
{
   if (idem_char == 0)
      set_default_encryption_keys(k);
   else
   {
      k->key0 = key_table[idem_char - 1].key0;
      k->key1 = key_table[idem_char - 1].key1;
      k->key2 = key_table[idem_char - 1].key2;
   }
   while (pw[idem_char] != '\0')
   {
      update_keys(pw[idem_char], k);
      key_table[idem_char].key0 = k->key0;
      key_table[idem_char].key1 = k->key1;
      key_table[idem_char].key2 = k->key2;
      ++idem_char;
   }
}

static inline void reset_encryption_keys(const struct encryption_keys *base, struct encryption_keys *key)
{
   key->key0 = base->key0;
   key->key1 = base->key1;
   key->key2 = base->key2;
}

static inline unsigned char decrypt_byte(unsigned int key)
{
   key |= 2;
   return ((key * (key ^ 1)) >> 8);
}

static inline unsigned char decrypt_header(const unsigned char *encrypted_header, struct encryption_keys *k)
{
   int i;
   unsigned char c;

   for (i = 0; i < ZIP_ENCRYPTION_HEADER_LENGTH; ++i)
   {
      c = encrypted_header[i] ^ decrypt_byte(k->key2);
      update_keys(c, k);
   }

   /* Returns the last byte of the decrypted header */
   return c;
}

ZC_EXPORT bool zc_cracker_test_one_pw(const char *pw, const struct zc_validation_data *vdata, size_t nmemb)
{
   struct encryption_keys key;
   struct encryption_keys base_key;
   size_t i;

   init_encryption_keys(pw, &base_key);
   for (i = 0; i < nmemb; ++i)
   {
      reset_encryption_keys(&base_key, &key);
      if (decrypt_header(vdata[i].encryption_header, &key) == vdata[i].magic)
         continue;
      return false;
   }
   return true;
}

ZC_EXPORT int zc_cracker_new(struct zc_ctx *ctx, struct zc_cracker **crk)
{
   struct zc_cracker *newcrk;

   newcrk = calloc(1, sizeof(struct zc_cracker));
   if (!newcrk)
      return ENOMEM;

   newcrk->ctx = ctx;
   newcrk->refcount = 1;
   *crk = newcrk;
   dbg(ctx, "cracker %p created\n", newcrk);
   return 0;
}

ZC_EXPORT struct zc_cracker *zc_cracker_ref(struct zc_cracker *crk)
{
   if (!crk)
      return NULL;
   crk->refcount++;
   return crk;
}

ZC_EXPORT struct zc_cracker *zc_cracker_unref(struct zc_cracker *crk)
{
   if (!crk)
      return NULL;
   crk->refcount--;
   if (crk->refcount > 0)
      return crk;
   dbg(crk->ctx, "cracker %p released\n", crk);
   zc_pwgen_unref(crk->gen);
   free(crk);
   return NULL;
}

ZC_EXPORT int zc_cracker_set_pwgen(struct zc_cracker *crk, struct zc_pwgen *pwgen)
{
   if (pwgen == NULL)
      return EINVAL;
   crk->gen = zc_pwgen_ref(pwgen);
   return 0;
}

ZC_EXPORT int zc_cracker_set_vdata(struct zc_cracker *crk, struct zc_validation_data *vdata, size_t nmemb)
{
   if (vdata == NULL)
      return EINVAL;
   if (nmemb == 0)
      return EINVAL;
   crk->vdata = vdata;
   crk->vdata_size = nmemb;
   return 0;
}

static bool is_valid_cracker(struct zc_cracker *crk)
{
   /* invalid arguments */
   if (crk->gen == NULL || crk->vdata == NULL)
      return false;

   if (!zc_pwgen_is_initialized(crk->gen))
      return false;
   return true;
}

ZC_EXPORT int zc_cracker_start(struct zc_cracker *crk, char *out_pw, size_t out_pw_size)
{
   struct encryption_keys base_key = { .key0 = 0, .key1 = 0, .key2 = 0};
   struct encryption_keys key_table[8]; // TODO: use a big enough table here
   const char *pw;
   size_t idem_char = 0;
   bool found = false;
   
   if (out_pw == NULL || !is_valid_cracker(crk))
      return EINVAL;

   pw = zc_pwgen_pw(crk->gen);
   do
   {
      init_encryption_keys_from_base(pw, key_table, &base_key, idem_char);
      found = true;
      for (size_t i = 0; i < crk->vdata_size; ++i)
      {
         reset_encryption_keys(&base_key, &crk->key);
         if (decrypt_header(crk->vdata[i].encryption_header, &crk->key) == crk->vdata[i].magic)
            continue;
         found = false;
         break;
      }

      if (found)
      {
         memset(out_pw, 0, out_pw_size);
         strncpy(out_pw, pw, out_pw_size - 1);
         break;
      }
      
      pw = zc_pwgen_generate(crk->gen, &idem_char);
   } while (pw != NULL);

   return found == true ? 0 : -1;
}

ZC_EXPORT int zc_cracker_restart(struct zc_cracker *crk, char *out_pw, size_t out_pw_size)
{
   size_t tmp;
   if (!is_valid_cracker(crk))
      return EINVAL;
   zc_pwgen_generate(crk->gen, &tmp);
   return zc_cracker_start(crk, out_pw, out_pw_size);
}
