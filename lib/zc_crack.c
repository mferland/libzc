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

static inline void update_keys(char c, struct encryption_keys *k)
{
   k->key0 = crc32(k->key0, c);
   k->key1 = (k->key1 + (k->key0 & 0x000000ff)) * 134775813 + 1;
   k->key2 = crc32(k->key2, k->key1 >> 24);
}

static inline void init_encryption_keys(const char *pw, struct encryption_keys *k)
{
   int i = 0;

   k->key0 = KEY0;
   k->key1 = KEY1;
   k->key2 = KEY2;

   while (pw[i] != '\0')
   {
      update_keys(pw[i], k);
      ++i;
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

ZC_EXPORT bool zc_crack(const char *pw, const struct zc_validation_data *vdata, size_t nmemb)
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
