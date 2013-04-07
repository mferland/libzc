/*
 *  zc - zip crack library
 *  Copyright (C) 2009  Marc Ferland
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
#include <errno.h>
#include <string.h>

#include "libzc.h"
#include "libzc_private.h"

struct zc_pwgen
{
   char *pw;
   char *char_lut;
   char *char_ascii;
   char *char_indexes;
   size_t max_pw_len;
   size_t char_lut_len;
   int step;
   struct zc_ctx *ctx;
   int refcount;
};

static void init_char_indexes(struct zc_pwgen *gen, const char *pw, size_t len);
static void init_char_ascii(struct zc_pwgen *gen, const char *pw, size_t len);

ZC_EXPORT struct zc_pwgen *zc_pwgen_ref(struct zc_pwgen *pwgen)
{
   if (!pwgen)
      return NULL;
   pwgen->refcount++;
   return pwgen;
}

ZC_EXPORT struct zc_pwgen *zc_pwgen_unref(struct zc_pwgen *pwgen)
{
   if (!pwgen)
      return NULL;
   pwgen->refcount--;
   if (pwgen->refcount > 0)
      return pwgen;
   dbg(pwgen->ctx, "pwgen %p released\n", pwgen);
   free(pwgen->char_lut);
   free(pwgen->char_ascii);
   free(pwgen->char_indexes);
   free(pwgen);
   return NULL;
}

ZC_EXPORT int zc_pwgen_new(struct zc_ctx *ctx, struct zc_pwgen **pwgen)
{
   struct zc_pwgen *newpwgen;

   newpwgen = calloc(1, sizeof(struct zc_pwgen));
   if (!newpwgen)
      return ENOMEM;

   newpwgen->ctx = ctx;
   newpwgen->refcount = 1;
   *pwgen = newpwgen;
   dbg(ctx, "pwgen %p created\n", newpwgen);
   return 0;
}

ZC_EXPORT int zc_pwgen_init(struct zc_pwgen *gen, const char *char_lut, size_t max_pw_len)
{
   const size_t lut_len = strlen(char_lut);
   char *char_lut_tmp = NULL;
   char *char_ascii_tmp = NULL;
   char *char_indexes_tmp = NULL;

   if (lut_len == 0)
      return EINVAL;

   if (max_pw_len == 0)
      return EINVAL;

   char_lut_tmp = strdup(char_lut);
   if (char_lut_tmp == NULL)
      return ENOMEM;

   char_ascii_tmp = calloc(1, max_pw_len + 1);
   if (!char_ascii_tmp)
      goto cleanup_error;

   char_indexes_tmp = calloc(1, max_pw_len);
   if (!char_indexes_tmp)
      goto cleanup_error;

   gen->char_lut = char_lut_tmp;
   gen->char_lut_len = lut_len;
   gen->char_ascii = char_ascii_tmp;
   gen->char_indexes = char_indexes_tmp;
   gen->max_pw_len = max_pw_len;
   return 0;

cleanup_error:
   if (char_lut_tmp)
      free(char_lut_tmp);
   if (char_ascii_tmp)
      free(char_ascii_tmp);
   if (char_indexes_tmp)
      free(char_indexes_tmp);
   return ENOMEM;
}

ZC_EXPORT int zc_pwgen_reset(struct zc_pwgen *gen, const char *pw)
{
   const size_t len = strlen(pw);

   if (len > gen->max_pw_len)
      return EINVAL;

   init_char_ascii(gen, pw, len);
   init_char_indexes(gen, pw, len);

   dbg(gen->ctx, "password reset to: %s\n", pw);
   return 0;
}

static void init_char_ascii(struct zc_pwgen *gen, const char *pw, size_t len)
{
   gen->pw = gen->char_ascii + gen->max_pw_len - len;
   strncpy(gen->pw, pw, len);
}

static void init_char_indexes(struct zc_pwgen *gen, const char *pw, size_t len)
{
   const size_t first_valid_index = gen->max_pw_len - len;
   size_t i;

   for (i = 0; i < first_valid_index; ++i)
      gen->char_indexes[i] = -1;

   for (i =  first_valid_index; i < len; ++i)
      gen->char_indexes[i] = strchr(gen->char_lut, gen->pw[i]) - gen->char_lut;
}

ZC_EXPORT void zc_pwgen_set_step(struct zc_pwgen *gen, unsigned int step)
{
   gen->step = step;
}

ZC_EXPORT const char *zc_pwgen_generate(struct zc_pwgen *gen)
{
   size_t pw_char_index = gen->max_pw_len - 1;
   int quotient = gen->step;

   while (1)
   {
      gen->char_indexes[pw_char_index] += quotient;
      quotient = gen->char_indexes[pw_char_index] / gen->char_lut_len;
      gen->char_indexes[pw_char_index] %= gen->char_lut_len;

      gen->char_ascii[pw_char_index] = gen->char_lut[(unsigned char)gen->char_indexes[pw_char_index]];

      if (pw_char_index == 0 && quotient > 0)
         return NULL;           /* overflow */

      if (quotient == 0)
         break;

      --pw_char_index;

      if (pw_char_index < (size_t)(gen->pw - gen->char_ascii))
      {
         gen->pw = &gen->char_ascii[pw_char_index];
      }
   }

   dbg(gen->ctx, "generated password: %s\n", gen->pw);
   return gen->pw;
}

ZC_EXPORT const char *zc_pwgen_pw(const struct zc_pwgen *gen)
{
   return gen->pw;
}
