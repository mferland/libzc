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
   struct zc_ctx *ctx;
   int refcount;
   char *char_set;
   size_t max_pw_len;
   int step;
   char *pw;
   char *pw_indexes;
};

static void init_indexes_from_pw(struct zc_pwgen *gen);

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
   free(pwgen->char_set);
   free(pwgen->pw);
   free(pwgen->pw_indexes);
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

ZC_EXPORT int zc_pwgen_init(struct zc_pwgen *gen, const char *char_set, size_t max_pw_len)
{
   char *char_set_tmp = NULL;
   char *pw_tmp = NULL;
   char *pw_indexes_tmp = NULL;
   
   if (strlen(char_set) == 0)
      return EINVAL;
   
   if (max_pw_len == 0)
      return EINVAL;

   char_set_tmp = strdup(char_set);
   if (char_set_tmp == NULL)
      return ENOMEM;

   pw_tmp = calloc(1, max_pw_len + 1);
   if (!pw_tmp)
      goto cleanup_error;

   pw_indexes_tmp = calloc(1, max_pw_len);
   if (!pw_indexes_tmp)
      goto cleanup_error;

   gen->char_set = char_set_tmp;
   gen->pw = pw_tmp;
   gen->pw_indexes = pw_indexes_tmp;
   gen->max_pw_len = max_pw_len;
   return 0;

cleanup_error:
   if (char_set_tmp)
      free(char_set_tmp);
   if (pw_tmp)
      free(pw_tmp);
   if (pw_indexes_tmp)
      free(pw_indexes_tmp);
   return ENOMEM;
}

ZC_EXPORT int zc_pwgen_reset(struct zc_pwgen *gen, const char *pw)
{
   if (strlen(pw) > gen->max_pw_len)
      return EINVAL;
   strcpy(gen->pw, pw);
   init_indexes_from_pw(gen);
   dbg(gen->ctx, "password reset to: %s\n", pw);
   return 0;
}

static void init_indexes_from_pw(struct zc_pwgen *gen)
{
   const size_t len = strlen(gen->pw);
   size_t i;

   for (i = 0; i < len; ++i)
      gen->pw_indexes[i] = strchr(gen->char_set, gen->pw[i]) - gen->char_set;
}

ZC_EXPORT void zc_pwgen_set_step(struct zc_pwgen *gen, unsigned int step)
{
   gen->step = step;
}

ZC_EXPORT const char *zc_pwgen_generate(struct zc_pwgen *gen)
{
   /* const size_t pw_char_index = strlen(gen->pw) - 1; */
   /* int quotient = gen->step; */
   
   /* while (1) */
   /* { */
   /*    new_pw_char_index = (gen->pw_indexes[pw_char_index] + quotient) % gen->char_set_len; */
   /*    quotient = (gen->pw_indexes[pw_char_index] + quotient) / gen->char_set_len; */

   /*    /\* update current character *\/ */
   /*    gen->pw[pw_char_index] = gen->char_set[new_pw_char_index]; */
   /*    gen->pw_indexes[pw_char_index] = new_pw_char_index; */

   /*    if (pw_char_index == 0 && quotient > 0) */
   /*    { */
         
   /*    } */

   /*    if (quotient == 0) */
   /*       break; */

   /*    --pw_char_index; */
      
   /* } */
   /* return NULL; */
   /* TODO */
   return NULL;
}
