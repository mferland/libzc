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

#include "libzc.h"
#include "libzc_private.h"

struct zc_pwgen
{
   struct zc_ctx *ctx;
   int refcount;
};

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

ZC_EXPORT int zc_pwgen_init(struct zc_pwgen *gen, const unsigned char *char_set, unsigned int max_pw_len)
{
   return 0;
}

ZC_EXPORT int zc_pwgen_reset(struct zc_pwgen *gen, const unsigned char *pw)
{
   return 0;
}

ZC_EXPORT void zc_pwgen_set_step(struct zc_pwgen *gen, unsigned int step)
{
}

ZC_EXPORT const char *zc_pwgen_generate(struct zc_pwgen *gen)
{
   return NULL;
}
