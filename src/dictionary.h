/*
 *  yazc - ZIP password recovery application
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

#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <stddef.h>

struct zc_crk_dict;

void zc_crk_dict_destroy(struct zc_crk_dict *crk);
int zc_crk_dict_new(struct zc_crk_dict **crk);
int zc_crk_dict_init(struct zc_crk_dict *crk, const char *filename);
int zc_crk_dict_start(struct zc_crk_dict *crk, const char *dict, char *pw,
		      size_t len);

#endif /* DICTIONARY_H */
