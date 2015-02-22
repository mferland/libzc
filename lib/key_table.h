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

#ifndef _KEY_TABLE_H_
#define _KEY_TABLE_H_

#include <stdlib.h>             /* size_t */
#include <stdio.h>
#include <stdint.h>

struct key_table {
    uint32_t *array;
    size_t size;
    size_t capacity;
};

int key_table_new(struct key_table **table, size_t initial_size);
void key_table_free(struct key_table *table);
void key_table_append(struct key_table *table, uint32_t key);
void key_table_uniq(struct key_table *table);
void key_table_squeeze(struct key_table *table);
void key_table_empty(struct key_table *table);
void key_table_print(struct key_table *table, FILE *stream);

static inline
uint32_t key_table_at(const struct key_table *table, uint32_t index)
{
    return table->array[index];
}

static inline
void key_table_swap(struct key_table **table1, struct key_table **table2)
{
    struct key_table *tmp = *table1;
    *table1 = *table2;
    *table2 = tmp;
}

#endif /* _KEY_TABLE_H_ */
