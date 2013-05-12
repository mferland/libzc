/*
 *  yazc - Yet Another Zip Cracker
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

#ifndef _CLEANUPQUEUE_H_
#define _CLEANUPQUEUE_H_

#include <stdbool.h>

#include "libzc.h"

struct cleanup_queue;

struct cleanup_node
{
   struct cleanup_node *next;
   pthread_t thread_id;
   int thread_num;
   bool found;
   bool active;
   struct zc_pwgen *pwgen;
};

int cleanup_queue_new(struct cleanup_queue **cq);
void cleanup_queue_destroy(struct cleanup_queue *cq);
void cleanup_queue_put(struct cleanup_queue *cq, struct cleanup_node *node);
int cleanup_queue_wait(struct cleanup_queue *cq, struct cleanup_node *node_array, size_t size);

#endif /* _CLEANUPQUEUE_H_ */
