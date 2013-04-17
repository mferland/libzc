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

#include <pthread.h>
#include <stdlib.h>
#include <errno.h>

#include "cleanupqueue.h"

struct cleanup_node
{
   struct cleanup_node *next;
   pthread_t tid;
};

struct cleanup_queue
{
   pthread_mutex_t mutex;
   pthread_cond_t cond;
   struct cleanup_node *head;
   struct cleanup_node *tail;
};

static void queue_put(struct cleanup_queue *root, struct cleanup_node *node)
{
   node->next = NULL;
   if (root->tail != NULL)
      root->tail->next = node;
   root->tail = node;
   if (root->head == NULL)
      root->head = node;
}

static struct cleanup_node *queue_get(struct cleanup_queue *root)
{
   struct cleanup_node* node;
   node = root->head;
   if (root->head != NULL)
   {
      root->head = root->head->next;
      if (root->head == NULL)
         root->tail = NULL;
   }
   return node;
}

int cleanup_node_new(struct cleanup_node **node, pthread_t tid)
{
   struct cleanup_node *n;

   n = calloc(1, sizeof(struct cleanup_node));
   if (n == NULL)
      return ENOMEM;

   n->tid = tid;
   *node = n;
   return 0;
}

int cleanup_queue_new(struct cleanup_queue **cq)
{
   struct cleanup_queue *new_cq = NULL;
   int err;

   new_cq = calloc(1, sizeof(struct cleanup_queue));
   if (!new_cq)
      return ENOMEM;

   err = pthread_mutex_init(&new_cq->mutex, NULL);
   if (err)
   {
      free(new_cq);
      return err;
   }

   err = pthread_cond_init(&new_cq->cond, NULL);
   if (err)
   {
      pthread_mutex_destroy(&new_cq->mutex);
      free(new_cq);
      return err;
   }

   new_cq->head = NULL;
   new_cq->tail = NULL;
   *cq = new_cq;
   
   return 0;
}

void cleanup_queue_destroy(struct cleanup_queue *cq)
{
   pthread_cond_destroy(&cq->cond);
   pthread_mutex_destroy(&cq->mutex);
}

void cleanup_queue_put(struct cleanup_queue *cq, struct cleanup_node *node)
{
   pthread_mutex_lock(&cq->mutex);
   queue_put(cq, node);
   pthread_cond_signal(&cq->cond);
   pthread_mutex_unlock(&cq->mutex);
}

void cleanup_queue_wait(struct cleanup_queue *cq, size_t num)
{
   struct cleanup_node *node;

   while (num)
   {
      pthread_mutex_lock(&cq->mutex);
      while (cq->head == NULL)
         pthread_cond_wait(&cq->cond, &cq->mutex);
      node = queue_get(cq);
      pthread_mutex_unlock(&cq->mutex);
      pthread_join(node->tid, NULL);
      free(node);
      --num;
   }
}
