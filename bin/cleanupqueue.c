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

struct cleanup_queue {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct cleanup_node *head;
    struct cleanup_node *tail;
};

static void queue_put(struct cleanup_queue *root, struct cleanup_node *node)
{
    node->next = NULL;
    if (root->tail)
        root->tail->next = node;
    root->tail = node;
    if (!root->head)
        root->head = node;
}

static struct cleanup_node *queue_get(struct cleanup_queue *root)
{
    struct cleanup_node *node;
    node = root->head;
    if (root->head) {
        root->head = root->head->next;
        if (!root->head)
            root->tail = NULL;
    }
    return node;
}

int cleanup_queue_new(struct cleanup_queue **cq)
{
    struct cleanup_queue *new_cq = NULL;
    int err;

    new_cq = calloc(1, sizeof(struct cleanup_queue));
    if (!new_cq)
        return ENOMEM;

    err = pthread_mutex_init(&new_cq->mutex, NULL);
    if (err) {
        free(new_cq);
        return err;
    }

    err = pthread_cond_init(&new_cq->cond, NULL);
    if (err) {
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
    free(cq);
}

void cleanup_queue_put(struct cleanup_queue *cq, struct cleanup_node *node)
{
    pthread_mutex_lock(&cq->mutex);
    queue_put(cq, node);
    pthread_cond_signal(&cq->cond);
    pthread_mutex_unlock(&cq->mutex);
}

static void cancel_active_threads(struct cleanup_node *array, size_t size)
{
    size_t i;

    for (i = 0; i < size; ++i) {
        if (!array[i].active)
            continue;
        pthread_cancel(array[i].thread_id);
    }
}

void cleanup_queue_wait(struct cleanup_queue *cq, struct cleanup_node *node_array, size_t size)
{
    struct cleanup_node *node;
    int nodes_left = size;

    if (size == 0)
        return;                   /* nothing to do */

    while (nodes_left) {
        pthread_mutex_lock(&cq->mutex);
        while (!cq->head)
            pthread_cond_wait(&cq->cond, &cq->mutex);
        node = queue_get(cq);
        node->active = false;
        if (node->found)
            cancel_active_threads(node_array, size);
        pthread_mutex_unlock(&cq->mutex);
        pthread_join(node->thread_id, NULL);
        --nodes_left;
    }
}
