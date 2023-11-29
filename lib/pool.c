/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2019 Marc Ferland
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "list.h"
#include "pool.h"
#include "libzc_private.h"

struct threadpool {
	/*
	 * Queue of active threads. These threads are ready
	 * or are currently processing work.
	 */
	struct list_head active_head;

	/*
	 * Queue of threads that are done executing. These threads are
	 * waiting to be joined. The wait_and_join() function waits
	 * for threads to appear on this queue.
	 */
	struct list_head cleanup_head;

	/*
	 * Function pointers.
	 */
	struct threadpool_ops *ops;

	/*
	 * Number of threads we were asked to create. <=0 is a special
	 * value here and means automatic (basically, get the number
	 * of online cpus).
	 */
	long nbthreads_default;

	/*
	 * The actual number of threads created. Used in case an error is encountered while allocating workers.
	 */
	long nbthreads_created, next_nbthreads;

	/*
	 * State of thread creation.
	 *
	 * -1: Thread creation failed. Threads will exit and call the
	 *     cleanup handler.
	 *  0: Default value. Threads creation not yet finished.
	 *  1: Thread creation successful. Threads will start working.
	 */
	int pthread_create_err;

	/*
	 * Indicates whether or not the threads support
	 * cancellation. Description of each mode:
	 *
	 * - If support_cancel is 'true', the thread will wait for
	 *   work units to appear on the work queue, if cancelled the
	 *   thread will move to the cleanup queue and signal the main
	 *   thread. In this mode, the thread will exit when the
	 *   do_work() function returns.
	 *
	 * - If support_cancel in 'false', the thread will wait for
	 *   work units to appear on the work queue. Since threads
	 *   cannot be cancelled, the main thread has to wait for all
	 *   threads to be idle and then set the 'exit_thread' flag
	 *   signalling to the idling threads that they should now
	 *   exit (i.e.: call pthread_exit()). In this mode, the
	 *   threads will return waiting for more work when the work
	 *   queue is empty.
	 */
	bool support_cancel;

	size_t next_worker_index;

	/* struct worker *next_worker; */

	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_barrier_t barrier;
};

struct worker {
	pthread_t id;
	int idx;
	uint32_t cancel_siblings : 1;
	uint32_t thread_created : 1;
	struct threadpool *pool;

	/*
	 * Queue of work units waiting to be processed.
	 */
	struct list_head waiting_head;

	/*
	 * active/cleanup queue.
	 */
	struct list_head list;
};

static void to_queue(struct worker *w, struct list_head *dest)
{
	pthread_mutex_lock(&w->pool->mutex);
	list_move(&w->list, dest);
	pthread_cond_signal(&w->pool->cond);
	pthread_mutex_unlock(&w->pool->mutex);
}

static void to_cleanup_queue(struct worker *w)
{
	to_queue(w, &w->pool->cleanup_head);
}

static void worker_cleanup_handler(void *p)
{
	struct worker *w = (struct worker *)p;
	to_cleanup_queue(w);
}

size_t threadpool_get_nbthreads(const struct threadpool *p)
{
	if (p->nbthreads_default < 1)
		return threads_to_create(p->nbthreads_default);
	return p->nbthreads_default;
}

int threadpool_new(struct threadpool **p, long nbthreads)
{
	struct threadpool *tmp;
	int err;

	tmp = calloc(1, sizeof(struct threadpool));
	if (!tmp) {
		perror("calloc() failed");
		return -1;
	}

	err = pthread_mutex_init(&tmp->mutex, NULL);
	if (err)
		goto err1;

	err = pthread_cond_init(&tmp->cond, NULL);
	if (err)
		goto err2;

	tmp->nbthreads_default = nbthreads;

	INIT_LIST_HEAD(&tmp->active_head);
	INIT_LIST_HEAD(&tmp->cleanup_head);

	*p = tmp;

	return 0;

err2:
	pthread_mutex_destroy(&tmp->mutex);
err1:
	free(tmp);
	return err;
}

void threadpool_destroy(struct threadpool *p)
{
	/* pthread_barrier_destroy(&p->barrier); */
	pthread_cond_destroy(&p->cond);
	pthread_mutex_destroy(&p->mutex);
	free(p);
}

int threadpool_set_ops(struct threadpool *p, struct threadpool_ops *ops)
{
	if (!ops->do_work)
		return -1;

	/*
	 * Now that threads are all waiting for work, change the ops
	 * pointer so that the next round of work units will use these
	 * new ops.
	 */
	p->ops = ops;
	return 0;
}

static void *_work(struct worker *w)
{
	struct threadpool *pool = w->pool;
	int ret = TPEMORE;

	/* wait on barrier, when barrier unlocks, it means work items
	 * are ready to be processed. */
	/* pthread_barrier_wait(&pool->barrier); */

	while (ret == TPEMORE && !list_empty(&w->waiting_head)) {
		struct list_head *work_head = w->waiting_head.next;
		list_del(w->waiting_head.next);
		ret = pool->ops->do_work(pool->ops->in, work_head, w->idx);
	}

	/* migrate thread to cleanup queue and wait for join() */
	to_cleanup_queue(w);

	return NULL;
}

static void *_work_cancel(struct worker *w)
{
	struct threadpool *pool = w->pool;
	int ret;

	/* https://gcc.gnu.org/bugzilla//show_bug.cgi?id=82109 */
	pthread_cleanup_push(worker_cleanup_handler, w);

	/* enable deferred cancellation */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	/* wait on barrier, when barrier unlocks, it means work items
	 * are ready to be processed. */
	pthread_barrier_wait(&pool->barrier);

	ret = TPEMORE;
	while (ret == TPEMORE && !list_empty(&w->waiting_head)) {
		struct list_head *work_head = w->waiting_head.next;
		list_del(w->waiting_head.next);
		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
		ret = pool->ops->do_work(pool->ops->in, work_head, w->idx);
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	}

	if (ret == TPECANCELSIBLINGS) {
		pthread_mutex_lock(&pool->mutex);
		w->cancel_siblings = 1;
		pthread_mutex_unlock(&pool->mutex);
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static void *work(void *p)
{
	struct worker *w = (struct worker *)p;

	if (w->pool->support_cancel)
		return _work_cancel(w);
	else
		return _work(w);
}

static void dealloc_workers(struct threadpool *p)
{
	struct worker *w, *tmp;
	list_for_each_entry_safe(w, tmp, &p->active_head, list) {
		list_del(&w->list);
		free(w);
	}
}

static void start_fail_cleanup(struct threadpool *p)
{
	long left = p->nbthreads_created;
	int err;

	while (left) {
		pthread_mutex_lock(&p->mutex);
		while (list_empty(&p->cleanup_head))
			pthread_cond_wait(&p->cond, &p->mutex);
		struct worker *w, *tmp;
		list_for_each_entry_safe(w, tmp, &p->cleanup_head, list) {
			list_del(&w->list);
			err = pthread_join(w->id, NULL);
			if (err)
				fatal("pthread_join() failed: %s\n",
				      strerror(err));
			free(w);
			--left;
		}
		pthread_mutex_unlock(&p->mutex);
	}

	/* delete workers for which a thread was not created */
	dealloc_workers(p);
}

static int create_threads(struct threadpool *p)
{
	struct worker *w;

	p->nbthreads_created = 0;

	pthread_mutex_lock(&p->mutex);
	p->pthread_create_err = 0;
	list_for_each_entry(w, &p->active_head, list) {
		if (pthread_create(&w->id, NULL, work, w)) {
			fputs("pthread_create() failed", stderr);
			pthread_mutex_unlock(&p->mutex);
			start_fail_cleanup(p);
			return -1;
		}
		++p->nbthreads_created;
	}
	pthread_mutex_unlock(&p->mutex);

	return 0;
}

static int allocate_workers(struct threadpool *p, long nbthreads)
{
	for (long i = 0; i < nbthreads; ++i) {
		struct worker *w = calloc(1, sizeof(struct worker));
		if (!w) {
			perror("calloc() failed");
			if (i > 0)
				dealloc_workers(p);
			return -1;
		}
		w->pool = p;
		w->idx = i;
		w->cancel_siblings = 0;
		INIT_LIST_HEAD(&w->waiting_head);
		list_add(&w->list, &p->active_head);
	}
	return 0;
}

/**
 * Cancel all threads.
 */
static void cancel(struct threadpool *p)
{
	struct worker *w;

	list_for_each_entry(w, &p->active_head, list) {
		if (pthread_cancel(w->id))
			fputs("pthread_cancel() failed", stderr);
	}
}

/**
 * Wait for threads to appear on the cleanup queue (they finished
 * executing or where cancelled) and join them. The function returns
 * once all threads in the pool have been joined.
 */
static void wait_and_join(struct threadpool *p)
{
	long left = p->nbthreads_created;

	while (left) {
		pthread_mutex_lock(&p->mutex);
		while (list_empty(&p->cleanup_head))
			pthread_cond_wait(&p->cond, &p->mutex);
		struct worker *w, *tmp;
		list_for_each_entry_safe(w, tmp, &p->cleanup_head, list) {
			list_del(&w->list);
			int err = pthread_join(w->id, NULL);
			if (err)
				fatal("pthread_join() failed: %s\n",
				      strerror(err));
			if (w->cancel_siblings && left > 1) {
				w->cancel_siblings = 0;
				cancel(p);
			}
			free(w);
			--left;
		}
		pthread_mutex_unlock(&p->mutex);
	}

	p->nbthreads_created = 0;
}

/* TODO: passer un facteur de scaling? */
/* TODO: remove parameter support_cancel? or set the parameter each time. */
void threadpool_submit_start_scale(struct threadpool *p, bool support_cancel,
				   long nbthreads)
{
	long max_threads;

	if (p->nbthreads_default < 1) {
		/* by default, use auto scale */
		max_threads = threads_to_create(0);
	} else {
		/* use parameter passed by user */
		max_threads = p->nbthreads_default;
	}

	if (nbthreads < 1)
		nbthreads = max_threads;
	else if (nbthreads > max_threads)
		fatal("cannot create more than %ld threads", max_threads);

	if (support_cancel) {
		int err = pthread_barrier_init(&p->barrier, NULL, nbthreads + 1);
		if (err)
			fatal("pthread_barrier_init() failed: %s\n",
			      strerror(err));
	}

	p->next_worker_index = 0;
	p->next_nbthreads = nbthreads;

	allocate_workers(p, nbthreads);
}

void threadpool_submit_start(struct threadpool *p, bool support_cancel)
{
	threadpool_submit_start_scale(p, support_cancel, p->nbthreads_default);
}

/**
 * Submit work to the thread pool.
 */
void threadpool_submit_work(struct threadpool *p, struct list_head *list)
{
	struct worker *w;
	size_t i = 0;

	list_for_each_entry(w, &p->active_head, list) {
		if (i == p->next_worker_index) {
			list_add_tail(list, &w->waiting_head);
			break;
		}
		++i;
	}

	p->next_worker_index = (p->next_worker_index + 1) % p->next_nbthreads;
}

void threadpool_submit_wait(struct threadpool *p)
{
	if (create_threads(p))
		fatal("create_threads failed\n");

	/* indicates that we are ready, all of the other threads can
	 * now proceed */
	if (p->support_cancel)
		pthread_barrier_wait(&p->barrier);

	wait_and_join(p);

	if (p->support_cancel)
		pthread_barrier_destroy(&p->barrier);
}
