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

#include "bitmap.h"
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
	 * Queue of work units waiting to be processed.
	 */
	struct list_head waiting_head;

	/*
	 * Work queue mutex. Used when adding/removing work units.
	 */
	pthread_mutex_t work_mutex;

	/*
	 * Work queue condition variable, used to signal new work
	 * units on the queue.
	 */
	pthread_cond_t work_cond;

	/*
	 * Wait condition variable, used to signal the main thread
	 * when all work units have been processed.
	 */
	pthread_cond_t wait_cond;

	/*
	 * Bitmap of threads that are waiting for work (idle).
	 */
	unsigned long *idle_bitmap;

	/*
	 * Function pointers.
	 */
	struct threadpool_ops *ops;

	/*
	 * Number of threads we were asked to created. <=0 is a special
	 * value here and means automatic (basically, get the number
	 * of online cpus).
	 */
	long nbthreads;

	/*
	 * The actual number of threads created. This number can be
	 * different from nbthreads if, for example, the system is
	 * limited on the number of threads that can be created or the
	 * user passed 0 (automatic) when creating the thread pool.
	 */
	long nbthreads_created;

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

	/*
	 * Only used when 'support_cancel' is false. Indicates that
	 * idling threads can now exit.
	 */
	bool exit_thread;

	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

/*
 * Worker.
 */
struct worker {
	/*
	 * Data/buffers used by each worker.
	 */
	pthread_t thread_id;
	struct threadpool *pool;
	uint32_t cancel_siblings : 1;
	uint32_t thread_created : 1;
	int id;

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

static void unlock_work_mutex(void *p)
{
	struct worker *w = (struct worker *)p;
	pthread_mutex_unlock(&w->pool->work_mutex);
}

/*
 * Returns -1 on error, 1 on success (0 is initial value).
 */
static int wait_workers_created(struct threadpool *p)
{
	pthread_mutex_lock(&p->mutex);
	while (!p->pthread_create_err)
		pthread_cond_wait(&p->cond, &p->mutex);
	pthread_mutex_unlock(&p->mutex);
	return p->pthread_create_err;
}

static bool all_workers_idle(const struct threadpool *pool)
{
	for (int i = 0; i < pool->nbthreads_created; ++i) {
		if (!test_bit(pool->idle_bitmap, i))
			return false;
	}
	return true;
}

static void __work(struct worker *w)
{
	struct threadpool *pool = w->pool;
	struct list_head *work_head = NULL;
	int ret;

	if (wait_workers_created(pool) < 0)
		goto end;

	do {
		pthread_mutex_lock(&pool->work_mutex);

		while (list_empty(&pool->waiting_head)) {
			if (pool->exit_thread) {
				/* main thread indicates that we
				 * should terminate, go ahead and
				 * exit */
				pthread_mutex_unlock(&pool->work_mutex);
				to_cleanup_queue(w);
				pthread_exit(NULL);
			}

			/* mark thread as idle */
			set_bit(pool->idle_bitmap, w->id);

			if (work_head && all_workers_idle(pool))
				/*
				 * - We have the mutex;
				 * - The list is empty;
				 * - All other threads are idling;
				 * - We finished processing the last element (work_head != NULL);
				 *
				 * Signal the main thread that
				 * processing is finished.
				 *
				 * Note: A worker might have been
				 * woken up but never actually
				 * processed any work items. In such a
				 * case, the worker will wake up from
				 * cond_wait, retest the conditions
				 * and go back to sleep (without
				 * sending the signal since the work
				 * pointer is NULL).
				 */
				pthread_cond_signal(&pool->wait_cond);

			work_head = NULL;

			pthread_cond_wait(&pool->work_cond, &pool->work_mutex);

			/* woke up - unmark thread */
			clear_bit(pool->idle_bitmap, w->id);
		}

		work_head = pool->waiting_head.next;
		list_del(pool->waiting_head.next);
		clear_bit(pool->idle_bitmap,
			  w->id); /* got work - unmark thread */
		pthread_mutex_unlock(&pool->work_mutex);

		ret = pool->ops->do_work(pool->ops->in, work_head, w->id);
	} while (ret == TPEMORE);

	to_cleanup_queue(w);

end:
	pthread_exit(NULL);
}

static void *__work_cancel(struct worker *w)
{
	struct threadpool *pool = w->pool;
	int ret;

	/* https://gcc.gnu.org/bugzilla//show_bug.cgi?id=82109 */
	pthread_cleanup_push(worker_cleanup_handler, w);

	if (wait_workers_created(pool) < 0)
		return NULL;

	/* enable deferred cancellation */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	pthread_mutex_lock(&pool->work_mutex);

	while (list_empty(&pool->waiting_head)) {
		if (pool->exit_thread) {
			/* The list is empty (maybe more workers than
			 * work units?) and the exit_thread flag is
			 * set. We can safely assume we will never be
			 * woken up so let's just exit the thread. */
			pthread_mutex_unlock(&pool->work_mutex);
			to_cleanup_queue(w);
			return NULL;
		}

		pthread_cleanup_push(unlock_work_mutex, w);
		pthread_cond_wait(&pool->work_cond, &pool->work_mutex);
		pthread_cleanup_pop(0);
	}

	struct list_head *work_head = pool->waiting_head.next;
	list_del(pool->waiting_head.next);
	pthread_mutex_unlock(&pool->work_mutex);

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	ret = pool->ops->do_work(pool->ops->in, work_head, w->id);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

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
		return __work_cancel(w);
	else {
		__work(w);
		return NULL;
	}
}

static void dealloc_workers(struct threadpool *p)
{
	struct worker *w, *tmp;
	list_for_each_entry_safe(w, tmp, &p->active_head, list) {
		list_del(&w->list);
		free(w);
	}
}

static void broadcast_workers_err(struct threadpool *p, int err)
{
	pthread_mutex_lock(&p->mutex);
	p->pthread_create_err = err;
	pthread_cond_broadcast(&p->cond);
	pthread_mutex_unlock(&p->mutex);
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
			err = pthread_join(w->thread_id, NULL);
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
		if (pthread_create(&w->thread_id, NULL, work, w)) {
			fputs("pthread_create() failed", stderr);
			pthread_mutex_unlock(&p->mutex);
			broadcast_workers_err(p, -1);
			start_fail_cleanup(p);
			return -1;
		}
		++p->nbthreads_created;
	}
	pthread_mutex_unlock(&p->mutex);

	/* success, workers will proceed and go wait for work */
	broadcast_workers_err(p, 1);

	return 0;
}

static int allocate_workers(struct threadpool *p)
{
	for (long i = 0; i < p->nbthreads; ++i) {
		struct worker *w = calloc(1, sizeof(struct worker));
		if (!w) {
			perror("calloc() failed");
			if (i > 0)
				dealloc_workers(p);
			return -1;
		}
		w->pool = p;
		w->cancel_siblings = 0;
		w->id = i;
		clear_bit(p->idle_bitmap, i); /* not idling */
		list_add(&w->list, &p->active_head);
	}
	return 0;
}

/**
 * Allocate new thread pool.
 */
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

	err = pthread_mutex_init(&tmp->work_mutex, NULL);
	if (err)
		goto err3;

	err = pthread_cond_init(&tmp->work_cond, NULL);
	if (err)
		goto err4;

	err = pthread_cond_init(&tmp->wait_cond, NULL);
	if (err)
		goto err5;

	INIT_LIST_HEAD(&tmp->active_head);
	INIT_LIST_HEAD(&tmp->cleanup_head);
	INIT_LIST_HEAD(&tmp->waiting_head);

	tmp->nbthreads = threads_to_create(nbthreads);
	tmp->exit_thread = false;
	tmp->idle_bitmap = bitmap_alloc(tmp->nbthreads);
	if (!tmp->idle_bitmap)
		goto err6;

	*p = tmp;

	return 0;

err6:
	pthread_cond_destroy(&tmp->wait_cond);
err5:
	pthread_cond_destroy(&tmp->work_cond);
err4:
	pthread_mutex_destroy(&tmp->work_mutex);
err3:
	pthread_cond_destroy(&tmp->cond);
err2:
	pthread_mutex_destroy(&tmp->mutex);
err1:
	free(tmp);
	return err;
}

size_t threadpool_get_nbthreads(const struct threadpool *pool)
{
	return pool->nbthreads;
}

/**
 * Cancel all threads.
 */
static void cancel(struct threadpool *p)
{
	struct worker *w;

	list_for_each_entry(w, &p->active_head, list) {
		if (pthread_cancel(w->thread_id))
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
			int err = pthread_join(w->thread_id, NULL);
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

static void quit_idling(struct threadpool *p)
{
	pthread_mutex_lock(&p->work_mutex);
	p->exit_thread = true;
	pthread_cond_broadcast(&p->work_cond);
	pthread_mutex_unlock(&p->work_mutex);

	wait_and_join(p);
	p->exit_thread = false;
}

/**
 * Restart thread pool.
 */
static int restart(struct threadpool *p, bool support_cancel)
{
	int err;

	if (p->nbthreads_created > 0)
		quit_idling(p);

	p->support_cancel = support_cancel;

	err = allocate_workers(p);
	if (err)
		return err;

	err = create_threads(p);
	if (err)
		return err;

	return 0;
}

void threadpool_submit_start(struct threadpool *p, bool support_cancel)
{
	bool must_restart = false;

	/* no threads have been created */
	if (!p->nbthreads_created)
		must_restart = true;

	/* support (or not) cancellation */
	if (p->support_cancel != support_cancel)
		must_restart = true;

	if (must_restart) {
		if (restart(p, support_cancel))
			fatal("threadpool_submit_work() failed\n");
	}

	pthread_mutex_lock(&p->work_mutex);
}

/**
 * Submit work to the thread pool.
 */
void threadpool_submit_work(struct threadpool *p, struct list_head *list)
{
	list_add_tail(list, &p->waiting_head);
}

void threadpool_submit_wait(struct threadpool *p)
{
	if (list_empty(&p->waiting_head))
		fatal("%s called with empty work queue.\n", __func__);

	p->exit_thread = true;
	pthread_cond_broadcast(&p->work_cond);
	pthread_mutex_unlock(&p->work_mutex);
	wait_and_join(p);
	p->exit_thread = false;
}

void threadpool_submit_wait_idle(struct threadpool *p)
{
	if (p->support_cancel)
		fatal("%s called in cancel mode, not supported.\n", __func__);

	if (list_empty(&p->waiting_head))
		fatal("%s called with empty work queue.\n", __func__);

	pthread_cond_broadcast(&p->work_cond);

	while (!all_workers_idle(p) || !list_empty(&p->waiting_head))
		pthread_cond_wait(&p->wait_cond, &p->work_mutex);

	pthread_mutex_unlock(&p->work_mutex);
}

int threadpool_set_ops(struct threadpool *p, struct threadpool_ops *ops)
{
	if (!ops->do_work)
		return -1;

	/* now that threads are all waiting for work, change the ops
	   pointer so that the next round of work units will use these
	   new ops. */
	p->ops = ops;
	return 0;
}

/**
 * Destroy the thread pool.
 */
void threadpool_destroy(struct threadpool *p)
{
	quit_idling(p);

	pthread_cond_destroy(&p->work_cond);
	pthread_cond_destroy(&p->wait_cond);
	pthread_mutex_destroy(&p->work_mutex);
	pthread_cond_destroy(&p->cond);
	pthread_mutex_destroy(&p->mutex);
	bitmap_free(p->idle_bitmap);
	free(p);
}
