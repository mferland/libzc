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

#include "list.h"
#include "pool.h"
#include "libzc_private.h"

struct threadpool {
	/*
	 * Queue of active threads. These threads are actively
	 * processing work units.
	 */
	struct list_head active_head;

	/*
	 * Queue of threads that are done executing. These threads are
	 * waiting to be destroyed. The threadpool_wait() function
	 * waits for threads to appear on this queue.
	 */
	struct list_head cleanup_head;

	/*
	 * Queue of idling threads. These threads are waiting for
	 * work, maybe the work queue has not been filled yet, or no
	 * more work is available.
	 */
	struct list_head idle_head;

	/*
	 * Queue of work units to be processed.
	 */
	struct list_head work_head;
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;

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
	/* void *data; */

	pthread_t thread_id;
	struct threadpool *pool;
	uint32_t cancel_siblings : 1;
	uint32_t thread_created : 1;
	int id;

	/*
	 * active/idle/cleanup queue.
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

static void to_active_queue(struct worker *w)
{
	to_queue(w, &w->pool->active_head);
}

static void to_idle_queue(struct worker *w)
{
	to_queue(w, &w->pool->idle_head);
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

static void *worker(void *p)
{
	struct worker *w = (struct worker *)p;
	int ret;

	pthread_cleanup_push(worker_cleanup_handler, w);

	if (wait_workers_created(w->pool) < 0)
		goto end;

	/* TODO: implement thread cancelling, when cancelling threads,
	 * restart them automatically. */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	do {
		pthread_mutex_lock(&w->pool->work_mutex);
		while (list_empty(&w->pool->work_head)) {
			/* no work --> idle */
			to_idle_queue(w);
			pthread_cleanup_push(unlock_work_mutex, w);
			pthread_cond_wait(&w->pool->work_cond, &w->pool->work_mutex);
			pthread_cleanup_pop(0);
		}

		/* work --> active */
		to_active_queue(w);

		/* remove work from the queue */
		struct list_head *work = w->pool->work_head.next;
		list_del(w->pool->work_head.next);
		pthread_cond_broadcast(&w->pool->work_cond);
		pthread_mutex_unlock(&w->pool->work_mutex);

		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
		ret = w->pool->ops->do_work(w->pool->ops->in, work, w->id);
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	} while (ret == TPEMORE);

	if (ret == TPECANCELSIBLINGS)
		w->cancel_siblings = 1;

end:
	pthread_cleanup_pop(1);
	return NULL;
}

static void dealloc_workers(struct threadpool *p)
{
	struct worker *w, *tmp;
	list_for_each_entry_safe(w, tmp, &p->idle_head, list) {
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
	list_for_each_entry(w, &p->idle_head, list) {
		if (pthread_create(&w->thread_id, NULL, worker, w)) {
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
			dealloc_workers(p);
			return -1;
		}
		w->pool = p;
		w->cancel_siblings = 0;
		w->id = i;
		/* workers start off idle */
		list_add(&w->list, &p->idle_head);
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

	INIT_LIST_HEAD(&tmp->active_head);
	INIT_LIST_HEAD(&tmp->cleanup_head);
	INIT_LIST_HEAD(&tmp->idle_head);
	INIT_LIST_HEAD(&tmp->work_head);

	tmp->nbthreads = threads_to_create(nbthreads);

	err = allocate_workers(tmp);
	if (err)
		goto err4;

	err = create_threads(tmp);
	if (err) {
		dealloc_workers(tmp);
		return err;
	}

	*p = tmp;

	return 0;

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
 * Cancel all threads from the idle and active queues. Lock the pool
 * mutex before calling.
 */
static void cancel(struct threadpool *p)
{
	struct worker *w;

	/* workers are either idle or active */
	list_for_each_entry(w, &p->idle_head, list) {
		if (pthread_cancel(w->thread_id))
			fputs("pthread_cancel() failed", stderr);
	}

	list_for_each_entry(w, &p->active_head, list) {
		if (pthread_cancel(w->thread_id))
			fputs("pthread_cancel() failed", stderr);
	}
}

/**
 * Destroy the thread pool.
 */
void threadpool_destroy(struct threadpool *p)
{
	pthread_mutex_lock(&p->mutex);
	cancel(p);
	pthread_mutex_unlock(&p->mutex);

	threadpool_wait(p);

	pthread_cond_destroy(&p->work_cond);
	pthread_mutex_destroy(&p->work_mutex);
	pthread_cond_destroy(&p->cond);
	pthread_mutex_destroy(&p->mutex);
	free(p);
}

int threadpool_set_ops(struct threadpool *p, struct threadpool_ops *ops)
{
	if (!ops->do_work)
		return -1;

	threadpool_wait_idle(p);

	/* now that threads are all waiting for work, change the ops
	   pointer so that the next round of work units will use these
	   new ops. */
	p->ops = ops;
	return 0;
}

/**
 * Wait for threads to appear on the cleanup queue (they finished
 * executing or where cancelled) and join them. The function returns
 * once all threads in the pool have been joined.
 */
void threadpool_wait(struct threadpool *p)
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
				fatal("pthread_join() failed: %s\n", strerror(err));
			if (w->cancel_siblings && left > 1)
				cancel(p);
			free(w);
			--left;
		}
		pthread_mutex_unlock(&p->mutex);
	}

	p->nbthreads_created = 0;
}

/**
 * Restart thread pool.
 */
int threadpool_restart(struct threadpool *p)
{
	int err;

	if (p->nbthreads_created > 0) {
		fputs("threadpool_restart() failed: threads already running",
		      stderr);
		return -1;	/* threads already running */
	}

	err = allocate_workers(p);
	if (err)
		return err;

	err = create_threads(p);
	if (err) {
		dealloc_workers(p);
		return err;
	}

	return 0;
}

/**
 * Wait for all threads to become idle.
 */
void threadpool_wait_idle(struct threadpool *p)
{
	/* wait for work queue to be empty */
	pthread_mutex_lock(&p->work_mutex);
	while (!list_empty(&p->work_head))
		pthread_cond_wait(&p->work_cond, &p->work_mutex);
	pthread_mutex_unlock(&p->work_mutex);

	/* wait for workers that are still working to finish */
	pthread_mutex_lock(&p->mutex);
	while (!list_empty(&p->active_head))
		pthread_cond_wait(&p->cond, &p->mutex);
	pthread_mutex_unlock(&p->mutex);
}

/**
 * Submit work to the thread pool.
 */
void threadpool_submit_work(struct threadpool *p, struct list_head *list)
{
	if (!p->nbthreads_created) {
		if (threadpool_restart(p))
			fatal("threadpool_submit_work() failed\n");
	}
	pthread_mutex_lock(&p->work_mutex);
	list_add_tail(list, &p->work_head);
	pthread_cond_signal(&p->work_cond);
	pthread_mutex_unlock(&p->work_mutex);
}
