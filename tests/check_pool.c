/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "libzc_private.h"
#include "pool.h"

START_TEST(test_new_destroy)
{
	struct threadpool *pool = NULL;
	int err;

	err = threadpool_new(&pool, -1);
	ck_assert_int_eq(err, 0);
	ck_assert(pool != NULL);
	threadpool_cancel(pool);
	threadpool_destroy(pool);
}
END_TEST

struct work1 {
	int i;
	struct list_head list;
};

static int do_work1(void *in, struct list_head *list, int id)
{
	(void)in;
	(void)id;
	static int do_work1_count = 0;
	do_work1_count++;
	ck_assert_int_eq(do_work1_count, 1); 	/* should be called once */
	struct work1 *e = list_entry(list, struct work1, list);
	ck_assert_int_eq(e->i, 42);
	return TPEEXIT;
}

START_TEST(test_start_submit_wait1)
{
	struct threadpool *pool = NULL;
	struct threadpool_ops ops = {
		.do_work = do_work1,
		.in = NULL
	};
	int err;

	err = threadpool_new(&pool, 1);
	ck_assert_int_eq(err, 0);
	ck_assert(pool != NULL);

	struct work1 *work1 = calloc(1, sizeof(struct work1));
	work1->i = 42;

	threadpool_set_ops(pool, &ops);
	threadpool_submit_work(pool, &work1->list);
	threadpool_wait(pool);
	threadpool_destroy(pool);
	free(work1);
}
END_TEST

struct work3 {
	int id;
	int target;
	struct list_head list;
};

static int do_work3(void *in, struct list_head *list, int id)
{
	(void)in;
	(void)id;
	struct work3 *e = list_entry(list, struct work3, list);
	return e->id == e->target ? TPECANCELSIBLINGS : TPEMORE;
}

static void test_start_submit_wait(size_t nb_workers,
				   size_t nb_units,
				   struct threadpool_ops *ops)
{
	struct threadpool *pool = NULL;
	struct work3 **tmp;
	int err;

	tmp = calloc(nb_units, sizeof(struct work3 *));

	err = threadpool_new(&pool, nb_workers);
	ck_assert_int_eq(err, 0);
	ck_assert(pool != NULL);

	threadpool_set_ops(pool, ops);

	for (size_t i = 0; i < nb_units; ++i) {
		tmp[i] = malloc(sizeof(struct work3));
		tmp[i]->id = i;
		tmp[i]->target = nb_units - 1;
		threadpool_submit_work(pool, &(tmp[i]->list));
	}

	threadpool_wait(pool);
	threadpool_destroy(pool);

	for (size_t i = 0; i < nb_units; ++i)
		free(tmp[i]);
	free(tmp);
}

START_TEST(test_start_submit_wait_less)
{
	struct threadpool_ops ops = {
		.do_work = do_work3,
		.in = NULL
	};
	test_start_submit_wait(3, 4, &ops);
}
END_TEST

START_TEST(test_start_submit_wait_equal)
{
	struct threadpool_ops ops = {
		.do_work = do_work3,
		.in = NULL
	};
	test_start_submit_wait(3, 8, &ops);
}
END_TEST

START_TEST(test_start_submit_wait_more)
{
	struct threadpool_ops ops = {
		.do_work = do_work3,
		.in = NULL
	};
	test_start_submit_wait(3, 16, &ops);
}
END_TEST

struct work_wait {
	int id;
	struct list_head list;
};

static int do_work_wait(void *in, struct list_head *list, int id)
{
	(void)id;
	(void)in;
	struct work_wait *w = list_entry(list, struct work_wait, list);
	ck_assert_int_lt(w->id, 64);
	ck_assert_int_ge(w->id, 0);
	return TPEMORE;
}

START_TEST(test_wait_idle)
{
	struct threadpool_ops ops = {
		.do_work = do_work_wait,
		.in = NULL
	};
	struct threadpool *pool = NULL;
	struct work_wait **tmp;
	int err;

	tmp = calloc(64, sizeof(struct work_wait *));

	err = threadpool_new(&pool, -1);
	ck_assert_int_eq(err, 0);
	ck_assert(pool != NULL);

	threadpool_set_ops(pool,  &ops);

	for (size_t i = 0; i < 64; ++i) {
		tmp[i] = malloc(sizeof(struct work_wait));
		tmp[i]->id = i;
		threadpool_submit_work(pool, &(tmp[i]->list));
	}

	threadpool_wait_idle(pool);
	threadpool_cancel(pool);
	threadpool_destroy(pool);

	for (int i = 0; i < 64; ++i)
		free(tmp[i]);
	free(tmp);
}
END_TEST

Suite *threadpool_suite()
{
	Suite *s = suite_create("threadpool");

	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_new_destroy);
	tcase_add_test(tc_core, test_start_submit_wait1);
	tcase_add_test(tc_core, test_start_submit_wait_less);
	tcase_add_test(tc_core, test_start_submit_wait_equal);
	tcase_add_test(tc_core, test_start_submit_wait_more);
	tcase_add_test(tc_core, test_wait_idle);
	suite_add_tcase(s, tc_core);

	return s;
}

int main()
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = threadpool_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
