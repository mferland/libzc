/*
 *  zc - zip crack library
 *  Copyright (C) 2014  Marc Ferland
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

#include "key_table.h"

struct key_table *table;

void setup_keytable()
{
   int err;
   err = key_table_new(&table, 1024);
   fail_if(err != 0);
   fail_if(table == 0);
}

void teardown_keytable()
{
   key_table_free(table);
}

START_TEST(test_keytable_new)
{
   int err;
   table = 0;
   err = key_table_new(&table, 0);
   fail_if(err == 0);
   fail_if(table != 0);
   key_table_free(table);
}
END_TEST

START_TEST(test_keytable_append)
{
   key_table_append(table, 0x12345678);
   fail_if(table->size != 1024 + 1);
   fail_if(table->capacity != 2048);
}
END_TEST

START_TEST(test_keytable_append_multi)
{
   for (int i = 0; i < 1024; ++i)
   {
      key_table_append(table, 1);
      fail_if(table->size != 1024 + i + 1);
      fail_if(table->capacity != 2048);
   }
}
END_TEST

START_TEST(test_keytable_uniq1)
{
   table->array[0] = 0;
   table->array[1] = 0;
   for (int i = 2; i < 1024; ++i)
   {
      table->array[i] = i;
   }
   key_table_uniq(table);
   fail_if(table->size != 1023);
   fail_if(table->array[0] != 0);
   for (int i = 1; i < table->size; ++i)
      fail_if(table->array[i] != i + 1);
}
END_TEST

START_TEST(test_keytable_uniq2)
{
   for (int i = 0; i < 1024; ++i)
      table->array[i] = 0;
   key_table_uniq(table);
   fail_if(table->size != 1);
   fail_if(table->array[0] != 0);
}
END_TEST

START_TEST(test_keytable_uniq3)
{
   for (int i = 0; i < 1024; ++i)
      table->array[i] = i;
   key_table_uniq(table);
   fail_if(table->size != 1024);
   for (int i = 0; i < 1024; ++i)
      fail_if(table->array[i] != i);
}
END_TEST

START_TEST(test_keytable_squeeze1)
{
   key_table_squeeze(table);
   fail_if(table->size != 1024);
   fail_if(table->capacity != 1024);
}
END_TEST

START_TEST(test_keytable_squeeze2)
{
   for (int i = 0; i < 1024; ++i)
      table->array[i] = 0;
   key_table_uniq(table);
   fail_if(table->size != 1);
   fail_if(table->capacity != 1024);
   key_table_squeeze(table);
   fail_if(table->size != 1);
   fail_if(table->capacity != 1);
}
END_TEST

START_TEST(test_keytable_empty1)
{
   key_table_empty(table);
   fail_if(table->size != 0);
}
END_TEST

START_TEST(test_keytable_empty2)
{
   key_table_empty(table);
   key_table_uniq(table);
   fail_if(table->size != 0);
   fail_if(table->capacity != 1024);
}
END_TEST

START_TEST(test_keytable_empty3)
{
   key_table_empty(table);
   key_table_squeeze(table);
   fail_if(table->size != 0);
   fail_if(table->capacity != 0);
   fail_if(table->array != 0);
}
END_TEST

START_TEST(test_keytable_empty4)
{
   key_table_empty(table);
   key_table_squeeze(table);
   key_table_append(table, 5);
   fail_if(table->size != 1);
   fail_if(table->capacity != 1024);
   fail_if(table->array == 0);
}
END_TEST

Suite *make_libzc_keytable_suite()
{
   Suite *s = suite_create("key table");

   TCase *tc_nofix = tcase_create("No fixtures");
   tcase_add_test(tc_nofix, test_keytable_new);
   suite_add_tcase(s, tc_nofix);

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup_keytable, teardown_keytable);
   tcase_add_test(tc_core, test_keytable_append);
   tcase_add_test(tc_core, test_keytable_append_multi);
   tcase_add_test(tc_core, test_keytable_uniq1);
   tcase_add_test(tc_core, test_keytable_uniq2);
   tcase_add_test(tc_core, test_keytable_uniq3);
   tcase_add_test(tc_core, test_keytable_squeeze1);
   tcase_add_test(tc_core, test_keytable_squeeze2);
   tcase_add_test(tc_core, test_keytable_empty1);
   tcase_add_test(tc_core, test_keytable_empty2);
   tcase_add_test(tc_core, test_keytable_empty3);
   tcase_add_test(tc_core, test_keytable_empty4);
   suite_add_tcase(s, tc_core);
   
   return s;
}

int main()
{
   int number_failed;
   SRunner *sr = srunner_create(make_libzc_keytable_suite());
   srunner_set_log(sr, "test_key_table.log");
   srunner_run_all(sr, CK_NORMAL);
   number_failed = srunner_ntests_failed(sr);
   srunner_free(sr);
   return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
