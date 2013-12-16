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

#ifndef _TEST_LIBZC_H_
#define _TEST_LIBZC_H_

#include <check.h>

Suite *make_libzc_file_suite();
Suite *make_libzc_pwgen_suite();
Suite *make_libzc_crack_suite();
Suite *make_libzc_pwdict_suite();
Suite *make_libzc_ptext_suite();

#endif

