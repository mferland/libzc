/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2020 Marc Ferland
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

#include <stddef.h>

#ifdef WIN32

size_t threads_to_create(long forced)
{
	if (forced > 0)
		return forced;
	return 1; /* best effort on windows */
}

#else

#include <unistd.h>

size_t threads_to_create(long forced)
{
	if (forced > 0)
		return forced;
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 1)
		return 1;
	return n;
}

#endif
