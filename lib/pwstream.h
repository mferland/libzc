/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2021 Marc Ferland
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

#ifndef _PWSTREAM_H_
#define _PWSTREAM_H_

struct pwstream;
struct entry {
	/* TODO: convert to ssize_t */
	int start, stop, initial;
};

int pwstream_new(struct pwstream **pws);

void pwstream_free(struct pwstream *pws);

/* initial indexes, when provided, are in natural left-to-right order. */
int pwstream_generate_from_pool(struct pwstream *pws, size_t pool_len, size_t pw_len,
		      size_t streams, const size_t *initial);

/* Backward-compatible pool generator name. */
int pwstream_generate(struct pwstream *pws, size_t pool_len, size_t pw_len,
		      size_t streams, const size_t *initial);

/* parsed_mask and initial both use natural left-to-right password order. */
int pwstream_generate_from_mask(struct pwstream *pws,
				const char *const *parsed_mask,
				size_t parsed_mask_len,
				size_t streams, const size_t *initial);

const struct entry *pwstream_get_entry(struct pwstream *pws, size_t stream,
				       size_t pos);

size_t pwstream_get_pwlen(const struct pwstream *pws);

size_t pwstream_get_stream_count(const struct pwstream *pws);

bool pwstream_is_empty(const struct pwstream *pws, unsigned int stream);

#endif /* _PWSTREAM_H_ */
