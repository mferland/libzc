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

#define _GNU_SOURCE		/* memmem() */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libzc.h"
#include "libzc_private.h"
#include "list.h"

#define LOCAL_HEADER_LEN      30
#define GP_BIT_HAS_DATA_DESC  (1 << 3)
#define GP_BIT_ENCRYPTION     0x1
#define MAX_FN_LEN            4096
#define MAX_COM_LEN           65536

#define CD_SIG             0x02014b50 /* PK\1\2 */
#define LOCAL_SIG          0x04034b50 /* PK\3\4 */
#define EOCD_SIG           0x06054b50 /* PK\5\6 */
#define EOCD64_SIG         0x06064b50 /* PK\6\6 */
#define EOCD64_LOC_SIG     0x07064b50 /* PK\6\7 */
#define EOCD_SIG_STR       "PK\5\6"
#define EXTRA_TAG_ZIP64    0x0001

#define LOCAL_LEN          30   /* Local header length */
#define EOCD_LEN           22 	/* End of central directory length */
#define EOCD64_LOC_LEN     20	/* Zip64 end of central directory locator length */
#define EOCD64_LEN         56	/* Zip64 end of central directory length */
#define CD_ENTRY_LEN       46   /* Central directory entry length */
#define CD_ENTRY64_LEN     56   /* Zip64 central directory entry length */
#define CD_BUF_LEN         (MAX_COM_LEN + EOCD_LEN + EOCD64_LOC_LEN)

/**
 * SECTION:file
 * @short_description: libzc zip file
 *
 * The file structure contains information about the targeted zip
 * file.
 */

/**
 * zc_file:
 *
 * Opaque object representing the zip file.
 */
struct zc_file {
	struct zc_ctx *ctx;
	int refcount;
	char *filename;
	FILE *stream;

	uint8_t buf[CD_BUF_LEN];
	uint8_t search_buf[CD_BUF_LEN];
	struct list_head info_head;
};

static uint16_t get_le16_at(const uint8_t *b, size_t i)
{
	return (uint16_t)b[i + 1] << 8 | (uint16_t)b[i];
}

static uint32_t get_le32_at(const uint8_t *b, size_t i)
{
	return (uint32_t)b[i + 3] << 24 | (uint32_t)b[i + 2] << 16 |
	       (uint32_t)b[i + 1] << 8 | (uint32_t)b[i];
}

static uint64_t get_le64_at(const uint8_t *b, size_t i)
{
	return (uint64_t)b[i + 7] << 56 |
		(uint64_t)b[i + 6] << 48 |
		(uint64_t)b[i + 5] << 40 |
		(uint64_t)b[i + 4] << 32 |
		(uint64_t)b[i + 3] << 24 |
		(uint64_t)b[i + 2] << 16 |
		(uint64_t)b[i + 1] << 8 |
		(uint64_t)b[i];
}

/*
   From APPNOTE.TXT:

   4.3.16  End of central directory record:

      end of central dir signature    4 bytes  (0x06054b50)
      number of this disk             2 bytes
      number of the disk with the
      start of the central directory  2 bytes
      total number of entries in the
      central directory on this disk  2 bytes
      total number of entries in
      the central directory           2 bytes
      size of the central directory   4 bytes
      offset of start of central
      directory with respect to
      the starting disk number        4 bytes
      .ZIP file comment length        2 bytes
      .ZIP file comment       (variable size)
*/
struct zc_eocd {
	uint32_t sig;
	uint16_t disk_num;
	uint16_t disk_cd_start;
	uint16_t entries_in_cd;
	uint16_t entries_in_cd_total;
	uint32_t cd_size;
	uint32_t cd_start_offset;
	uint16_t comment_len;
	uint8_t *comment;
};

static void parse_eocd(const uint8_t *from, struct zc_eocd *eocd)
{
	eocd->sig = get_le32_at(from, 0);
	eocd->disk_num = get_le16_at(from, 4);
	eocd->disk_cd_start = get_le16_at(from, 6);
	eocd->entries_in_cd = get_le16_at(from, 8);
	eocd->entries_in_cd_total = get_le16_at(from, 10);
	eocd->cd_size = get_le32_at(from, 12);
	eocd->cd_start_offset = get_le32_at(from, 16);
	eocd->comment_len = get_le16_at(from, 20);
	eocd->comment = NULL;
}

/*
   From APPNOTE.TXT:

   4.3.15 Zip64 end of central directory locator

      zip64 end of central dir locator
      signature                       4 bytes  (0x07064b50)
      number of the disk with the
      start of the zip64 end of
      central directory               4 bytes
      relative offset of the zip64
      end of central directory record 8 bytes
      total number of disks           4 bytes
 */
struct zc_eocd64_loc {
	uint32_t sig;
	uint32_t disk_num;
	uint64_t cd_start_offset;
	uint32_t disk_total;
};

static void parse_eocd64_loc(const uint8_t *from, struct zc_eocd64_loc *eocd64_loc)
{
	eocd64_loc->sig = get_le32_at(from, 0);
	eocd64_loc->disk_num = get_le32_at(from, 4);
	eocd64_loc->cd_start_offset = get_le64_at(from, 8);
	eocd64_loc->disk_total = get_le32_at(from, 16);
}

/*
   From APPNOTE.TXT:

   4.3.12  Central directory structure:

      [central directory header 1]
      .
      .
      .
      [central directory header n]
      [digital signature]

      File header:

        central file header signature   4 bytes  (0x02014b50)
        version made by                 2 bytes
        version needed to extract       2 bytes
        general purpose bit flag        2 bytes
        compression method              2 bytes
        last mod file time              2 bytes
        last mod file date              2 bytes
        crc-32                          4 bytes
        compressed size                 4 bytes
        uncompressed size               4 bytes
        file name length                2 bytes
        extra field length              2 bytes
        file comment length             2 bytes
        disk number start               2 bytes
        internal file attributes        2 bytes
        external file attributes        4 bytes
        relative offset of local header 4 bytes

        file name (variable size)
        extra field (variable size)
        file comment (variable size)
 */
struct zc_cdheader {
	uint32_t sig;
	uint16_t version_made_by;
	uint16_t version_needed;
	uint16_t gen_bit_flag;
	uint16_t comp_method;
	uint16_t last_mod_time;
	uint16_t last_mod_date;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint16_t filename_length;
	uint16_t extra_length;
	uint16_t comment_length;
	uint16_t disk_num_start;
	uint16_t int_fattrs;
	uint32_t ext_fattrs;
	uint32_t loc_header_offt;
	char *filename;
	uint8_t *extra;
	char *comment;
};

static void parse_cd(const uint8_t *from, struct zc_cdheader *cd)
{
	cd->version_made_by = get_le16_at(from, 4);
	cd->version_needed = get_le16_at(from, 6);
	cd->gen_bit_flag = get_le16_at(from, 8);
	cd->comp_method = get_le16_at(from, 10);
	cd->last_mod_time = get_le16_at(from, 12);
	cd->last_mod_date = get_le16_at(from, 14);
	cd->crc32 = get_le32_at(from, 16);
	cd->comp_size = get_le32_at(from, 20);
	cd->uncomp_size = get_le32_at(from, 24);
	cd->filename_length = get_le16_at(from, 28);
	cd->extra_length = get_le16_at(from, 30);
	cd->comment_length = get_le16_at(from, 32);
	cd->disk_num_start = get_le16_at(from, 34);
	cd->int_fattrs = get_le16_at(from, 36);
	cd->ext_fattrs = get_le32_at(from, 38);
	cd->loc_header_offt = get_le32_at(from, 42);
	cd->filename = NULL;
	cd->extra = NULL;
	cd->comment = NULL;
}

static int alloc_cdheader(struct zc_cdheader *cd)
{
	void *tmp;

	/* filename length already validated as being > 1 */
	tmp = calloc(1, cd->filename_length + 1);
	if (!tmp)
		return -1;
	cd->filename = tmp;

	if (cd->extra_length) {
		tmp = malloc(cd->extra_length);
		if (!tmp)
			goto err1;
		cd->extra = tmp;
	}

	if (cd->comment_length) {
		tmp = malloc(cd->comment_length);
		if (!tmp)
			goto err2;
		cd->comment = tmp;
	}

	return 0;
err2:
	free(cd->extra);
	cd->extra = NULL;
err1:
	free(cd->filename);
	cd->filename = NULL;

	return -1;
}

static void dealloc_cdheader(struct zc_cdheader *cd)
{
	free(cd->comment);
	free(cd->extra);
	free(cd->filename);
}

/*
   From APPNOTE.TXT:

  4.3.7  Local file header:

      local file header signature     4 bytes  (0x04034b50)
      version needed to extract       2 bytes
      general purpose bit flag        2 bytes
      compression method              2 bytes
      last mod file time              2 bytes
      last mod file date              2 bytes
      crc-32                          4 bytes
      compressed size                 4 bytes
      uncompressed size               4 bytes
      file name length                2 bytes
      extra field length              2 bytes

      file name (variable size, skipped)
      extra field (variable size, skipped)
 */
struct zc_local_header {
	uint32_t sig;
	uint16_t version_needed;
	uint16_t gen_bit_flag;
	uint16_t comp_method;
	uint16_t last_mod_time;
	uint16_t last_mod_date;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint16_t filename_length;
	uint16_t extra_length;
};

static void parse_local_header(const uint8_t *from, struct zc_local_header *loc)
{
	loc->sig = get_le32_at(from, 0);
	loc->version_needed = get_le16_at(from, 4);
	loc->gen_bit_flag = get_le16_at(from, 6);
	loc->comp_method = get_le16_at(from, 8);
	loc->last_mod_time = get_le16_at(from, 10);
	loc->last_mod_date = get_le16_at(from, 12);
	loc->crc32 = get_le32_at(from, 14);
	loc->comp_size = get_le32_at(from, 18);
	loc->uncomp_size = get_le32_at(from, 22);
	loc->filename_length = get_le16_at(from, 26);
	loc->extra_length = get_le16_at(from, 28);
}

/*
   From APPNOTE.TXT:

   4.3.14  Zip64 end of central directory record

        zip64 end of central dir
        signature                       4 bytes  (0x06064b50)
        size of zip64 end of central
        directory record                8 bytes
        version made by                 2 bytes
        version needed to extract       2 bytes
        number of this disk             4 bytes
        number of the disk with the
        start of the central directory  4 bytes
        total number of entries in the
        central directory on this disk  8 bytes
        total number of entries in the
        central directory               8 bytes
        size of the central directory   8 bytes
        offset of start of central
        directory with respect to
        the starting disk number        8 bytes
        zip64 extensible data sector    (variable size)

      4.3.14.1 The value stored into the "size of zip64 end of central
      directory record" SHOULD be the size of the remaining
      record and SHOULD NOT include the leading 12 bytes.

      Size = SizeOfFixedFields + SizeOfVariableData - 12.

      4.3.14.2 The above record structure defines Version 1 of the
      zip64 end of central directory record. Version 1 was
      implemented in versions of this specification preceding
      6.2 in support of the ZIP64 large file feature. The
      introduction of the Central Directory Encryption feature
      implemented in version 6.2 as part of the Strong Encryption
      Specification defines Version 2 of this record structure.
      Refer to the section describing the Strong Encryption
      Specification for details on the version 2 format for
      this record. Refer to the section in this document entitled
      "Incorporating PKWARE Proprietary Technology into Your Product"
      for more information applicable to use of Version 2 of this
      record.

      4.3.14.3 Special purpose data MAY reside in the zip64 extensible
      data sector field following either a V1 or V2 version of this
      record.  To ensure identification of this special purpose data
      it MUST include an identifying header block consisting of the
      following:

         Header ID  -  2 bytes
         Data Size  -  4 bytes

      The Header ID field indicates the type of data that is in the
      data block that follows.

      Data Size identifies the number of bytes that follow for this
      data block type.

      4.3.14.4 Multiple special purpose data blocks MAY be present.
      Each MUST be preceded by a Header ID and Data Size field.  Current
      mappings of Header ID values supported in this field are as
      defined in APPENDIX C.
 */
struct zc_eocd64 {
	uint32_t sig;
	uint64_t eocd64_size;
	uint16_t version_made_by;
	uint16_t version_needed;
	uint32_t disk_num;
	uint32_t disk_num_cd_start;
	uint64_t entries_in_cd;
	uint64_t entries_in_cd_total;
	uint64_t cd_size;
	uint64_t cd_start_offset;
};

static void parse_eocd64(const uint8_t *from, struct zc_eocd64 *eocd64)
{
	eocd64->sig = get_le32_at(from, 0);
	eocd64->eocd64_size = get_le64_at(from, 4);
	eocd64->version_made_by = get_le16_at(from, 12);
	eocd64->version_needed = get_le16_at(from, 14);
	eocd64->disk_num = get_le32_at(from, 16);
	eocd64->disk_num_cd_start = get_le32_at(from, 20);
	eocd64->entries_in_cd = get_le64_at(from, 24);
	eocd64->entries_in_cd_total = get_le64_at(from, 32);
	eocd64->cd_size = get_le64_at(from, 40);
	eocd64->cd_start_offset = get_le64_at(from, 48);
}

/*
   From APPNOTE.TXT:

  4.5.3 -Zip64 Extended Information Extra Field (0x0001):

      The following is the layout of the zip64 extended
      information "extra" block. If one of the size or
      offset fields in the Local or Central directory
      record is too small to hold the required data,
      a Zip64 extended information record is created.
      The order of the fields in the zip64 extended
      information record is fixed, but the fields MUST
      only appear if the corresponding Local or Central
      directory record field is set to 0xFFFF or 0xFFFFFFFF.

      Note: all fields stored in Intel low-byte/high-byte order.

        Value      Size       Description
        -----      ----       -----------
(ZIP64) 0x0001     2 bytes    Tag for this "extra" block type
        Size       2 bytes    Size of this "extra" block
        Original
        Size       8 bytes    Original uncompressed file size
        Compressed
        Size       8 bytes    Size of compressed data
        Relative Header
        Offset     8 bytes    Offset of local header record
        Disk Start
        Number     4 bytes    Number of the disk on which
                              this file starts

      This entry in the Local header MUST include BOTH original
      and compressed file size fields. If encrypting the
      central directory and bit 13 of the general purpose bit
      flag is set indicating masking, the value stored in the
      Local Header for the original file size will be zero.
*/
struct zc_extra_zip64_ext {
	uint16_t tag;
	uint16_t size;
	uint64_t uncomp_size;
	uint64_t comp_size;
	uint64_t local_offset;
	uint32_t disk_num;
};

struct zc_info {
	/* parsed headers */
	struct zc_cdheader header;
	struct zc_extra_zip64_ext extra;

	/* begin and end of the entry payload */
	off_t begin_offset;
	off_t end_offset;
	off_t local_offset;

	/* encryption header */
	struct zc_header encrypt_header;
	off_t header_offset;

	/* zip file entry index */
	int idx;

	struct list_head list;
};

static bool is_encrypted(uint16_t flag)
{
	return !!(flag & GP_BIT_ENCRYPTION);
}

static bool has_data_desc(uint16_t flag)
{
	return !!(flag & GP_BIT_HAS_DATA_DESC);
}

static bool is_deflated(uint16_t flag)
{
	return flag == 0x8;
}

static bool is_stored(uint16_t flag)
{
	return flag == 0x0;
}

static uint8_t check_byte(const struct zc_cdheader *h)
{
	if (has_data_desc(h->gen_bit_flag))
		return h->last_mod_time >> 8;
	return h->crc32 >> 24;
}

static void clear_info_list(struct zc_file *f)
{
	struct zc_info *i, *tmp;
	list_for_each_entry_safe(i, tmp, &f->info_head, list) {
		list_del(&i->list);
		dealloc_cdheader(&i->header);
		free(i);
	}
}

static bool is_zip64(const struct zc_cdheader *h)
{
	return (h->comp_size == UINT32_MAX ||
		h->uncomp_size == UINT32_MAX ||
		h->disk_num_start == UINT16_MAX ||
		h->loc_header_offt == UINT32_MAX);
}

static size_t zfread(struct zc_file *f, void *ptr, size_t size, size_t nmemb)
{
	size_t ret = fread(ptr, size, nmemb, f->stream);
	if (ret != nmemb) {
		if (ferror(f->stream))
			err(f->ctx, "fread() failed: %zu\n", ret);
		else if (feof(f->stream))
			err(f->ctx, "fread() failed, eof reached: %zu\n", ret);
	}
	return ret;
}

static int zfseeko(struct zc_file *f, off_t offset, int whence)
{
	int ret = fseeko(f->stream, offset, whence);
	if (ret)
		err(f->ctx, "fseeko() failed: %s\n", strerror(errno));
	return ret;
}

static int find_cd_offset_from_eocd(struct zc_file *f, const struct zc_eocd *eocd,
				    const uint8_t *from, off_t *cd_offset,
				    uint64_t *nbentries)
{
	struct zc_eocd64_loc eocd64_loc;
	struct zc_eocd64 eocd64;
	const uint8_t *loc_ptr;
	size_t len;
	int ret = -1;

	/* standard zip */
	if (eocd->cd_start_offset != UINT32_MAX) {
		dbg(f->ctx, "Detected standard zip EOCD: cd_offset: 0x%x, nbentries: %d\n",
		    eocd->cd_start_offset,
		    eocd->entries_in_cd);
		*cd_offset = eocd->cd_start_offset;
		*nbentries = eocd->entries_in_cd;
		return 0;
	}

	dbg(f->ctx, "Detected zip64 EOCD\n");

	/* zip64 - go back EOCD64_LOC_LEN bytes */
	if (from - EOCD64_LOC_LEN < f->buf) {
		dbg(f->ctx, "error reading zip64 end of central directory locator\n");
		return -1;
	}

	loc_ptr = from - EOCD64_LOC_LEN;

	/* parse zip64 EOCD locator */
	parse_eocd64_loc(loc_ptr, &eocd64_loc);

	if (eocd64_loc.sig != EOCD64_LOC_SIG) {
		err(f->ctx, "found invalid EOCD64 locator signature: 0x%08x\n", eocd64_loc.sig);
		return -1;
	}

	dbg(f->ctx, "Reading EOCD locator:\n");
	dbg(f->ctx, "\tsig: 0x%08x, disk_num: %d, cd_start_offset: 0x%016jx, disk_total: %d\n",
	    eocd64_loc.sig,
	    eocd64_loc.disk_num,
	    eocd64_loc.cd_start_offset,
	    eocd64_loc.disk_total);

	if (eocd64_loc.cd_start_offset > INT64_MAX) {
		/* offset is too large, malformed zip file? */
		dbg(f->ctx, "central directory locator offset too large, skipping...\n");
		return -1;
	}

	if (eocd64_loc.disk_num || eocd64_loc.disk_total > 1) {
		err(f->ctx, "multi-disk zip files not supported\n");
		return -1;
	}

	ret = zfseeko(f, (off_t)eocd64_loc.cd_start_offset, SEEK_SET);
	if (ret < 0)
		return ret;

	/* read zip64 End of Central Directory */
	len = zfread(f, f->buf, EOCD64_LEN, 1);
	if (len != 1)
		return -1;

	parse_eocd64(f->buf, &eocd64);
	if (eocd64.cd_start_offset > INT64_MAX) {
		/* offset is too large, malformed zip file? */
		dbg(f->ctx, "central directory offset too large, skipping...\n");
		return -1;
	}

	dbg(f->ctx, "Reading zip64 EOCD:\n");
	dbg(f->ctx, "\tsig: 0x%08x, eocd64_size: %zu, version_made_by: %d, version_needed: %d,\n",
	    eocd64.sig,
	    eocd64.eocd64_size,
	    eocd64.version_made_by,
	    eocd64.version_needed);
	dbg(f->ctx, "\tdisk_num: %d, disk_num_cd_start: %d, entries_in_cd: %zu, entries_in_cd_total: %zu,\n",
	    eocd64.disk_num,
	    eocd64.disk_num_cd_start,
	    eocd64.entries_in_cd,
	    eocd64.entries_in_cd_total);
	dbg(f->ctx, "\tcd_size: %zu, cd_start_offset: 0x%016jx\n",
	    eocd64.cd_size,
	    eocd64.cd_start_offset);

	*cd_offset = eocd64.cd_start_offset;
	*nbentries = eocd64.entries_in_cd;

	return 0;
}

static int read_single_entry_at(struct zc_file *f, off_t cd_offset,
				struct zc_cdheader *header,
				struct zc_extra_zip64_ext *extra,
				off_t *next)
{
	uint32_t sig;
	size_t len;
	int ret;

	dbg(f->ctx, "Reading central directory entry at: 0x%016jx\n", cd_offset);

	/* seek to beginning of entry */
	ret = zfseeko(f, cd_offset, SEEK_SET);
	if (ret)
		return ret;

	/* read central directory entry, optionnaly followed
	   by a zip64 entry */
	len = zfread(f, f->buf, CD_ENTRY_LEN, 1);
	if (len != 1)
		return -1;

	sig = get_le32_at(f->buf, 0);
	if (sig != CD_SIG) {
		dbg(f->ctx, "found invalid central directory entry signature: 0x08%x\n", sig);
		return -1;
	}

	parse_cd(f->buf, header);

	dbg(f->ctx, "\tsig: 0x%08x, version_made_by: %d, version_needed: %d, gen_bit_flag: 0x%04x,\n",
	    sig,
	    header->version_made_by,
	    header->version_needed,
	    header->gen_bit_flag);
	dbg(f->ctx, "\tcomp_method: %d, last_mod_time: %d, last_mod_date: %d, crc32: 0x%08x,\n",
	    header->comp_method,
	    header->last_mod_time,
	    header->last_mod_date,
	    header->crc32);
	dbg(f->ctx, "\tcomp_size: %"PRIu32", uncomp_size: %"PRIu32", filename_length: %d, extra_length: %d,\n",
	    header->comp_size,
	    header->uncomp_size,
	    header->filename_length,
	    header->extra_length);
	dbg(f->ctx, "\tcomment_length: %d, disk_num_start: %d, int_fattrs: 0x%04x, ext_fattrs: 0x%08x,\n",
	    header->comment_length,
	    header->disk_num_start,
	    header->int_fattrs,
	    header->ext_fattrs);
	dbg(f->ctx, "\tloc_header_offt: 0x%08x\n",
	    header->loc_header_offt);

	/*
	 * encrypted files should always have a minimum compressed
	 * size of ENC_HEADER_LEN. See APPNOTE.txt.
	 */
	if (is_encrypted(header->gen_bit_flag) &&
	    header->comp_size < ENC_HEADER_LEN) {
		err(f->ctx, "encrypted file size (%"PRIu32") smaller than %d\n",
		    header->comp_size, ENC_HEADER_LEN);
		return -1;
	}

	if (!header->filename_length ||
	    header->filename_length > MAX_FN_LEN) {
		err(f->ctx, "invalid filename length: %d\n",
		    header->filename_length);
		return -1;
	}

	ret = alloc_cdheader(header);
	if (ret)
		return -1;

	len = zfread(f, header->filename, header->filename_length, 1);
	if (len != 1)
		goto err;
	dbg(f->ctx, "\tfilename: %s\n", header->filename);

	dbg(f->ctx, "\textra_length: %d\n", header->extra_length);
	if (header->extra_length) {
		len = zfread(f, header->extra, header->extra_length, 1);
		if (len != 1)
			goto err;
	}

	if (header->comment_length) {
		len = zfread(f, header->comment, header->comment_length, 1);
		if (len != 1)
			goto err;
	}

	if (is_zip64(header)) {
		/* Zip64 Extended Information Extra Field */
		int header_id_index = 0;

		while (1) {
			extra->tag = get_le16_at(header->extra, header_id_index);
			extra->size = get_le16_at(header->extra, header_id_index + 2);

			dbg(f->ctx, "Reading extra tag: 0x%x, size: %d\n", extra->tag, extra->size);

			if (extra->tag != EXTRA_TAG_ZIP64) {
				int next = header_id_index + extra->size + 4; /* 4 ==> tag + size */

				/* skip this extra field */
				if (next + 4 > header->extra_length)
					/* nothing more to read from extra field */
					break;
				header_id_index = next;
				continue;
			}
			/* found it ! */
			break;
		}

		/* zip64 extra field is always >= 8 bytes */
		if (extra->size < 8) {
			err(f->ctx, "extra field is %d bytes, expected >= 8\n", extra->size);
			goto err;
		}

		/*
		 * Make sure we do not read past the end of the extra
		 * buffer.
		 */
		if (header_id_index + extra->size - 1 > header->extra_length)
			goto err;

		/* align on first member of the extra field */
		header_id_index += 4;

		/* Original uncompressed file size */
		if (header->uncomp_size == UINT32_MAX) {
			extra->uncomp_size = get_le64_at(header->extra, header_id_index);
			header_id_index += 8;
			dbg(f->ctx, "\t\tzip64 extra field: uncompressed file size: %"PRIu64"\n",
			    extra->uncomp_size);
		}

		/* Size of compressed data */
		if (header->comp_size == UINT32_MAX) {
			extra->comp_size = get_le64_at(header->extra, header_id_index);
			header_id_index += 8;
			dbg(f->ctx, "\t\tzip64 extra field: compressed file size: %"PRIu64"\n",
			    extra->comp_size);
		}

		/* Offset of local header record */
		if (header->loc_header_offt == UINT32_MAX) {
			extra->local_offset = get_le64_at(header->extra, header_id_index);
			header_id_index += 8;
			dbg(f->ctx, "\t\tzip64 extra field: local header offset: 0x%016jx\n",
			    extra->local_offset);
		}

		/* Number of the disk on which this file starts */
		if (header->disk_num_start == UINT16_MAX) {
			extra->disk_num = get_le32_at(header->extra, header_id_index); /* last field */
			dbg(f->ctx, "\t\tzip64 extra field: local header offset: %d\n",
			    extra->disk_num);
		}
	}

	*next = ftello(f->stream);

	return 0;
err:
	dealloc_cdheader(header);
	return -1;
}

static int read_all_entries_at(struct zc_file *f, off_t cd_offset, uint64_t nbentries)
{
	struct zc_info *info;
	struct zc_local_header loc;
	size_t len;
	int ret;

	for (uint64_t i = 0; i < nbentries; ++i) {
		info = calloc(1, sizeof(struct zc_info));
		if (!info)
			goto err;

		dbg(f->ctx, "Reading entry: %ld\n", i);

		ret = read_single_entry_at(f, cd_offset, &info->header,
					   &info->extra, &cd_offset);
		if (ret) {
			free(info);
			goto err;
		}

		if (info->header.loc_header_offt == UINT32_MAX)
			info->local_offset = info->extra.local_offset;
		else
			info->local_offset = info->header.loc_header_offt;

		info->idx = i;
		list_add_tail(&info->list, &f->info_head);
	}

	/* fill out data offsets */
	list_for_each_entry(info, &f->info_head, list) {
		uint8_t buf[LOCAL_HEADER_LEN];

		dbg(f->ctx, "Reading local file header at: 0x%016jx\n", info->local_offset);

		ret = zfseeko(f, info->local_offset, SEEK_SET);
		if (ret)
			goto err;

		len = zfread(f, buf, LOCAL_HEADER_LEN, 1);
		if (len != 1)
			goto err;

		parse_local_header(buf, &loc);

		dbg(f->ctx, "\tsig: 0x%08x, version_needed: %d, gen_bit_flag: 0x%04x, comp_method: %d,\n",
		    loc.sig, loc.version_needed, loc.gen_bit_flag, loc.comp_method);
		dbg(f->ctx, "\tlast_mod_time: %d, last_mod_date: %d, crc32: 0x%08x, comp_size: %"PRIu32",\n",
		    loc.last_mod_time, loc.last_mod_date, loc.crc32, loc.comp_size);
		dbg(f->ctx, "\tuncomp_size: %"PRIu32", filename_length: %d, extra_length: %d\n",
		    loc.uncomp_size, loc.filename_length, loc.extra_length);

		if (loc.sig != LOCAL_SIG)
			goto err;

		/* skip filename */
		ret = zfseeko(f, loc.filename_length, SEEK_CUR);
		if (ret)
			goto err;

		/* skip extra field */
		ret = zfseeko(f, loc.extra_length, SEEK_CUR);
		if (ret)
			goto err;

		uint64_t comp_size;
		if (info->header.comp_size == UINT32_MAX)
			comp_size = info->extra.comp_size;
		else
			comp_size = info->header.comp_size;

		if (is_encrypted(info->header.gen_bit_flag)) {
			info->encrypt_header.magic = check_byte(&info->header);
			info->header_offset = ftello(f->stream);
			info->begin_offset = info->header_offset + ENC_HEADER_LEN;
			info->end_offset = info->header_offset + comp_size;
			len = zfread(f, info->encrypt_header.buf, ENC_HEADER_LEN, 1);
			if (len != 1)
				goto err;
		} else {
			info->encrypt_header.magic = 0;
			info->header_offset = -1;
			info->begin_offset = ftello(f->stream);
			info->end_offset = info->begin_offset + comp_size;
		}

		dbg(f->ctx, "\tencrypt_header: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, magic: 0x%02x\n",
		    info->encrypt_header.buf[0], info->encrypt_header.buf[1],
		    info->encrypt_header.buf[2], info->encrypt_header.buf[3],
		    info->encrypt_header.buf[4], info->encrypt_header.buf[5],
		    info->encrypt_header.buf[6], info->encrypt_header.buf[7],
		    info->encrypt_header.buf[8], info->encrypt_header.buf[9],
		    info->encrypt_header.buf[10], info->encrypt_header.buf[11],
		    info->encrypt_header.magic);
	}

	return 0;

 err:
	clear_info_list(f);
	return -1;
}

static int fill_info_list_central_directory(struct zc_file *f)
{
	int err, fd;
	struct stat sb;
	off_t cd_offset;
	uint64_t entries_in_cd;
	uint8_t *from, *end;
	size_t len, to_read = CD_BUF_LEN;

	fd = fileno(f->stream);
	if (fd < 0) {
		err(f->ctx, "fileno() failed: %s\n", strerror(errno));
		return -1;
	}

	err = fstat(fd, &sb);
	if (err < 0) {
		err(f->ctx, "fstat() failed: %s\n", strerror(errno));
		return -1;
	}

	/*
	 * file is actually smaller than max buffer size, read the
	 * whole file in this case.
	 */
	if (sb.st_size < CD_BUF_LEN)
		to_read = sb.st_size;

	dbg(f->ctx, "Detected file size: %zu bytes\n", sb.st_size);
	dbg(f->ctx, "Bytes to read: %zu\n", to_read);

	err = zfseeko(f, -(off_t)to_read, SEEK_END);
	if (err)
		return -1;

	len = zfread(f, f->search_buf, to_read, 1);
	if (len != 1)
		return -1;

	/* start searching from beginning of the buffer */
	from = f->search_buf;
	end = from + to_read - 1;

	while (1) {
		struct zc_eocd eocd;
		size_t rem;

		/* find the end of central directory record */
		from = memmem(from, to_read, EOCD_SIG_STR, 4);
		if (!from) {
			/*
			 * end of central directory signature not
			 * found, bail out
			 */
			err(f->ctx, "EOCD signature not found\n");
			goto err1;
		}

		rem = end - from + 1;

		dbg(f->ctx, "Found EOCD signature at: 0x%016jx\n", sb.st_size - rem);

		/* make sure we have enough to read */
		if (rem < EOCD_LEN)
			goto err1;

		parse_eocd(from, &eocd);

		dbg(f->ctx, "\tsig: 0x%08x, disk_num: %d, disk_cd_start: %d, entries_in_cd: %d,\n",
		    eocd.sig,
		    eocd.disk_num,
		    eocd.disk_cd_start,
		    eocd.entries_in_cd);
		dbg(f->ctx, "\tentries_in_cd_total: %d, cd_size: %"PRIu32", cd_start_offset: 0x%x\n",
		    eocd.entries_in_cd_total,
		    eocd.cd_size,
		    eocd.cd_start_offset);
		dbg(f->ctx, "\tcomment_len: %d\n",
		    eocd.comment_len);

		err = find_cd_offset_from_eocd(f, &eocd, from, &cd_offset,
					       &entries_in_cd);
		if (err) {
			to_read = rem;
			from++;
			continue;
		}

		/* basic sanity checks */
		if (!entries_in_cd || cd_offset > sb.st_size) {
			err(f->ctx, "detected invalid zip file: entries_in_cd: %ld, cd_offset: 0x%016jx\n",
			    entries_in_cd, cd_offset);
			to_read = rem;
			from++;
			continue;
		}

		err = read_all_entries_at(f, cd_offset, entries_in_cd);
		if (!err)
			break;
		else {
			to_read = rem;
			from++;
			continue;
		}
	}

	return 0;

err1:
	return -1;
}

ZC_EXPORT struct zc_file *zc_file_ref(struct zc_file *f)
{
	if (!f)
		return NULL;
	f->refcount++;
	return f;
}

ZC_EXPORT struct zc_file *zc_file_unref(struct zc_file *f)
{
	if (!f)
		return NULL;
	f->refcount--;
	if (f->refcount > 0)
		return f;
	dbg(f->ctx, "file %p released\n", f);
	free(f->filename);
	free(f);
	return NULL;
}

/**
 * zc_file_new_from_filename:
 *
 * Allocate a new zc_file from the given filename. The file existence
 * is not verified at this stage.
 *
 * @retval 0      Success
 * @retval -1     Error
 */
ZC_EXPORT int zc_file_new_from_filename(struct zc_ctx *ctx,
					const char *filename,
					struct zc_file **file)
{
	struct zc_file *newfile;

	newfile = calloc(1, sizeof(struct zc_file));
	if (!newfile)
		return -1;

	newfile->ctx = ctx;
	newfile->refcount = 1;
	newfile->filename = strdup(filename);
	INIT_LIST_HEAD(&newfile->info_head);
	*file = newfile;
	dbg(ctx, "file %p created for %s\n", newfile, filename);
	return 0;
}

/**
 * zc_file_get_filename:
 *
 * @retval Filename of the passed zc_file object.
 */
ZC_EXPORT const char *zc_file_get_filename(const struct zc_file *f)
{
	return f->filename;
}

/**
 * zc_file_open:
 *
 * Open the file for reading.
 *
 * @retval Returns the fopen() return value.
 */
ZC_EXPORT int zc_file_open(struct zc_file *f)
{
	FILE *stream;

	if (zc_file_isopened(f))
		return -1;

	/*
	 * Regarding the 'b' (from manpages):
	 *
	 * The mode string can also include the letter 'b' either as a
	 * last character or as a character between the characters in
	 * any of the two-character strings described above.  This is
	 * strictly for compatibility with C89 and has no effect; the
	 * 'b' is ignored on all POSIX conforming systems, including
	 * Linux.  (Other systems may treat text files and binary
	 * files differently, and adding the 'b' may be a good idea if
	 * you do I/O to a binary file and expect that your program
	 * may be ported to non-UNIX environments.)
	 *
	 * Required for the Windows (minmgw64) build.
	 */
	stream = fopen(f->filename, "rb");
	if (!stream) {
		err(f->ctx, "fopen(%s) failed: %s.\n",
		    f->filename,
		    strerror(errno));
		return -1;
	}

	dbg(f->ctx, "file %s open returned: %p\n", f->filename, stream);

	f->stream = stream;

	if (fill_info_list_central_directory(f)) {
		err(f->ctx, "failure while reading headers.\n");
		goto err;
	}

	return 0;

err:
	fclose(f->stream);
	f->stream = NULL;
	return -1;
}

/**
 * zc_file_close:
 *
 * Close the file.
 *
 * @retval Returns the fclose() return value.
 */
ZC_EXPORT int zc_file_close(struct zc_file *f)
{
	if (!zc_file_isopened(f))
		return -1;

	clear_info_list(f);

	if (fclose(f->stream)) {
		err(f->ctx, "fclose() failed: %s.\n", strerror(errno));
		return -1;
	}

	dbg(f->ctx, "file %p closed\n", f);

	f->stream = NULL;

	return 0;
}

/**
 * zc_file_isopened:
 *
 * @retval Whether or not the file is opened.
 */
ZC_EXPORT bool zc_file_isopened(struct zc_file *f)
{
	return (f->stream != NULL);
}

static bool consider_file(struct zc_info *info)
{
	if (!is_encrypted(info->header.gen_bit_flag) ||
	    (!is_deflated(info->header.comp_method) &&
	     !is_stored(info->header.comp_method)))
		return false;
	return true;
}

/**
 * read_zc_header:
 *
 * Read the validation data from the file and store them in the header
 * array. At most nmemb elements will be stored in the array.
 *
 * The file must be opened before calling this function.
 *
 * @retval 0  No encryption data found in this file.
 * @retval >0 The number of encryption data objects read.
 */
size_t read_zc_header(struct zc_file *f, struct zc_header *h, size_t len)
{
	struct zc_info *info;
	size_t valid = 0;

	list_for_each_entry(info, &f->info_head, list) {
		if (!consider_file(info))
			continue;

		h[valid].magic = info->encrypt_header.magic;
		memcpy(h[valid].buf, info->encrypt_header.buf, ENC_HEADER_LEN);

		if (++valid == len)
			break;
	}

	return valid;
}

static struct zc_info *find_file_smallest(struct zc_file *f)
{
	struct zc_info *info, *ret = NULL;
	long s = LONG_MAX;

	list_for_each_entry(info, &f->info_head, list) {
		if (!consider_file(info))
			continue;
		long tmp = info->end_offset - info->begin_offset;
		if (tmp < s) {
			s = tmp;
			ret = info;
		}
	}

	return ret;
}

int read_crypt_data(struct zc_file *f, unsigned char **buf,
		    size_t *out_len, uint32_t *original_crc, bool *deflated)
{
	struct zc_info *info;
	size_t to_read;
	int err;

	info = find_file_smallest(f);
	if (!info)
		return -1;

	to_read = info->end_offset - info->header_offset;

	err = zfseeko(f, info->header_offset, SEEK_SET);
	if (err)
		return -1;

	unsigned char *tmp = malloc(to_read);
	if (!tmp) {
		err(f->ctx, "malloc() failed(): %s\n", strerror(errno));
		return -1;
	}

	size_t len = zfread(f, tmp, 1, to_read);
	if (len != to_read)
		goto err;

	*buf = tmp;
	*out_len = len;
	*original_crc = info->header.crc32;
	*deflated = is_deflated(info->header.comp_method);

	return 0;

err:
	free(tmp);
	return -1;
}

ZC_EXPORT struct zc_info *zc_file_info_next(struct zc_file *f,
					    struct zc_info *info)
{
	struct zc_info *i;

	if (!info)
		return list_entry(f->info_head.next, struct zc_info, list);

	if (info->list.next == &f->info_head)
		return NULL;

	i = list_entry(info->list.next, struct zc_info, list);

	return i;
}

ZC_EXPORT const char *zc_file_info_name(const struct zc_info *info)
{
	return info->header.filename;
}

ZC_EXPORT uint64_t zc_file_info_size(const struct zc_info *info)
{
	if (info->header.uncomp_size == UINT32_MAX)
		return info->extra.uncomp_size;
	return info->header.uncomp_size;
}

ZC_EXPORT uint64_t zc_file_info_compressed_size(const struct zc_info *info)
{
	if (info->header.comp_size == UINT32_MAX)
		return info->extra.comp_size;
	return info->header.comp_size;
}

ZC_EXPORT off_t zc_file_info_offset_begin(const struct zc_info *info)
{
	return info->begin_offset;
}

ZC_EXPORT off_t zc_file_info_offset_end(const struct zc_info *info)
{
	return info->end_offset;
}

ZC_EXPORT off_t zc_file_info_crypt_header_offset(const struct zc_info *info)
{
	return info->header_offset;
}

ZC_EXPORT const uint8_t *zc_file_info_enc_header(const struct zc_info *info)
{
	return info->encrypt_header.buf;
}

ZC_EXPORT int zc_file_info_idx(const struct zc_info *info)
{
	return info->idx;
}
