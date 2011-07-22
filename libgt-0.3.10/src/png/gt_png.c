/*
 * $Id: gt_png.c 74 2010-02-22 11:42:26Z ahto.truu $
 *
 * Copyright 2008-2010 GuardTime AS
 *
 * This file is part of the GuardTime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "gt_png.h"
#include "gtpng_crc32.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef _WIN32
#ifndef UINT32_T_DEFINED
typedef unsigned __int32 uint32_t;
#define UINT32_T_DEFINED
#endif /* not UINT32_T_DEFINED */
#else /* _WIN32 */
#include <stdint.h>
#endif /* not _WIN32 */

/** The PNG file signature. */
static const unsigned char png_sig[] = {137, 80, 78, 71, 13, 10, 26, 10};

/** The IHDR chunk type. */
static const uint32_t png_ihdr = ((((((uint32_t) 'I' << 8) + 'H') << 8) + 'D') << 8) + 'R';

/** The IEND chunk type. */
static const uint32_t png_iend = ((((((uint32_t) 'I' << 8) + 'E') << 8) + 'N') << 8) + 'D';

/** The gtTS chunk type. */
static const uint32_t png_gtts = ((((((uint32_t) 'g' << 8) + 't') << 8) + 'T') << 8) + 'S';

/** Version number of the chunk structure. */
static const unsigned char png_gtts_ver = 1;

/** Size of the file signature. */
static const size_t png_sig_sz = 8;

/** Size of the chunk length. */
static const size_t png_len_sz = 4;

/** Size of the chunk tag. */
static const size_t png_tag_sz = 4;

/** Size of the gtTS chunk version number. */
static const size_t png_ver_sz = 1;

/** Size of the chunk CRC. */
static const size_t png_crc_sz = 4;

/** Internal helper: reverses the order of bytes in a memory buffer. */
static void memrev(unsigned char *buf, size_t len)
{
	int i = 0, j = len - 1;
	while (i < j) {
		unsigned char c = buf[i];
		buf[i] = buf[j];
		buf[j] = c;
		++i; --j;
	}
}

/** Internal helper: swaps two adjacent data blocks in a memory buffer. */
static void memswap(unsigned char *buf, size_t len1, size_t len2)
{
	memrev(buf, len1);
	memrev(buf + len1, len2);
	memrev(buf, len1 + len2);
}

/** Internal helper: extracts a 4-byte unsigned integer from the buffer. */
static uint32_t get_uint32(const unsigned char *buf)
{
	uint32_t res = buf[0];
	res = (res << 8) | buf[1];
	res = (res << 8) | buf[2];
	res = (res << 8) | buf[3];
	return res;
}

/* Internal helper: inserts a 4-byte unsigned integer into the buffer. */
static void put_uint32(unsigned char *buf, uint32_t val)
{
	buf[0] = (unsigned char) ((val >> 24) & 0xff);
	buf[1] = (unsigned char) ((val >> 16) & 0xff);
	buf[2] = (unsigned char) ((val >> 8) & 0xff);
	buf[3] = (unsigned char) (val & 0xff);
}

/* Internal helper: locates the gtTS chunk within the PNG image data.
 * If there's no gtTS chunk, sets *res_pos and *res_len to zero. */
static int find_gtts(const void *img, size_t img_len,
		size_t *res_pos, size_t *res_len)
{
	int res = GT_UNKNOWN_ERROR;
	const unsigned char *p = img;
	size_t tmp_pos = 0, tmp_len = 0;
	size_t pos = 0;

	assert(sizeof(png_sig) == png_sig_sz);

	/* Check that the data has proper PNG signature. */
	if (img_len < pos + png_sig_sz || memcmp(p + pos, png_sig, png_sig_sz) != 0) {
		res = GTPNG_BAD_DATA;
#ifdef _DEBUG
		fprintf(stderr, "find_gtts: no header\n");
#endif
		goto cleanup;
	}
	pos += png_sig_sz;

	/* Check the chunks sequentially. */
	while (pos < img_len) {
		uint32_t len, crc, typ;

		/* At the minimum, a chunk has to have length, type, and CRC. */
		if (img_len < pos + png_len_sz + png_tag_sz + png_crc_sz) {
			res = GTPNG_BAD_DATA;
#ifdef _DEBUG
		fprintf(stderr, "find_gtts: too small chunk at %u\n", (unsigned) pos);
#endif
			goto cleanup;
		}

		/* Extract data length. */
		len = get_uint32(p + pos);

		/* The chunk must not exceed the remainder of the data. */
		if (img_len < len || img_len < pos + png_len_sz + png_tag_sz + len + png_crc_sz) {
			res = GTPNG_BAD_DATA;
#ifdef _DEBUG
		fprintf(stderr, "find_gtts: too large chunk at %u\n", (unsigned) pos);
#endif
			goto cleanup;
		}

		/* Extract the chunk type. */
		typ = get_uint32(p + pos + png_len_sz);

		/* Check that IHDR is the first and only first chunk. */
		if (pos == png_sig_sz || typ == png_ihdr) {
			if (pos != png_sig_sz || typ != png_ihdr) {
				res = GTPNG_BAD_DATA;
#ifdef _DEBUG
		fprintf(stderr, "find_gtts: wrong IHDR at %u\n", (unsigned) pos);
#endif
				goto cleanup;
			}
		}

		/* Check that IEND is the last and only the last chunk. */
		if (pos + png_len_sz + png_tag_sz + len + png_crc_sz == img_len || typ == png_iend) {
			if (pos + png_len_sz + png_tag_sz + len + png_crc_sz != img_len || typ != png_iend || len != 0) {
				res = GTPNG_BAD_DATA;
#ifdef _DEBUG
		fprintf(stderr, "find_gtts: wrong IEND at %u\n", (unsigned) pos);
#endif
				goto cleanup;
			}
		}

		/* Check for gtTS chunk. */
		if (typ == png_gtts) {

			/* A gtTS chunk has to have a supported version number. */
			if (len < png_ver_sz || p[pos + png_len_sz + png_tag_sz] != png_gtts_ver) {
				res = GTPNG_GTTS_VERSION;
#ifdef _DEBUG
				fprintf(stderr, "find_gtts: bad gtTS version %u at %u\n",
						(unsigned) p[pos + png_len_sz + png_tag_sz], (unsigned) pos);
#endif
				goto cleanup;
			}

			/* At most one gtTS is allowed per file. */
			if (tmp_pos != 0 || tmp_len != 0) {
				res = GTPNG_MULTIPLE_GTTS;
#ifdef _DEBUG
			fprintf(stderr, "find_gtts: duplicate gtTS at %u\n", (unsigned) pos);
#endif
				goto cleanup;
			}

			/* Remember the locaton of the gtTS chunk. */
			tmp_pos = pos;
			tmp_len = png_len_sz + png_tag_sz + len + png_crc_sz;
		}

		/* Extract the CRC value. */
		crc = get_uint32(p + pos + png_len_sz + png_tag_sz + len);

		/* The CRC is over the type and data. */
		if (GTPNG_crc32(p + pos + png_len_sz, png_tag_sz + len) != crc) {
			res = GTPNG_BAD_DATA;
#ifdef _DEBUG
			fprintf(stderr, "find_gtts: CRC error at %u\n", (unsigned) pos);
#endif
			goto cleanup;
		}

		/* Skip over the chunk. */
		pos += png_len_sz + png_tag_sz + len + png_crc_sz;
	}

	/* All right, deliver the results. */
	if (res_pos != NULL) {
		*res_pos = tmp_pos;
	}
	if (res_len != NULL) {
		*res_len = tmp_len;
	}
	res = GT_OK;

cleanup:

	return res;
}

/**/

const char *GTPNG_getErrorString(int error)
{
	if (error < GTPNG_LOWEST || error > GTPNG_HIGHEST) {
		return GTHTTP_getErrorString(error);
	}

	switch (error) {
		case GTPNG_BAD_DATA:
			return "Not a valid PNG image.";
		case GTPNG_NO_GTTS:
			return "Timestamp chunk not found";
		case GTPNG_MULTIPLE_GTTS:
			return "Multiple timestamp chunks found";
		case GTPNG_GTTS_VERSION:
			return "Unknown timestamp chunk version";
		default:
			return "<Not a valid GuardTime PNG status code>";
	}
}

/**/

int GTPNG_getVersion(void)
{
	return GTPNG_VERSION;
}

/**/

int GTPNG_hash(int hash_algorithm, void *img, size_t img_len,
		GTDataHash **img_hash)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *p = img; /* alias with a better type */
	int swapped = 0;
	size_t tmp_pos, tmp_len;

	if (img == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (img_hash == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Look for existing timestamp, validate the whole image in process. */
	res = find_gtts(img, img_len, &tmp_pos, &tmp_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* If there is an existing timestamp, move it out of the image. */
	if (tmp_len > 0) {
		memswap(p + tmp_pos, tmp_len, img_len - tmp_pos - tmp_len);
		swapped = 1;
	}

	/* Hash the remaining data. */
	res = GTDataHash_create(hash_algorithm, img, img_len - tmp_len, img_hash);
	if (res != GT_OK) {
		goto cleanup;
	}

cleanup:

	if (swapped) {
		/* Undo the data block swap. */
		memswap(p + tmp_pos, img_len - tmp_pos - tmp_len, tmp_len);
		swapped = 0;
	}

	return res;
}

/**/

int GTPNG_insert(void *img, size_t *img_len, size_t buf_len,
		const void *ts, size_t ts_len)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *p = img; /* alias with a better type */
	unsigned char *q = img; /* ditto */
	size_t tmp_pos, tmp_len;

	if (img == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (*img_len > buf_len) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (ts == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Look for existing timestamp, validate the whole image in process. */
	res = find_gtts(img, *img_len, &tmp_pos, &tmp_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	assert(tmp_pos < *img_len);
	assert(tmp_len < *img_len);
	assert(tmp_pos + tmp_len < *img_len);

	/* Check the buffer size. */
	if (*img_len - tmp_len + (png_len_sz + png_tag_sz + png_ver_sz + ts_len + png_crc_sz) > buf_len) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* If there is an existing timestamp, move it out of the new image. */
	if (tmp_len > 0) {
		memswap(p + tmp_pos, tmp_len, *img_len - tmp_pos - tmp_len);
		*img_len -= tmp_len;
	}

	/* Append the new timestamp to the end of the new image. */
	q += *img_len; /* the next byte after the current image */
	put_uint32(q, png_ver_sz + ts_len);
	q += png_len_sz;
	put_uint32(q, png_gtts);
	q += png_tag_sz;
	*q = png_gtts_ver;
	q += png_ver_sz;
	memcpy(q, ts, ts_len);
	q += ts_len;
	put_uint32(q, GTPNG_crc32(p + *img_len + png_len_sz, png_tag_sz + png_ver_sz + ts_len));
	q += png_crc_sz;
	*img_len += (png_len_sz + png_tag_sz + png_ver_sz + ts_len + png_crc_sz);
	assert(*img_len = q - p);
	assert(*img_len <= buf_len);

	/* Move the new timestamp to just before the IEND chunk.
	 * NOTE: This operation relies on the IEND chunk having no data. */
	memswap(p + *img_len - (png_len_sz + png_tag_sz + png_crc_sz) - (png_len_sz + png_tag_sz + png_ver_sz + ts_len + png_crc_sz),
			png_len_sz + png_tag_sz + png_crc_sz,
			png_len_sz + png_tag_sz + png_ver_sz + ts_len + png_crc_sz);

	res = GT_OK;

cleanup:

	return res;
}

/**/

int GTPNG_extract(const void *img, size_t img_len,
		const void **ts, size_t *ts_len)
{
	int res = GT_UNKNOWN_ERROR;
	const unsigned char *p = img; /* alias with a better type */
	size_t tmp_pos, tmp_len;

	if (img == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Look for existing timestamp, validate the whole image in process. */
	res = find_gtts(img, img_len, &tmp_pos, &tmp_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	assert(tmp_pos < img_len);
	assert(tmp_len < img_len);
	assert(tmp_pos + tmp_len < img_len);

	/* There's no timestamp in the image. */
	if (tmp_len == 0) {
		res = GTPNG_NO_GTTS;
		goto cleanup;
	}

	/* Return just the timestamp portion of the gtTS chunk. */
	if (ts != NULL) {
		*ts = p + tmp_pos + png_len_sz + png_tag_sz + png_ver_sz;
	}
	if (ts_len != NULL) {
		*ts_len = tmp_len - (png_len_sz + png_tag_sz + png_ver_sz + png_crc_sz);
	}
	res = GT_OK;

cleanup:

	return res;
}

/**/

int GTPNG_createTimestamp(const void *img, size_t img_len, const char *url,
		void **img_ts, size_t *img_ts_len)
{
	int res = GT_UNKNOWN_ERROR;
	const unsigned char *p = img; /* alias with a better type */
	size_t tmp_pos, tmp_len;
	unsigned char *buf = NULL;
	size_t buf_len, new_len;
	GTDataHash *hash = NULL;
	GTTimestamp *ts = NULL;
	unsigned char *der = NULL;
	size_t der_len;

	/* Look for existing timestamp, validate the whole image in process. */
	res = find_gtts(img, img_len, &tmp_pos, &tmp_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	assert(tmp_pos < img_len);
	assert(tmp_len < img_len);
	assert(tmp_pos + tmp_len < img_len);

	/* Create a copy of plain image in a new buffer. */
	buf_len = img_len - tmp_len;
	buf = GT_malloc(buf_len);
	if (buf == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy(buf, p, tmp_pos); /* the part before gtTS */
	memcpy(buf + tmp_pos, p + tmp_pos + tmp_len,
			img_len - tmp_pos - tmp_len); /* the part after gtTS */

	/* Get the hash of the plain image data. */
	res = GTDataHash_create(GT_HASHALG_DEFAULT, buf, buf_len, &hash);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Get the timestamp. */
	res = GTHTTP_createTimestampHash(hash, url, &ts);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTTimestamp_getDEREncoded(ts, &der, &der_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Extend the buffer and insert timestamp. */
	new_len = buf_len + png_len_sz + png_tag_sz + png_ver_sz + der_len + png_crc_sz;
	buf = GT_realloc(buf, new_len);
	if (buf == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	res = GTPNG_insert(buf, &buf_len, new_len, der, der_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	assert(buf_len == new_len);

	/* Return the result. */
	*img_ts = buf;
	buf = NULL;
	*img_ts_len = buf_len;
	res = GT_OK;

cleanup:

	GT_free(der);
	GTTimestamp_free(ts);
	GTDataHash_free(hash);
	GT_free(buf);

	return res;
}

/**/

int GTPNG_extendTimestamp(const void *img, size_t img_len, const char *url,
		void **img_ts, size_t *img_ts_len)
{
	int res = GT_UNKNOWN_ERROR;
	const unsigned char *p = img; /* alias with a better type */
	size_t tmp_pos, tmp_len;
	GTTimestamp *ts_in = NULL;
	GTTimestamp *ts_out = NULL;
	unsigned char *der = NULL;
	size_t der_len;
	unsigned char *buf = NULL;
	size_t buf_len, new_len;

	/* Look for existing timestamp, validate the whole image in process. */
	res = find_gtts(img, img_len, &tmp_pos, &tmp_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	if (tmp_len == 0) {
		res = GTPNG_NO_GTTS;
		goto cleanup;
	}
	assert(tmp_pos < img_len);
	assert(tmp_len < img_len);
	assert(tmp_pos + tmp_len < img_len);

	/* Get the original timestamp and extend it. */
	res = GTTimestamp_DERDecode(p + tmp_pos + png_len_sz + png_tag_sz + png_ver_sz,
			tmp_len - (png_len_sz + png_tag_sz + png_ver_sz + png_crc_sz), &ts_in);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTHTTP_extendTimestamp(ts_in, url, &ts_out);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTTimestamp_getDEREncoded(ts_out, &der, &der_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Create a copy of plain image in a new buffer. */
	buf_len = img_len - tmp_len;
	new_len = buf_len + png_len_sz + png_tag_sz + png_ver_sz + der_len + png_crc_sz;
	buf = GT_malloc(new_len);
	if (buf == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy(buf, img, tmp_pos); /* the part before gtTS */
	memcpy(buf + tmp_pos, p + tmp_pos + tmp_len,
			img_len - tmp_pos - tmp_len); /* the part after gtTS */

	/* Insert timestamp in the new image. */
	res = GTPNG_insert(buf, &buf_len, new_len, der, der_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	assert(buf_len == new_len);

	/* Return the result. */
	*img_ts = buf;
	buf = NULL;
	*img_ts_len = buf_len;
	res = GT_OK;

cleanup:

	GT_free(buf);
	GT_free(der);
	GTTimestamp_free(ts_out);
	GTTimestamp_free(ts_in);

	return res;
}

/**/

int GTPNG_verifyTimestamp(void *img, size_t img_len,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver)
{
	int res = GT_UNKNOWN_ERROR;
	const void *der = NULL;
	size_t der_len;
	GTTimestamp *ts = NULL;
	int hash_alg;
	GTDataHash *hash = NULL;

	/* Extract the timestamp, if any. */
	res = GTPNG_extract(img, img_len, &der, &der_len);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTTimestamp_DERDecode(der, der_len, &ts);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Re-hash the image data. */
	res = GTTimestamp_getAlgorithm(ts, &hash_alg);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTPNG_hash(hash_alg, img, img_len, &hash);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Verify the timestamp. */
	res = GTHTTP_verifyTimestampHash(ts, hash, ext_url, ext_ts, pub, pub_url, parse, ver);

cleanup:

	GTDataHash_free(hash);
	GTTimestamp_free(ts);
	/* NOTE: der is an alias and must not be freed! */

	return res;
}
