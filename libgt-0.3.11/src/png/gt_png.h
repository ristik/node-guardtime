/*
 * $Id: gt_png.h 123 2011-12-07 23:05:50Z ahto.truu $
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

/**
 * \file gt_png.h
 *
 * \brief GuardTime timestamping SDK, public header file for PNG integration.
 *
 * This module offers the functions to embed GuardTime timestamps in PNG
 * image files.
 *
 * <b>Usage</b>
 *
 * The timestamping functions in this module rely on the base module and
 * any functions taking URLs as parameters additionally rely on the HTTP
 * transport module, so the \c libgtbase and \c libgthttp libraries have
 * to be available to your application. Refer to the usage notes in the
 * \c gt_base.h and \c gt_http.h sections for more details.
 */

#ifndef GT_PNG_H_INCLUDED
#define GT_PNG_H_INCLUDED

#include "gt_base.h"
#include "gt_http.h"

#include <stddef.h>

/**
 * \ingroup png
 *
 * Version number of the PNG module, as a 4-byte integer, with the major
 * number in the highest, minor number in the second highest and build
 * number in the two lowest bytes.
 * The preprocessor macro is included to enable conditional compilation.
 *
 * \see GTPNG_getVersion, GT_VERSION, GTHTTP_VERSION
 */
#define GTPNG_VERSION (0 << 24 | 3 << 16 | 11)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \ingroup png
 *
 * Status codes specific for the PNG integration.
 *
 * \see #GTStatusCode and #GTHTTPStatusCode.
 */
enum GTPNGStatusCode {
	/**
	 * The image data passed in is not a valid PNG image.
	 * This result is returned if the image does not have the PNG file signature,
	 * does not have the IHDR and IEND chunks as the first and last ones in the file,
	 * or if any of the data chunks has an invalid length or fails the CRC check.
	 */
	GTPNG_BAD_DATA = GTPNG_LOWEST,
	/**
	 * The image data passed in does not contain any \c gtTS chunks.
	 */
	GTPNG_NO_GTTS,
	/**
	 * The image data passed in contains several \c gtTS chunks.
	 * Currently, we only allow one GuardTime timestamp in an image.
	 */
	GTPNG_MULTIPLE_GTTS,
	/**
	 * Missing or unsupported version number in the \c gtTS chunk.
	 * Currently, only version 1 of the chunk is defined.
	 */
	GTPNG_GTTS_VERSION
};

/**
 * \ingroup png
 *
 * Gets human readable error string in English.
 *
 * \param error \c (in) - Status code from a GuardTime PNG function.
 * \return the error string (it is static, don't try to free it).
 *
 * \note The functions in the PNG module may relay status codes from
 * the base and HTTP modules. This function can handle the relayed codes
 * as well.
 *
 * \see #GT_getErrorString(), #GTHTTP_getErrorString()
 */
const char *GTPNG_getErrorString(int error);

/**
 * \ingroup png
 *
 * Returns the version number of the library.
 *
 * \return version number of the PNG module, as a 4-byte integer, with
 * the major number in the highest, minor number in the second highest
 * and build number in the two lowest bytes.
 *
 * \see GTPNG_VERSION, GT_getVersion, GTHTTP_getVersion
 */
int GTPNG_getVersion(void);

/**
 * \ingroup png
 *
 * Calculates a hash of given PNG image, skipping over the \c gtTS chunk,
 * if one is present.
 *
 * \param hash_algorithm \c (in) - Identifier of the hash algorithm.
 * See #GTHashAlgorithm for possible values.
 * \param img \c (in) - Pointer to the PNG image data to be hashed.
 * Note that the pointer is NOT \c const. This is because the function actually does
 * temporarily modify the buffer for implementation ease and efficiency.
 * \param img_len \c (in) - Length of the PNG image data.
 * \param img_hash \c (out) - Pointer that will receive pointer to the hash. Use
 * #GTDataHash_free() to release the memory when done.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
 */
int GTPNG_hash(int hash_algorithm, void *img, size_t img_len,
		GTDataHash **img_hash);

/**
 * \ingroup png
 *
 * Inserts the given timestamp into the given PNG image. This function does not
 * allocate any memory. The given image buffer is updated in place and must be
 * large enough to hold the result. If the image already contains a timestamp,
 * it is quietly replaced with the new one.
 *
 * \param img \c (in/out) - Pointer to the PNG image data.
 * \param img_len \c (in/out) - Pointer to the length of the PNG image data.
 * The length is updated to reflect the new size of the image.
 * \param buf_len \c (in) - Size of the buffer.
 * The buffer must be large enough to hold the result.
 * \param ts \c (in) - Pointer to the timestamp data.
 * \param ts_len \c (in) - Length of the timestamp data.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code;
 * in particular \c GT_OUT_OF_MEMORY when the buffer is too small).
 */
int GTPNG_insert(void *img, size_t *img_len, size_t buf_len,
		const void *ts, size_t ts_len);

/**
 * \ingroup png
 *
 * Extracts the timestamp from the given PNG image. This function does not
 * allocate any memory. The result points to the location of the timestamp
 * within the given image buffer. If the image does not contain a timestamp,
 * the pointer is set to \c NULL.
 *
 * \param img \c (in/out) - Pointer to the PNG image data.
 * \param img_len \c (in/out) - Length of the PNG image data.
 * \param ts \c (out) - Pointer that will receive pointer to the timestamp data.
 * \param ts_len \c (out) - Pointer that will receive the length of the timestamp data.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
 */
int GTPNG_extract(const void *img, size_t img_len,
		const void **ts, size_t *ts_len);

/**
 * \ingroup png
 *
 * Creates a timestamp for a PNG file and inserts it into the file.
 *
 * \param img \c (in) - Pointer to the PNG image data.
 * \param img_len \c (in) - Length of the PNG image data.
 * \param url \c (in) - The signing service to use.
 * \param img_ts \c (out) - Pointer that will receive pointer to the new
 * timestamped image. Use #GT_free() to release the memory when done.
 * \param img_ts_len \c (out) - Pointer that will receive the length of
 * the new timestamped image.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
 */
int GTPNG_createTimestamp(const void *img, size_t img_len, const char *url,
		void **img_ts, size_t *img_ts_len);

/**
 * \ingroup png
 *
 * Extends a timestamp for a PNG file and inserts it into the file.
 *
 * \param img \c (in) - Pointer to the PNG image data.
 * \param img_len \c (in) - Length of the PNG image data.
 * \param url \c (in) - The extending service to use.
 * \param img_ts \c (out) - Pointer that will receive pointer to the new
 * timestamped image. Use #GT_free() to release the memory when done.
 * \param img_ts_len \c (out) - Pointer that will receive the length of
 * the new timestamped image.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
 */
int GTPNG_extendTimestamp(const void *img, size_t img_len, const char *url,
		void **img_ts, size_t *img_ts_len);

/**
 * \ingroup png
 *
 * Verifies the given timestamped PNG image using the given publications file.
 *
 * \param img \c (in) - Pointer to the PNG image data.
 * \param img_len \c (in) - Length of the PNG image data.
 * \param ext_url \c (in) - The URL of the extending service.
 * If this is \c NULL and the timestamp should be extended to be
 * verified, verification will fail.
 * \param ext_ts \c (out) - The pointer that will receive a pointer to
 * the extended timestamp if the timestamp is extended during verification.
 * If the timestamp is not extended, *ext_ts will be set to \c NULL.
 * If ext_ts is \c NULL, the extended timestamp is discarded.
 * \param pub \c (in) - The publications file.
 * Exactly one of \c pub, \c pub_url must be non-\c NULL.
 * \param pub_url \c (in) - The URL to get the publications file from.
 * Exactly one of \c pub, \c pub_url must be non-\c NULL.
 * \param parse \c (in) - The \c explicit_data field of the verification
 * info will be filled if this is non-zero.
 * \param ver \c (out) - Pointer that will receive pointer to
 * verification info.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTPNG_verifyTimestamp(void *img, size_t img_len,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* not GT_PNG_H_INCLUDED */
