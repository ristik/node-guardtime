/*
 * $Id: gt_http.h 99 2010-12-01 13:30:21Z ahto.truu $
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
 * \file gt_http.h
 *
 * \brief GuardTime client SDK, public header file for HTTP transport module.
 *
 * This module offers the functions to communicate with the GuardTime
 * network over the HTTP protocol.
 *
 * The three main functions are:
 * - creating a timestamp (the resulting PKI-signed timestamp
 * can be verified using the GuardTime public key certificate);
 * - extending a timestamp (the resulting hash-linked timestamp
 * can be verified independently from GuardTime for unlimited time);
 * - verifying a timestamp; the following diagram illustrates the
 * decision process:
 * \image html ApiVerifyTimestamp.png
 * \image latex ApiVerifyTimestamp.pdf "" width=15cm
 *
 * <h2>Usage</h2>
 *
 * <b>Linux</b>
 *
 * The networking functions in this module rely on cURL. The use of
 * the cURL code is covered by the license available online from
 * <a href="http://curl.haxx.se/docs/copyright.html">curl.haxx.se/docs/copyright.html</a>
 * and also enclosed in the file \c licence.curl.txt.
 *
 * Multi-platform source code for cURL can be dowloaded from
 * <a href="http://curl.haxx.se/">curl.haxx.se</a>.
 * This version of the GuardTime SDK has been tested with cURL 7.18.1.
 *
 * Although it's not difficult to compile cURL on Linux, most distributions
 * also provide prebuilt binaries through their normal package management
 * facilities. When installing a prebuilt package, make sure you pick a
 * "developer" version, otherwise you may only get the tools and utilities,
 * but no libraries or headers.
 *
 * To compile a program that uses both the HTTP module and GuardTime base
 * API, use a command along the lines of
 * \code
 *    gcc example.c -o example -I/usr/local/gt/include \
 *    -L/usr/local/gt/lib -L/usr/local/curl/lib -L/usr/local/ssl/lib \
 *    -lgthttp -lgtbase -lcurl -lcrypto -lrt
 * \endcode
 * (either with the backslashes or all on a single line) replacing
 * \c /usr/local/gt, \c /usr/local/curl and \c /usr/local/ssl with
 * the directories where you unpacked the GuardTime, cURL and OpenSSL libraries.
 *
 * <b>Windows</b>
 *
 * The networking functions in this module rely on WinINet, which comes
 * standard on all supported versions of Windows.
 *
 * To compile a program that uses both the HTTP module and GuardTime base
 * API, use a command along the lines of
 * \code
 *    cl.exe /MT example.c /I C:\gt\include
 *    /link /libpath:C:\gt\lib /libpath:C:\openssl\lib
 *    libgthttpMT.lib libgtbaseMT.lib libeay32MT.lib wininet.lib
 *    wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib
 * \endcode
 * (all on a single line) replacing
 * \c C:\\gt and \c C:\\openssl with
 * the directories where you unpacked the GuardTime and OpenSSL libraries.
 *
 * When compiling, keep in mind that mixing code compiled with different
 * \c /Mxx settings is dangerous. It's best to always use the
 * GuardTime and OpenSSL libraries that match the \c /Mxx
 * setting you specified for compiling your own source code.
 */

#ifndef GTHTTP_H_INCLUDED
#define GTHTTP_H_INCLUDED

#include "gt_base.h"

#include <stddef.h>

/**
 * \ingroup http
 *
 * Version number of the HTTP module, as a 4-byte integer, with the major
 * number in the highest, minor number in the second highest and build
 * number in the two lowest bytes.
 * The preprocessor macro is included to enable conditional compilation.
 *
 * \see GTHTTP_getVersion, GT_VERSION
 */
#define GTHTTP_VERSION (0 << 24 | 3 << 16 | 8)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \ingroup http
 *
 * GuardTime status codes specific for the HTTP transport module.
 *
 * \see #GTStatusCode.
 */
enum GTHTTPStatusCode {
	/**
	 * This is the limit on distinct HTTP response codes the GuardTime
	 * HTTP module can handle. Since it's a fair bit above the highest
	 * value defined by the W3C, we should be safe for quite some time.
	 */
	GTHTTP_HTTP_LIMIT = 0x1000,
	/**
	 * This is the base value for response codes from the HTTP server.
	 * The response \c xxx is returned as \c (GTHTTP_HTTP_BASE + xxx),
	 * where xxx must be >0 and <GTHTTP_HTTP_LIMIT; anything outside
	 * that range is replaced with 0 (and returned as GTHTTP_HTTP_BASE).
	 */
	GTHTTP_HTTP_BASE = GTHTTP_LOWEST,
	/**
	 * This is the base value for error codes from the underlying transport
	 * library (cURL on Linux, WinINet on Windows) used to disambiguate them
	 * from the GuardTime error codes: the library error \c err is returned
	 * as \c (GTHTTP_IMPL_BASE + err) from the GuardTime functions. Make sure
	 * nobody else uses the values in the range from \c GTHTTP_IMPL_BASE to
	 * \c GTHTTP_HIGHEST or else the error codes can't be resolved to error
	 * messages correctly.
	 */
	GTHTTP_IMPL_BASE = GTHTTP_HTTP_BASE + GTHTTP_HTTP_LIMIT
};

/**
 * \ingroup http
 *
 * Initializes the HTTP module. Must be called once before any other HTTP
 * functions.
 *
 * \param user_agent \c (in) - If this is not \c NULL, it is reported to
 * the service provider in order to help with server-side troubleshooting
 * and statistics. It is recommended to include the application name and
 * version number.
 * \param init_winsock \c (in) - If this parameter is non-zero, then performs
 * Windows socket initialization and cleanup. If this flag is zero, then the
 * user must have initialized Windows sockets. On Unix systems, this parameter
 * has no effect.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 *
 * \note You most likely have to call #GT_init() to initialize the base
 * module as well.
 */
int GTHTTP_init(const char *user_agent, int init_winsock);

/**
 * \ingroup http
 *
 * Frees the resources used by the HTTP module. Must be called once after
 * any other HTTP functions.
 *
 * \note You most likely have to call #GT_finalize() to clean up the base
 * module as well.
 */
void GTHTTP_finalize(void);

/**
 * \ingroup http
 *
 * Gets human readable error string in English.
 *
 * \param error \c (in) - Status code from a GuardTime HTTP function.
 * \return the error string (it is static, don't try to free it).
 *
 * \note The functions in the HTTP module may relay status codes from
 * the base module. This function can handle the relayed codes as well.
 *
 * \see #GT_getErrorString()
 */
const char *GTHTTP_getErrorString(int error);

/**
 * \ingroup http
 *
 * Returns the version number of the library.
 *
 * \return version number of the HTTP module, as a 4-byte integer, with
 * the major number in the highest, minor number in the second highest
 * and build number in the two lowest bytes.
 *
 * \see GTHTTP_VERSION, GT_getVersion
 */
int GTHTTP_getVersion(void);

/**
 * \ingroup http
 *
 * Sets the timeout to be used for subsequent HTTP requests for
 * connecting to the server.
 *
 * \param timeout \c (in) - The timeout, in seconds.
 * Pass zero to wait forever (no timeout), or negative to use the
 * implementation default.
 */
void GTHTTP_setConnectTimeout(int timeout);

/**
 * \ingroup http
 *
 * Returns the timeout for connecting to the server.
 *
 * \return The timeout, in seconds. Zero means waiting forever (no
 * timeout), negative means using the implementation default.
 */
int GTHTTP_getConnectTimeout(void);

/**
 * \ingroup http
 *
 * Sets the timeout to be used for subsequent HTTP requests for
 * getting a response from the server.
 *
 * \param timeout \c (in) - The timeout, in seconds.
 * Pass zero to wait forever (no timeout), or negative to use the
 * implementation default.
 */
void GTHTTP_setResponseTimeout(int timeout);

/**
 * \ingroup http
 *
 * Returns the timeout for getting a response from the server.
 *
 * \return The timeout, in seconds. Zero means waiting forever (no
 * timeout), negative means using the implementation default.
 */
int GTHTTP_getResponseTimeout(void);

/**
 * \ingroup http
 *
 * Sends a HTTP request.
 *
 * \param url \c (in) - URL to send the request to.
 * \param request \c (in) - Pointer to the buffer containing the request.
 * If \p request is \c NULL, a \c GET request is sent.
 * If \p request is non-\c NULL, a \c POST request is sent.
 * \param request_length \c (in) - Size of the buffer pointed by \p request.
 * \param response \c (out) - Pointer that will receive pointer to the
 * response. Use #GT_free() to release the memory when done.
 * \param response_length \c (out) - Pointer to the variable that receives
 * the length of the response.
 * \param error \c (out) - Pointer that will receive pointer to the
 * error message. Use #GT_free() to release the memory when done.
 * May be \c NULL, in which case the error message is not returned.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTHTTP_sendRequest(const char *url,
		const unsigned char *request, size_t request_length,
		unsigned char **response, size_t *response_length,
		char **error);

/**
 * \ingroup http
 *
 * Creates a timestamp for the given data hash using the signing service
 * on the given URL.
 *
 * \param hash \c (in)  - The data hash to create the timestamp for.
 * \param url \c (in) - The signing service to use.
 * \param timestamp \c (out) - Pointer that will receive pointer to the
 * created timestamp. Use #GTTimestamp_free() to release the memory when
 * done.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTHTTP_createTimestampHash(const GTDataHash *hash,
		const char *url, GTTimestamp **timestamp);

/**
 * \ingroup http
 *
 * Creates a timestamp for the given data bytes using the signing service
 * on the given URL.
 *
 * \param data \c (in) - The data to create the timestamp for.
 * \param data_len \c (in) - Length of the data.
 * \param url \c (in) - The signing service to use.
 * \param timestamp \c (out) - Pointer that will receive pointer to the
 * created timestamp. Use #GTTimestamp_free() to release the memory when
 * done.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTHTTP_createTimestampData(const unsigned char *data, size_t data_len,
		const char *url, GTTimestamp **timestamp);

/**
 * \ingroup http
 *
 * Extends the given timestamp using the extending service on the given URL.
 *
 * \param ts_in \c (in) - The timestamp to be extended.
 * \param url \c (in)  - The extending service to use.
 * \param ts_out \c (out) - Pointer that will receive pointer to the
 * newly created timestamp. Use #GTTimestamp_free() to release the memory
 * when done.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTHTTP_extendTimestamp(const GTTimestamp *ts_in,
		const char *url, GTTimestamp **ts_out);

/**
 * \ingroup http
 *
 * Verifies the given timestamp using the given data hash and the
 * publication file from the given URL.
 *
 * \param ts \c (in) - The timestamp to be verified.
 * \param hash \c (in) - The data hash to check the timestamp against.
 * \param ext_url \c (in) - The URL of the extending service.
 * If this is \c NULL, no extension is attempted.
 * \param ext_ts \c (out) - The pointer that will receive a pointer to
 * the extended timestamp if the timestamp is extended during verification.
 * If no extension is performed, \c *ext_ts will be set to \c NULL.
 * If \c ext_ts is \c NULL, the extended timestamp is discarded.
 * \param pub \c (in) - The publications file.
 * Exactly one of \c pub and \c pub_url must be non-\c NULL.
 * \param pub_url \c (in) - The URL to get the publications file from.
 * Exactly one of \c pub and \c pub_url must be non-\c NULL.
 * \param parse \c (in) - The \c explicit_data field of the verification
 * info will be filled if this is non-zero.
 * \param ver \c (out) - Pointer that will receive pointer to
 * verification info.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 * \note On success \c verification_errors should still be checked.
 */
int GTHTTP_verifyTimestampHash(const GTTimestamp *ts,
		const GTDataHash *hash,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver);

/**
 * \ingroup http
 *
 * Verifies the given timestamp using the given data and the
 * publication file from the given URL.
 *
 * \param ts \c (in) - The timestamp to be verified.
 * \param data \c (in) - The data to check the timestamp against.
 * \param data_len \c (in) - Length of the data.
 * \param ext_url \c (in) - The URL of the extending service.
 * If this is \c NULL, no extension is attempted.
 * \param ext_ts \c (out) - The pointer that will receive a pointer to
 * the extended timestamp if the timestamp is extended during verification.
 * If no extension is performed, \c *ext_ts will be set to \c NULL.
 * If \c ext_ts is \c NULL, the extended timestamp is discarded.
 * \param pub \c (in) - The publications file.
 * Exactly one of \c pub and \c pub_url must be non-\c NULL.
 * \param pub_url \c (in) - The URL to get the publications file from.
 * Exactly one of \c pub and \c pub_url must be non-\c NULL.
 * \param parse \c (in) - The \c explicit_data field of the verification
 * info will be filled if this is non-zero.
 * \param ver \c (out) - Pointer that will receive pointer to
 * verification info.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 * \note On success \c verification_errors should still be checked.
 */
int GTHTTP_verifyTimestampData(const GTTimestamp *ts,
		const unsigned char *data, size_t data_len,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver);

/**
 * \ingroup http
 *
 * Downloads the publications file from the given URL.
 *
 * \param url \c (in) - Publications file URL.
 * \param pub \c (out) - Pointer that will receive pointer to the
 * publications file. Use #GTPublicationsFile_free() to release
 * the memory when done.
 * \return status code (\c GT_OK, when operation succeeded, otherwise
 * an error code).
 */
int GTHTTP_getPublicationsFile(const char *url, GTPublicationsFile **pub);

#ifdef __cplusplus
}
#endif

#endif /* not GTHTTP_H_INCLUDED */
