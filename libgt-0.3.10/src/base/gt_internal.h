/*
 * $Id: gt_internal.h 74 2010-02-22 11:42:26Z ahto.truu $
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

#ifndef GT_INTERNAL_H_INCLUDED
#define GT_INTERNAL_H_INCLUDED

#include "gt_base.h"
#include "gt_asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This type is used for history and publication identifiers. It is basically
 * a 64-bit unsigned value and should be used with caution as printf()-style
 * function arguments.
 */
typedef GT_UInt64 GT_HashDBIndex;

/**
 * Convert ASN1_GENERALIZEDTIME to struct tm type.
 * Unfortunately OpenSSL does not provide such function.
 * \param genTime \c (in)	- UTC value.
 * \param the_time \c (out)	- structure that will hold all parsed values
 * 				separately: year, month, day, hour, minute,
 * 				second.
 * 				Other fields aren't calculated.
 * \return			- GT_ error code.
 *
 * \note Current implementation of this function assumes that input value is
 * set by ASN1_GENERALIZEDTIME_set() and returns error if input value is not
 * expressed in UTC but in local time or with UTC offset.
 */
int GT_GENERALIZEDTIME_get(const ASN1_GENERALIZEDTIME* genTime,
		struct tm* the_time);

/**
 * This function returns \param data \c (in) presented in hex form (xx:xx:xx..)
 * through a dynamically allocated \param hex \c (out),
 * which must be GT_free()-d after use.
 * \return	- GT_ error code.
 */
int GT_hexEncode(const void* data, size_t data_length, char** hex);

/**
 * Converts given unsigned 64-bit value to ASN1_INTEGER.
 *
 * \return 1 on success, 0 on failure.
 */
int GT_uint64ToASN1Integer(ASN1_INTEGER *dst, GT_UInt64 src);

/**
 * Converts given ASN1_INTEGER to the unsigned 64-bit value.
 *
 * \return 1 on success, 0 on failure.
 */
int GT_asn1IntegerToUint64(GT_UInt64 *dst, const ASN1_INTEGER *src);

/**
 *  Analyzes given response status and returns either GT_OK or
 *  error.
 *
 *  \param status Response status to be analysed.
 *  \return GT_OK or error code.
 *  \note Use GT_getErrorString() to get human readable error string.
 */
int GT_analyseResponseStatus(const GTPKIStatusInfo *status);

/**
 * Checks if given stack of unhandled X509_EXTENSIONs contains critical ones.
 *
 * \param unhandled_extensions Input stack. It should contain only those
 * extensions that are not yet handled.
 *
 * \return \c GT_OK if there were no critical extensions,
 * \c GT_UNSUPPORTED_FORMAT if at least one critical extension was
 * found or any other error code for other errors.
 */
int GT_checkUnhandledExtensions(
		const STACK_OF(X509_EXTENSION) *unhandled_extensions);

/**
 * Extracts accuracy info from the given GTAccuracy structure.
 *
 * \param accuracy Input structure. Can be a null pointer, so there's no
 * need to check presence of accuracy info before calling this function.
 *
 * \param seconds Pointer to the integer value receiving extracted seconds part
 * of the accuracy or null pointer if not interested.
 *
 * \param millis Pointer to the integer value receiving extracted
 * milliseconds part of the accuracy or null pointer if not interested.
 *
 * \param micros Pointer to the integer value receiving extracted
 * microseconds part of the accuracy or null pointer if not interested.
 *
 * \return \c GT_OK on success, an error code otherwise.
 *
 * \note Negative value (-1) is returned for all three output values if
 * accuracy info is not present at all. Make sure that you check this
 * before using these values!
 */
int GT_getAccuracy(const GTAccuracy *accuracy,
		int *seconds, int *millis, int *micros);

/**
 * Converts given GENERAL_NAME structure into human-readable string.
 *
 * \param general_name Input structure. Can be a null pointer in which case
 * null pointer will be returned.
 *
 * \param result Pointer to the pointer taht receives output value or null
 * pointer depending on the input value. This must be freed with
 * \c GT_free() after use.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_getGeneralName(
		const GENERAL_NAME *general_name,
		char **result);

/**
 * Create data imprint (ASN1_OCTET_STRING) from MessageImprint.
 *
 * \param message_imprint Input parameter - data to convert
 * \param data_imprint Result is placed here
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_messageImprintToDataImprint(
		const GTMessageImprint* message_imprint,
		ASN1_OCTET_STRING** data_imprint);

/**
 * Performs consistency check required by the timestamp extension procedure.
 */
int GT_extendConsistencyCheck(
		const GTTimeSignature *time_signature,
		const GTCertToken *cert_token);

/**
 * Creates extended time signature for the given short term signature and
 * cert token.
 *
 * \note \p pub_reference can be a null pointer, in which case the value inside
 * the \p cert_token will be used instead.
 */
int GT_extendTimeSignature(
		const GTTimeSignature *time_signature,
		const GTCertToken *cert_token,
		const STACK_OF(ASN1_OCTET_STRING) *pub_reference,
		GTTimeSignature **extended_time_signature);

/**
 * Decodes base32-encoded DER-encoded published data.
 *
 * \param publication \c (in) - base32-encoded DER-encoded published data.
 *
 * \param publication_length \c (in) - Length on \p publication or -1 if
 * length is not known and \p publication is null terminated C-string.
 *
 * \param published_data \c (out) - Pointer to pointer that receives
 * newly allocated decoded \c GTPublishedData structure.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_base32ToPublishedData(
		const char *publication, int publication_length,
		GTPublishedData **published_data);

/**
 * Converts given published data structure to base32 encoded representation.
 *
 * \param published_data \c (in) - Input structure.
 *
 * \param publication \c (out) - This pointer receives extracted human
 * readable publication value as an ordinary C-string on success. This
 * value must be freed with \c GT_free() later when not needed anymore.
 *
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GT_publishedDataToBase32(
		const GTPublishedData *published_data, char **publication);

/**
 * Checks if tha reason of the last failed OpenSSL function was
 * ERR_R_MALLOC_FAILURE. Note that you must call ERR_clear_error() before
 * calling the function that can fail. This ensures that this function will not
 * be confused.
 *
 * \return 1 if the reason was ERR_R_MALLOC_FAILURE, 0 otherwise.
 *
 * \note This function leaves error stack intact.
 */
int GT_isMallocFailure();

#ifdef __cplusplus
}
#endif

#endif /* not GT_INTERNAL_H_INCLUDED */
