/*
 * $Id: gt_info.c 74 2010-02-22 11:42:26Z ahto.truu $
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

#include "gt_base.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static int printInfo(FILE *f, int indent, const char *format, ...)
#ifdef __GNUC__
	__attribute__ ((format (printf, 3, 4)))
#endif
;

/**/

static const char* timeToString(
		GT_Time_t64 time_in, char *buf, size_t buf_size)
{
	time_t time_buf;

	time_buf = time_in;

	if (strftime(buf, buf_size,
				"%Y-%m-%d %H:%M:%S %Z", localtime(&time_buf)) == 0) {
		strcpy(buf, "strftime() failed");
	}

	return buf;
}

/**/

static void bufAppendErrorOrStatus(
		char *buf, size_t buf_size, const char *str)
{
	size_t l;

	l = strlen(buf);

	if (l > 0 && buf_size - l > 1) {
		strncat(buf, ", ", buf_size - l - 1);
		l = strlen(buf);
	}

	if (buf_size - l > 1) {
		strncat(buf, str, buf_size - l - 1);
	}
}

/**/

static const char* verificationErrorToString(int verification_error)
{
	switch ((enum GTVerificationError) verification_error) {
	case GT_NO_FAILURES:
		return "NO_FAILURES";
	case GT_SYNTACTIC_CHECK_FAILURE:
		return "SYNTACTIC_CHECK_FAILURE";
	case GT_HASHCHAIN_VERIFICATION_FAILURE:
		return "HASHCHAIN_VERIFICATION_FAILURE";
	case GT_PUBLIC_KEY_SIGNATURE_FAILURE:
		return "PUBLIC_KEY_SIGNATURE_FAILURE";
	case GT_NOT_VALID_PUBLIC_KEY_FAILURE:
		return "NOT_VALID_PUBLIC_KEY_FAILURE";
	case GT_WRONG_DOCUMENT_FAILURE:
		return "WRONG_DOCUMENT_FAILURE";
	case GT_NOT_VALID_PUBLICATION:
		return "NOT_VALID_PUBLICATION";
	}

	return "INVALID_OR_UNSUPPORTED_ERROR_CODE";
}

/**/

static const char* verificationStatusToString(int verification_status)
{
	switch ((enum GTVerificationStatus) verification_status) {
	case GT_PUBLIC_KEY_SIGNATURE_PRESENT:
		return "PUBLIC_KEY_SIGNATURE_PRESENT";
	case GT_PUBLICATION_REFERENCE_PRESENT:
		return "PUBLICATION_REFERENCE_PRESENT";
	case GT_DOCUMENT_HASH_CHECKED:
		return "DOCUMENT_HASH_CHECKED";
	case GT_PUBLICATION_CHECKED:
		return "PUBLICATION_CHECKED";
	}

	return "INVALID_OR_UNSUPPORTED_STATUS_CODE";
}

/**/

static const char* bitsToString(
		char *buf, size_t buf_size,
		unsigned int bits, const char* (*mask_to_string_func)(int))
{
	unsigned int mask = 1;

	buf[0] = '\0';

	for (mask = 1; bits != 0; mask <<= 1) {
		if (mask & bits) {
			bufAppendErrorOrStatus(buf, buf_size, mask_to_string_func(mask));
		}
		bits &= ~mask;
	}

	return buf;
}

/**/

static const char* hashAlgName(int hash_alg)
{
	switch ((enum GTHashAlgorithm) hash_alg) {
	case GT_HASHALG_SHA1:
		return "SHA1";
	case GT_HASHALG_SHA256:
		return "SHA256";
	case GT_HASHALG_RIPEMD160:
		return "RIPEMD160";
	case GT_HASHALG_SHA224:
		return "SHA224";
	case GT_HASHALG_SHA384:
		return "SHA384";
	case GT_HASHALG_SHA512:
		return "SHA512";
	case GT_HASHALG_DEFAULT:
		/* Special value, handle as an invalid value. It is present only to
		 * suppress otherwise useful warning about unhandled enumeration
		 * value. */
		break;
	}

	return "*** INVALID OR UNKNOWN ALGORITHM ***";
}

/**/

static int printInfo(FILE *f, int indent, const char *format, ...)
{
	va_list args;
	int i;
	int retval;

	if (indent < 0) {
		indent = 0;
	}

	for (i = 0; i < indent; ++i) {
		putc(' ', f);
	}

	va_start(args, format);
	retval = vfprintf(f, format, args);
	va_end(args);

	putc('\n', f);

	return retval + indent + 1;
}

/**/

static void printSignedAttributeList(
		FILE *f, int indent, const char *signed_attribute_name,
		int count, const GTSignedAttribute *list)
{
	int i;

	for (i = 0; i < count; ++i) {
		printInfo(f, indent, "%s %d:", signed_attribute_name, i);
		indent += 2;
		printInfo(f, indent, "attr_type = %s", list[i].attr_type);
		printInfo(f, indent, "attr_value = %s", list[i].attr_value);
		indent -= 2;
	}
}

/**/

static void printHashEntryList(
		FILE *f, int indent, const char *hash_entry_name,
		int count, const GTHashEntry *list)
{
	int i;

	for (i = 0; i < count; ++i) {
		printInfo(f, indent, "%s %d:", hash_entry_name, i);
		indent += 2;
		printInfo(f, indent, "hash_algorithm = %d (%s)",
				list[i].hash_algorithm, hashAlgName(list[i].hash_algorithm));
		printInfo(f, indent, "direction = %d", list[i].direction);
		printInfo(f, indent, "sibling_hash_algorithm = %d (%s)",
				list[i].sibling_hash_algorithm,
				hashAlgName(list[i].sibling_hash_algorithm));
		printInfo(f, indent, "sibling_hash_value = %s",
				list[i].sibling_hash_value);
		printInfo(f, indent, "level = %d", list[i].level);
		indent -= 2;
	}
}

/**/

static void printReferenceList(
		FILE *f, int indent, const char *reference_name,
		int count, char **list)
{
	int i;

	for (i = 0; i < count; ++i) {
		printInfo(f, indent, "%s %d:", reference_name, i);
		printInfo(f, indent + 2, "%s", list[i]);
	}
}

/**/

void GTVerificationInfo_print(
		FILE *f, int indent, const GTVerificationInfo *vinfo)
{
	char buf[256];
	int i;

	printInfo(f, indent, "version = %d", vinfo->version);
	printInfo(f, indent, "verification_errors = %d (%s)",
			vinfo->verification_errors,
			bitsToString(buf, sizeof(buf),
				vinfo->verification_errors, verificationErrorToString));
	printInfo(f, indent, "verification_status = %d (%s)",
			vinfo->verification_status,
			bitsToString(buf, sizeof(buf),
				vinfo->verification_status, verificationStatusToString));

	printInfo(f, indent, "implicit_data:");
	indent += 2;
	printInfo(f, indent, "location_id = %u.%u.%u.%u",
			(unsigned) (vinfo->implicit_data->location_id >> 48 & 0xffff),
			(unsigned) (vinfo->implicit_data->location_id >> 32 & 0xffff),
			(unsigned) (vinfo->implicit_data->location_id >> 16 & 0xffff),
			(unsigned) (vinfo->implicit_data->location_id & 0xffff));
	printInfo(f, indent, "registered_time = %lu (%s)",
			(unsigned long) vinfo->implicit_data->registered_time,
			timeToString(vinfo->implicit_data->registered_time,
				buf, sizeof(buf)));
	printInfo(f, indent, "public_key_fingerprint = %s",
			vinfo->implicit_data->public_key_fingerprint == NULL ?
			"N/A" : vinfo->implicit_data->public_key_fingerprint);
	printInfo(f, indent, "publication_string = %s",
			vinfo->implicit_data->publication_string == NULL ?
			"N/A" : vinfo->implicit_data->publication_string);
	indent -= 2;

	printInfo(f, indent, "explicit_data:");
	indent += 2;
	if (vinfo->explicit_data == NULL) {
		printInfo(f, indent, "N/A");
	} else {
		printInfo(f, indent, "content_type = %s",
				vinfo->explicit_data->content_type);
		printInfo(f, indent, "signed_data_version = %d",
				vinfo->explicit_data->signed_data_version);
		printInfo(f, indent, "digest_algorithm_count = %d",
				vinfo->explicit_data->digest_algorithm_count);
		printInfo(f, indent, "digest_algorithm_list:");
		for (i = 0; i < vinfo->explicit_data->digest_algorithm_count; ++i) {
			printInfo(f, indent + 2, "digest algorithm %d: %d (%s)",
					i, vinfo->explicit_data->digest_algorithm_list[i],
					hashAlgName(
						vinfo->explicit_data->digest_algorithm_list[i]));
		}
		printInfo(f, indent, "encap_content_type = %s",
				vinfo->explicit_data->encap_content_type);
		printInfo(f, indent, "tst_info_version = %d",
				vinfo->explicit_data->tst_info_version);
		printInfo(f, indent, "policy = %s", vinfo->explicit_data->policy);
		printInfo(f, indent, "hash_algorithm = %d (%s)",
				vinfo->explicit_data->hash_algorithm,
				hashAlgName(vinfo->explicit_data->hash_algorithm));
		printInfo(f, indent, "hash_value = %s",
				vinfo->explicit_data->hash_value);
		printInfo(f, indent, "serial_number = %s",
				vinfo->explicit_data->serial_number);
		printInfo(f, indent, "issuer_request_time = %ld (%s)",
				(long) vinfo->explicit_data->issuer_request_time,
				timeToString(vinfo->explicit_data->issuer_request_time,
					buf, sizeof(buf)));
		printInfo(f, indent, "issuer_accuracy = %llu",
				(unsigned long long) vinfo->explicit_data->issuer_accuracy);
		printInfo(f, indent, "nonce = %s",
				vinfo->explicit_data->nonce == NULL ?
				"N/A" : vinfo->explicit_data->nonce);
		printInfo(f, indent, "issuer_name = %s",
				vinfo->explicit_data->issuer_name);
		printInfo(f, indent, "certificate = %s",
				vinfo->explicit_data->certificate == NULL ?
				"N/A" : vinfo->explicit_data->certificate);
		printInfo(f, indent, "signer_info_version = %d",
				vinfo->explicit_data->signer_info_version);
		printInfo(f, indent, "cert_issuer_name = %s",
				vinfo->explicit_data->cert_issuer_name);
		printInfo(f, indent, "cert_serial_number = %s",
				vinfo->explicit_data->cert_serial_number);
		printInfo(f, indent, "digest_algorithm = %d (%s)",
				vinfo->explicit_data->digest_algorithm,
				hashAlgName(vinfo->explicit_data->digest_algorithm));
		printInfo(f, indent, "signed_attr_count = %d",
				vinfo->explicit_data->signed_attr_count);
		printInfo(f, indent, "signed_attr_list:");
		printSignedAttributeList(f, indent + 2, "signed attribute",
				vinfo->explicit_data->signed_attr_count,
				vinfo->explicit_data->signed_attr_list);
		printInfo(f, indent, "signature_algorithm = %s",
				vinfo->explicit_data->signature_algorithm);
		printInfo(f, indent, "location_count = %d",
				vinfo->explicit_data->location_count);
		printInfo(f, indent, "location_list:");
		printHashEntryList(f, indent + 2, "location hash chain entry",
				vinfo->explicit_data->location_count,
				vinfo->explicit_data->location_list);
		printInfo(f, indent, "history_count = %d",
				vinfo->explicit_data->history_count);
		printInfo(f, indent, "history_list:");
		printHashEntryList(f, indent + 2, "history hash chain entry",
				vinfo->explicit_data->history_count,
				vinfo->explicit_data->history_list);
		printInfo(f, indent, "publication_identifier = %ld (%s)",
				(long) vinfo->explicit_data->publication_identifier,
				timeToString(vinfo->explicit_data->publication_identifier,
					buf, sizeof(buf)));
		printInfo(f, indent, "publication_hash_algorithm = %d",
				vinfo->explicit_data->publication_hash_algorithm);
		printInfo(f, indent, "publication_hash_value = %s",
				vinfo->explicit_data->publication_hash_value);
		printInfo(f, indent, "pki_algorithm = %s",
				vinfo->explicit_data->pki_algorithm == NULL ?
				"N/A" : vinfo->explicit_data->pki_algorithm);
		printInfo(f, indent, "pki_value = %s",
				vinfo->explicit_data->pki_value == NULL ?
				"N/A" : vinfo->explicit_data->pki_value);
		printInfo(f, indent, "key_commitment_ref_count = %d",
				vinfo->explicit_data->key_commitment_ref_count);
		printInfo(f, indent, "key_commitment_ref_list:");
		printReferenceList(f, indent + 2, "reference",
				vinfo->explicit_data->key_commitment_ref_count,
				vinfo->explicit_data->key_commitment_ref_list);
		printInfo(f, indent, "pub_reference_count = %d",
				vinfo->explicit_data->pub_reference_count);
		printInfo(f, indent, "pub_reference_list:");
		printReferenceList(f, indent + 2, "reference",
				vinfo->explicit_data->pub_reference_count,
				vinfo->explicit_data->pub_reference_list);
	}
	indent -= 2;
}
