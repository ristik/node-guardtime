/*
 * $Id: gt_internal.c 135 2013-09-20 14:57:14Z henri.lakk $
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

#include "gt_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>

#include "hashchain.h"
#include "base32.h"
#include "gt_crc32.h"

#ifdef _WIN32
#define snprintf _snprintf
#endif

/**/

int GT_GENERALIZEDTIME_get(const ASN1_GENERALIZEDTIME* genTime,
			struct tm* the_time)
{
	assert(genTime != NULL && the_time != NULL);

	/* WARNING: This function cannot be used as a general decoder for
	 * ASN1_GENERALIZEDTIME values because it assumes that input value is
	 * expressed in UTC timezone (value ends with Z). However, this condition
	 * is satisfied for values set by ASN1_GENERALIZEDTIME_set().
	 */
	if (!ASN1_GENERALIZEDTIME_check((ASN1_GENERALIZEDTIME*)genTime) ||
			genTime->data[genTime->length - 1] != 'Z') {
		return GT_INVALID_FORMAT;
	}

	memset(the_time, 0, sizeof(*the_time));

	/* HACK: ASN1_GENERALIZEDTIME is actually ASN1_STRING.
	 * OpenSSL doesn't provide any functions of getting the time out of
	 * the structure. Such a pity...
	 */
	sscanf((const char*)genTime->data, "%04d%02d%02d%02d%02d%02d",
			&the_time->tm_year, &the_time->tm_mon, &the_time->tm_mday,
			&the_time->tm_hour, &the_time->tm_min, &the_time->tm_sec);

	the_time->tm_year -= 1900;
	the_time->tm_mon--;

	return GT_OK;
}

int GT_hexEncode(const void* data, size_t data_length, char** hex)
{
	int res = GT_UNKNOWN_ERROR;
	char *tmp_hex = NULL, *tmp;
	const unsigned char* ptr = data;
	size_t c, tmp_hex_size = data_length * 3;

	assert(data != NULL && hex != NULL);

	if (tmp_hex_size == 0) {
		tmp_hex_size = 1;
	}

	tmp_hex = tmp = GT_malloc(tmp_hex_size);
	if (tmp_hex == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (c = 0; c < data_length; c++) {
		unsigned int i = *ptr;
		snprintf(tmp, c == data_length - 1 ? 3 : 4,
				c == data_length - 1 ? "%02x" : "%02x:", i);
		ptr++;
		tmp += 3;
	}

	tmp_hex[tmp_hex_size - 1] = '\0';
	*hex = tmp_hex;
	tmp_hex = NULL;
	res = GT_OK;

cleanup:
	GT_free(tmp_hex);

	return res;
}

/**/

int GT_uint64ToASN1Integer(ASN1_INTEGER *dst, GT_UInt64 src)
{
	int retval = 0;
	int i, j, k;
	GT_UInt64 d;
	unsigned char buf[sizeof(GT_UInt64)];

	if (dst == NULL) {
		goto e;
	}

	dst->type = V_ASN1_INTEGER;
	if (dst->length < (int) sizeof(GT_UInt64)) {
		OPENSSL_free(dst->data);
		dst->data = OPENSSL_malloc(sizeof(GT_UInt64));
		if (dst->data == NULL) {
			dst->length = 0;
			goto e;
		}
		dst->length = sizeof(GT_UInt64);
	}

	d = src;

	for (i = 0; d != 0 && i < (int) sizeof(GT_UInt64); ++i) {
		buf[i] = (unsigned char)(d & 0xFF);
		d >>= 8;
	}
	j = 0;
	for (k = i - 1; k >= 0; --k) {
		dst->data[j++] = buf[k];
	}
	dst->length = j;

	retval = 1;

e:

	return retval;
}

/**/

int GT_asn1IntegerToUint64(GT_UInt64 *dst, const ASN1_INTEGER *src)
{
	int retval = 0;
	int i;
	GT_UInt64 result;

	if (src == NULL || dst == NULL) {
		goto e;
	}

	/* Negative values are not supported for obvious reasons. */
	if (src->type != V_ASN1_INTEGER) {
		goto e;
	}

	/* Check for overflow. */
	if (src->length > (int) sizeof(GT_UInt64)) {
		goto e;
	}

	result = 0;
	for (i = 0; i < src->length; ++i) {
		result <<= 8;
		result |= (unsigned char) src->data[i];
	}
	*dst = result;

	retval = 1;

e:

	return retval;
}

/**/

int GT_analyseResponseStatus(const GTPKIStatusInfo *status)
{
	int res = GT_UNKNOWN_ERROR;
	long pki_status = ASN1_INTEGER_get(status->status);

	if (pki_status != GTPKIStatus_granted) {
		if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_badAlg)) {
			res = GT_PKI_BAD_ALG;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_badRequest)) {
			res = GT_PKI_BAD_REQUEST;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_badDataFormat)) {
			res = GT_PKI_BAD_DATA_FORMAT;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
			GTPKIFailureInfo_unacceptedPolicy)) {
			res = GT_UNACCEPTED_POLICY;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_unacceptedExtension)) {
			res = GT_PROTOCOL_MISMATCH;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_systemFailure)) {
			res = GT_PKI_SYSTEM_FAILURE;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_extendLater)) {
			res = GT_NONSTD_EXTEND_LATER;
		} else if (ASN1_BIT_STRING_get_bit(status->failInfo,
					GTPKIFailureInfo_extensionOverdue)) {
			res = GT_NONSTD_EXTENSION_OVERDUE;
		}

		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

/**/

int GT_checkUnhandledExtensions(
		const STACK_OF(X509_EXTENSION) *unhandled_extensions)
{
	int res;

	if (unhandled_extensions == NULL) {
		res = GT_OK;
		goto cleanup;
	}

	if (X509v3_get_ext_by_critical(unhandled_extensions, 1, -1) >= 0) {
		res = GT_UNSUPPORTED_FORMAT;
		goto cleanup;
	}

	res = GT_OK;

cleanup:
	return res;
}

/**/

int GT_getAccuracy(const GTAccuracy *accuracy,
		int *seconds, int *millis, int *micros)
{
	int res;
	int out_sec = -1;
	int out_mil = -1;
	int out_mic = -1;
	long tmp_val;

	if (accuracy == NULL ||
			(accuracy->seconds == NULL &&
			 accuracy->millis == NULL &&
			 accuracy->micros == NULL)) {
		res = GT_OK;
		goto cleanup;
	}

	if (accuracy->seconds == NULL) {
		out_sec = 0;
	} else {
		tmp_val = ASN1_INTEGER_get(accuracy->seconds);
		if (tmp_val < 0) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		out_sec = tmp_val;
	}

	if (accuracy->millis == NULL) {
		out_mil = 0;
	} else {
		tmp_val = ASN1_INTEGER_get(accuracy->millis);
		if (tmp_val < 1 || tmp_val > 999) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		out_mil = tmp_val;
	}

	if (accuracy->micros != NULL) {
		tmp_val = ASN1_INTEGER_get(accuracy->micros);
		if (tmp_val < 1 || tmp_val > 999) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		out_mic = tmp_val;
	}

	res = GT_OK;

cleanup:
	if (res == GT_OK) {
		if (seconds != NULL) {
			*seconds = out_sec;
		}
		if (millis != NULL) {
			*millis = out_mil;
		}
		if (micros != NULL) {
			*micros = out_mic;
		}
	}

	return res;
}

/**/

int GT_getGeneralName(
		const GENERAL_NAME *general_name,
		char **result)
{
	int res;
	BIO *mem = NULL;
	char *mem_data;
	long mem_len;
	char *tmp_result = NULL;

	if (result == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (general_name != NULL) {
		mem = BIO_new(BIO_s_mem());
		if (mem == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}

		if (!GENERAL_NAME_print(mem, (GENERAL_NAME*) general_name)) {
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}

		mem_len = BIO_get_mem_data(mem, &mem_data);

		tmp_result = GT_malloc(mem_len + 1);
		if (tmp_result == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}

		memcpy(tmp_result, mem_data, mem_len);
		tmp_result[mem_len] = '\0';
	}

	*result = tmp_result;
	tmp_result = NULL;

	res = GT_OK;

cleanup:
	BIO_free(mem);
	GT_free(tmp_result);

	return res;
}

/**
 * The function \p GT_MessageImprintToDataImprint converts from
 * one format of the message imprints to another. A message imprint
 * is a hash algorithm ID together with a bit-string that is apparently
 * a result of applying that hash algorithm to some data. The length
 * of the bit-string must equal the output length of the hash algorithm.
 *
 * In \p GTMessageImprint, the bit-string is stored in the field
 * \p hashedMessage (as a sequence of bytes, eight bits per byte) and
 * the hash algorithm ID in the field hashAlgorithm. The type of
 * hashAlgorithm is the standard OpenSSL type for algorithm identifiers.
 * Standard Object Identifiers are used.
 *
 * A \e DataImprint is a single string of bytes. Its first byte is the
 * hash algorithm identifier. The identifiers for certain hash algorithms
 * have been defined in the project. This byte is followed by the
 * bit-string (eight bits per byte).
 */

int GT_messageImprintToDataImprint(
		const GTMessageImprint* message_imprint,
		ASN1_OCTET_STRING** data_imprint)
{
	int res = GT_UNKNOWN_ERROR;
	ASN1_OCTET_STRING* result = NULL;
	unsigned char buff[1 + EVP_MAX_MD_SIZE];
	int hash_alg;
	size_t len;

	if (message_imprint == NULL || data_imprint == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	hash_alg = GT_EVPToHashChainID(
			EVP_get_digestbyobj(message_imprint->hashAlgorithm->algorithm));
	if (hash_alg < 0) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	len = ASN1_STRING_length(message_imprint->hashedMessage);
	if (len != GT_getHashSize(hash_alg)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	assert(len <= EVP_MAX_MD_SIZE);

	buff[0] = hash_alg;
	memcpy(buff + 1, ASN1_STRING_data(message_imprint->hashedMessage), len);

	result = ASN1_OCTET_STRING_new();
	if (result == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (ASN1_STRING_set(result, buff, len + 1) == 0) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*data_imprint = result;
	result = NULL;
	res = GT_OK;

cleanup:
	ASN1_OCTET_STRING_free(result);

	return res;
}

/**
 * In the following we can see several sets of functions to iterate
 * over data structures that can be seen as sequences of bit-strings.
 * Each set also contains a data type \p readXXState where the internal
 * state is kept between the invocations.
 *
 * A set of such functions contains:
 *  - \p readXXInit: takes the data structure XX and a pointer to
 *    the initial state; and initializes the state. The state is not yet
 *    ready for reading (call \p readXXAdvance before it).
 *  - \p readXXAdvance: takes the internal state and modifies it so that
 *    it now points to the next bit-string in the sequence.
 *  - \p readXXPeekImprint: takes the internal state and returns the
 *    bit-string it is currently pointing to.
 *  - \p readXXEOF: takes the internal state and returns whether it has
 *    already moved past the last bit-string in the sequence. If EOF is
 *    true then the results of reading or further advancing the state
 *    are undefined.
 *
 * There are also sets of functions to iterate over data structures that
 * can be seen as sequences of bits. In this case, \p readXXPeekImprint is
 * replaced with \p readXXPeekDir.
 *
 * XX may stand for
 *  - HC (hash chain). It is both a sequence of bit-strings and a sequence
 *    of (direction) bits. I.e. there are both \p readHCPeekImprint and
 *    \p readHCPeekDir.
 *  - St (the stack of historical imprints). It is a sequence of bit-strings.
 *  - Ro (the sequence number of a long-term timestamp and the sequence
 *    number of the last timestamp in a cycle). With these numbers, the
 *    shape of the hash chain in the long-term timestamp is fixed. We have
 *    here a sequence of bits describing the shape of that hash chain.
 */

/**
 * This internal structure is used to iterate over hash chain.
 */
typedef struct readHCState {
	const unsigned char *data;
	size_t length;
	const unsigned char *pp;
	int eof;
	int onlylefts;
} ReadHCState;

/**
 * Initializes ReadHCState. It may be used in two modes: either it
 * considers all hash steps, or only those steps where the constant
 * dataimprint goes to left.
 */
static void readHCInit(const ASN1_OCTET_STRING *hash_chain,
						ReadHCState *state, int init_onlylefts)
{
	state->data = hash_chain->data;
	state->length = hash_chain->length;
	state->pp = NULL;
	state->eof = 0;
	state->onlylefts = init_onlylefts;
}

/**
 * Helper for readHCAdvance().
 */
static void stepOverHashStep(ReadHCState *state)
{
	size_t datalen;

	if ((state->pp + 2) - state->data >= (int) state->length) {
		state->eof = 1;
		return;
	}
	datalen = GT_getHashSize(state->pp[2]);
	if ((state->pp + datalen + 4) - state->data > (int) state->length) {
		state->eof = 1;
	} else {
		state->pp += datalen + 4;
	}
}

/**
 * Advances ReadHCState to the next or first (if called on first time) hash
 * step.
 */
static void readHCAdvance(ReadHCState *state)
{
	size_t datalen;

	if (state->pp == NULL) {
		state->pp = state->data;
	} else {
		stepOverHashStep(state);
		if (state->eof) {
			return;
		}
	}
	for (;;) {
		if ((state->pp + 2) - state->data >= (int) state->length) {
			state->eof = 1;
			return;
		}
		if (state->pp[1] == 0 || !state->onlylefts) {
			datalen = GT_getHashSize(state->pp[2]);
			if ((state->pp + datalen + 4) - state->data > (int) state->length) {
				state->eof = 1;
			}
			return;
		}
		stepOverHashStep(state);
		if (state->eof) {
			return;
		}
	}
}

/**
 * Reads data imprint value (algorithm byte + hash value) of the current
 * hash step. Returned data points inside the hashchain and should not be
 * freed.
 */
static void readHCPeekImprint(ReadHCState *state,
				 const unsigned char **from, size_t *len)
{
	assert(!state->eof);
	assert(state->pp != NULL);
	assert((state->pp + 2) - state->data < (int) state->length);
	*len = GT_getHashSize(state->pp[2]) + 1;
	assert((state->pp + (*len) + 3) - state->data <= (int) state->length);
	*from = state->pp + 2;
}

/**
 * Returns true if end of hash chain is reached.
 */
static int readHCEof(ReadHCState *state)
{
	return state->eof;
}

/**
 * Internal function for comparing of the history imprints in the two hash
 * chains.
 */
static int compareHashChainHistoryImprints(
		const ASN1_OCTET_STRING *hash_chain_1,
		const ASN1_OCTET_STRING *hash_chain_2)
{
	ReadHCState hcstate1;
	ReadHCState hcstate2;
	const unsigned char *hcp1;
	const unsigned char *hcp2;
	size_t hclen1;
	size_t hclen2;

	/* Iterate over the hash chains, considering only dataimprints that go
	 * to the left. Verify that the values match. */
	if (hash_chain_1 == NULL || hash_chain_2 == NULL) {
		return GT_INVALID_ARGUMENT;
	}

	readHCInit(hash_chain_1, &hcstate1, 1);
	readHCInit(hash_chain_2, &hcstate2, 1);

	for (;;) {
		readHCAdvance(&hcstate1);
		readHCAdvance(&hcstate2);
		/* Both chains must contain same number of historical digests and
		 * thus scanning must end at the same time for the check to be
		 * successful. */
		if (readHCEof(&hcstate1)) {
			if (readHCEof(&hcstate2)) {
				/* Success! */
				break;
			}
			/* Hash chain 1 is too short. */
			return GT_CANNOT_EXTEND;
		} else if (readHCEof(&hcstate2)) {
			/* Hash chain 2 is too short. */
			return GT_CANNOT_EXTEND;
		}
		readHCPeekImprint(&hcstate1, &hcp1, &hclen1);
		readHCPeekImprint(&hcstate2, &hcp2, &hclen2);
		if (hclen1 != hclen2 || memcmp(hcp1, hcp2, hclen1) != 0) {
			return GT_CANNOT_EXTEND;
		}
	}

	return GT_OK;
}

/**/

int GT_extendConsistencyCheck(
		const GTTimeSignature *time_signature,
		const GTCertToken *cert_token)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	ASN1_OCTET_STRING *signature_history_shape = NULL;
	GT_HashDBIndex signature_history_identifier;
	ASN1_OCTET_STRING *token_history_shape = NULL;
	GT_HashDBIndex token_history_identifier;

	if (time_signature == NULL || cert_token == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_res = GT_shape(time_signature->history, &signature_history_shape);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_res = GT_findHistoryIdentifier(
			time_signature->publishedData->publicationIdentifier,
			signature_history_shape, NULL, &signature_history_identifier);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_res = GT_shape(cert_token->history, &token_history_shape);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_res = GT_findHistoryIdentifier(
			cert_token->publishedData->publicationIdentifier,
			token_history_shape, NULL, &token_history_identifier);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	if (signature_history_identifier != token_history_identifier) {
		res = GT_CANNOT_EXTEND;
		goto cleanup;
	}

	tmp_res = compareHashChainHistoryImprints(
			cert_token->history, time_signature->history);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	res = GT_OK;

cleanup:
	ASN1_OCTET_STRING_free(signature_history_shape);
	ASN1_OCTET_STRING_free(token_history_shape);

	return res;
}

/**/

int GT_extendTimeSignature(
		const GTTimeSignature *time_signature,
		const GTCertToken *cert_token,
		const STACK_OF(ASN1_OCTET_STRING) *pub_reference,
		GTTimeSignature **extended_time_signature)
{
	int res = GT_UNKNOWN_ERROR;
	GTTimeSignature *tmp_extended_time_signature = NULL;
	ASN1_OCTET_STRING *tmp_octet_string = NULL;
	int i;

	if (time_signature == NULL || cert_token == NULL ||
			extended_time_signature == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (pub_reference == NULL) {
		pub_reference = cert_token->pubReference;
	}

	tmp_extended_time_signature = GTTimeSignature_new();
	if (tmp_extended_time_signature == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!ASN1_OCTET_STRING_set(
				tmp_extended_time_signature->location,
				ASN1_STRING_data(time_signature->location),
				ASN1_STRING_length(time_signature->location))) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!ASN1_OCTET_STRING_set(
				tmp_extended_time_signature->history,
				ASN1_STRING_data(cert_token->history),
				ASN1_STRING_length(cert_token->history))) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	GTPublishedData_free(tmp_extended_time_signature->publishedData);
	tmp_extended_time_signature->publishedData =
		ASN1_item_dup(ASN1_ITEM_rptr(GTPublishedData),
				cert_token->publishedData);
	if (tmp_extended_time_signature->publishedData == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	assert(tmp_extended_time_signature->pkSignature == NULL);
	assert(tmp_extended_time_signature->pubReference == NULL);

	if (pub_reference != NULL && sk_ASN1_OCTET_STRING_num(pub_reference) > 0) {
		tmp_extended_time_signature->pubReference = sk_ASN1_OCTET_STRING_new_null();
		if (tmp_extended_time_signature->pubReference == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}

		for (i = 0; i < sk_ASN1_OCTET_STRING_num(pub_reference); ++i) {
			tmp_octet_string = ASN1_OCTET_STRING_dup(
					(ASN1_OCTET_STRING*) sk_ASN1_OCTET_STRING_value(pub_reference, i));
			if (tmp_octet_string == NULL) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}

			if (sk_ASN1_OCTET_STRING_push(tmp_extended_time_signature->pubReference,
						tmp_octet_string) == 0) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}
			tmp_octet_string = NULL;
		}
	}

	*extended_time_signature = tmp_extended_time_signature;
	tmp_extended_time_signature = NULL;

	res = GT_OK;

cleanup:
	GTTimeSignature_free(tmp_extended_time_signature);
	ASN1_OCTET_STRING_free(tmp_octet_string);

	return res;
}

/**/

int GT_base32ToPublishedData(
		const char *publication, int publication_length,
		GTPublishedData **published_data)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	GTPublishedData *tmp_published_data = NULL;
	int i;
	unsigned long tmp_ulong;
	GT_UInt64 tmp_uint64;
	int hash_alg;
	size_t hash_size;

	if (publication_length < 0) {
		publication_length = strlen(publication);
	}

	binary_publication = GT_base32Decode(
			publication, publication_length, &binary_publication_length);
	if (binary_publication == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (binary_publication_length < 13) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	tmp_ulong = 0;
	for (i = 0; i < 4; ++i) {
		tmp_ulong <<= 8;
		tmp_ulong |= binary_publication[binary_publication_length - 4 + i];
	}

	if (GT_crc32(binary_publication, binary_publication_length - 4, 0) !=
			tmp_ulong) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	tmp_published_data = GTPublishedData_new();
	if (tmp_published_data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_uint64 = 0;
	for (i = 0; i < 8; ++i) {
		tmp_uint64 <<= 8;
		tmp_uint64 |= binary_publication[i];
	}

	if (!GT_uint64ToASN1Integer(
				tmp_published_data->publicationIdentifier, tmp_uint64)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	hash_alg = binary_publication[8];
	if (!GT_isSupportedHashAlgorithm(hash_alg)) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	hash_size = GT_getHashSize(hash_alg);
	if (binary_publication_length != 8 + 1 + hash_size + 4) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (!ASN1_STRING_set(
				tmp_published_data->publicationImprint,
				binary_publication + 8,
				hash_size + 1)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*published_data = tmp_published_data;
	tmp_published_data = NULL;

	res = GT_OK;

cleanup:
	OPENSSL_free(binary_publication);
	GTPublishedData_free(tmp_published_data);

	return res;
}

/**/

int GT_publishedDataToBase32(
		const GTPublishedData *published_data, char **publication)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	GT_UInt64 publication_identifier;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	int i;
	GT_UInt64 tmp_uint64;
	unsigned long tmp_ulong;
	char *s;
	char *tmp_publication = NULL;

	if (published_data == NULL ||
			published_data->publicationIdentifier == NULL ||
			published_data->publicationImprint == NULL ||
			publication == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_res = GT_checkDataImprint(published_data->publicationImprint);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	if (!GT_asn1IntegerToUint64(
				&publication_identifier,
				published_data->publicationIdentifier)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	binary_publication_length =
		8 + ASN1_STRING_length(published_data->publicationImprint) + 4;
	binary_publication = OPENSSL_malloc(binary_publication_length);
	if (binary_publication == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_uint64 = publication_identifier;
	for (i = 7; i >= 0; --i) {
		binary_publication[i] = (unsigned char) (tmp_uint64 & 0xff);
		tmp_uint64 >>= 8;
	}

	memcpy(binary_publication + 8,
			ASN1_STRING_data(published_data->publicationImprint),
			ASN1_STRING_length(published_data->publicationImprint));

	tmp_ulong = GT_crc32(binary_publication, binary_publication_length - 4, 0);
	for (i = 3; i >= 0; --i) {
		binary_publication[binary_publication_length - 4 + i] =
			(unsigned char) (tmp_ulong & 0xff);
		tmp_ulong >>= 8;
	}

	tmp_publication =
		GT_base32Encode(binary_publication, binary_publication_length, 6);
	if (tmp_publication == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* This string duplication is necessary because we dont want to return
	 * OPENSSL_malloc()-ed data in public API. */
	s = GT_malloc(strlen(tmp_publication) + 1);
	if (s == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	strcpy(s, tmp_publication);
	*publication = s;

	res = GT_OK;

cleanup:
	OPENSSL_free(binary_publication);
	OPENSSL_free(tmp_publication);

	return res;
}

/**/

int GT_isMallocFailure()
{
	/* Check if the earliest reason was malloc failure. */
	if (ERR_GET_REASON(ERR_peek_error()) == ERR_R_MALLOC_FAILURE) {
		return 1;
	}

	/* The following statement is not strictly necessary because main reason
	 * is the earliest one and there are usually nested fake reasons like
	 * ERR_R_NESTED_ASN1_ERROR added later (for traceback). However, it can
	 * be useful if error stack was not properly cleared before failed
	 * operation and there are no abovementioned fake reason codes present. */
	if (ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_MALLOC_FAILURE) {
		return 1;
	}

	return 0;
}
