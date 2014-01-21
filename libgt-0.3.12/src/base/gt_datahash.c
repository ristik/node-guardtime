/*
 * $Id: gt_datahash.c 74 2010-02-22 11:42:26Z ahto.truu $
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

#include <assert.h>

#include <openssl/evp.h>

#include "gt_internal.h"
#include "hashchain.h"

int GTDataHash_create(int hash_algorithm,
		const unsigned char* data, size_t data_length, GTDataHash **data_hash)
{
	int res = GT_UNKNOWN_ERROR;
	EVP_MD_CTX md_ctx;
	const EVP_MD *evp_md;
	GTDataHash *tmp_data_hash = NULL;
	unsigned char* tmp_hash = NULL;
	size_t tmp_length;
	unsigned int digest_length;

	if ((data == NULL && data_length != 0) || data_hash == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!GT_isSupportedHashAlgorithm(hash_algorithm)) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	evp_md = GT_hashChainIDToEVP(hash_algorithm);
	if (evp_md == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_data_hash = GT_malloc(sizeof(GTDataHash));
	if (tmp_data_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp_data_hash->digest = NULL;
	tmp_data_hash->context = NULL;

	tmp_length = EVP_MD_size(evp_md);
	tmp_hash = GT_malloc(tmp_length);
	if (tmp_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	EVP_DigestInit(&md_ctx, evp_md);
	EVP_DigestUpdate(&md_ctx, data, data_length);
	EVP_DigestFinal(&md_ctx, tmp_hash, &digest_length);
	assert(digest_length == tmp_length);

	tmp_data_hash->digest = tmp_hash;
	tmp_hash = NULL;
	tmp_data_hash->digest_length = tmp_length;
	tmp_data_hash->algorithm = hash_algorithm;
	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;

	res = GT_OK;

cleanup:
	GT_free(tmp_hash);
	GTDataHash_free(tmp_data_hash);

	return res;
}

/**/

int GTDataHash_open(int hash_algorithm, GTDataHash **data_hash)
{
	int res = GT_UNKNOWN_ERROR;
	const EVP_MD *evp_md;
	GTDataHash *tmp_data_hash = NULL;

	if (data_hash == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!GT_isSupportedHashAlgorithm(hash_algorithm)) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	evp_md = GT_hashChainIDToEVP(hash_algorithm);
	if (evp_md == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_data_hash = GT_malloc(sizeof(GTDataHash));
	if (tmp_data_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp_data_hash->digest = NULL;
	tmp_data_hash->context = NULL;

	tmp_data_hash->context = GT_malloc(sizeof(EVP_MD_CTX));
	if (tmp_data_hash->context == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_data_hash->algorithm = hash_algorithm;
	tmp_data_hash->digest_length = EVP_MD_size(evp_md);

	EVP_DigestInit(tmp_data_hash->context, evp_md);

	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;

	res = GT_OK;

cleanup:
	GTDataHash_free(tmp_data_hash);

	return res;
}

/**/

int GTDataHash_add(GTDataHash *data_hash,
		const unsigned char* data, size_t data_length)
{
	int res = GT_UNKNOWN_ERROR;

	if (data_hash == NULL || data_hash->context == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (data == NULL && data_length != 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	EVP_DigestUpdate(data_hash->context, data, data_length);

	res = GT_OK;

cleanup:

	return res;
}

/**/

int GTDataHash_close(GTDataHash *data_hash)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char* tmp_hash = NULL;
	unsigned int digest_length;

	if (data_hash == NULL || data_hash->context == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_hash = GT_malloc(data_hash->digest_length);
	if (tmp_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	EVP_DigestFinal(data_hash->context, tmp_hash, &digest_length);
	assert(digest_length == data_hash->digest_length);

	data_hash->digest = tmp_hash;
	tmp_hash = NULL;

	GT_free(data_hash->context);
	data_hash->context = NULL;

	res = GT_OK;

cleanup:

	return res;
}

/**/

void GTDataHash_free(GTDataHash *data_hash)
{
	if (data_hash != NULL) {
		GT_free(data_hash->digest);
		GT_free(data_hash->context);
		GT_free(data_hash);
	}
}

/**/

const char* GTHash_oid(int hash_algorithm)
{
	if (GT_isSupportedHashAlgorithm(hash_algorithm)) {
		/* Note that we cant use OBJ_nid2txt() or similar functions here
		 * without major thread safety issues --- we are expected to return
		 * pointer to the read only string constant. */
		switch ((enum GTHashAlgorithm) hash_algorithm) {
		case GT_HASHALG_SHA1:
			return "1.3.14.3.2.26";
		case GT_HASHALG_SHA256:
			return "2.16.840.1.101.3.4.2.1";
		case GT_HASHALG_RIPEMD160:
			return "1.3.36.3.2.1";
		case GT_HASHALG_SHA224:
			return "2.16.840.1.101.3.4.2.4";
		case GT_HASHALG_SHA384:
			return "2.16.840.1.101.3.4.2.2";
		case GT_HASHALG_SHA512:
			return "2.16.840.1.101.3.4.2.3";
		case GT_HASHALG_DEFAULT:
			/* Not a real hash algorithm but just a special value. */
			return NULL;
		}
	}

	return NULL;
}
