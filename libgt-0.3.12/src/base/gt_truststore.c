/*
 * $Id: gt_truststore.c 203 2014-01-28 23:16:24Z risto.laanoja $
 *
 * Copyright 2008-2013 GuardTime AS
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

#include <assert.h>
#include <string.h>

#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "gt_base.h"

#ifndef _WIN32
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

/*
 * The following global variable holds the trust store as a shared resource.
 */
X509_STORE *GT_truststore = NULL;

int GTTruststore_init(int set_defaults)
{
	int res = GT_UNKNOWN_ERROR;

	/* Do nothing if truststore initialized. */
	if (GT_truststore != NULL) {
		res = GT_OK;
		goto cleanup;
	}

	GT_truststore = X509_STORE_new();
	if (GT_truststore == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (set_defaults) {
		/* Set system default paths. */
		if (!X509_STORE_set_default_paths(GT_truststore)) {
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}

		/* Set lookup file for trusted CA certificates if specified. */
#ifdef OPENSSL_CA_FILE
		res = GTTruststore_addLookupFile(OPENSSL_CA_FILE);
		if (res != GT_OK) {
			goto cleanup;
		}
#endif

	/* Set lookup directory for trusted CA certificates if specified. */
#ifdef OPENSSL_CA_DIR
		res = GTTruststore_addLookupDir(OPENSSL_CA_DIR);
		if (res != GT_OK) {
			goto cleanup;
		}
#endif
	}

	res = GT_OK;

cleanup:

	if (res != GT_OK) {
		GTTruststore_finalize();
	}
	return res;
}

/**/

void GTTruststore_finalize(void)
{
	if (GT_truststore != NULL) {
		X509_STORE_free(GT_truststore);
		GT_truststore = NULL;
	}
}

/**/

int GTTruststore_addLookupFile(const char *path)
{
	int res = GT_UNKNOWN_ERROR;
	X509_LOOKUP *lookup = NULL;

	if (GT_truststore == NULL) {
		/* Create an empty trustrore. */
		res = GTTruststore_init(0);
		if (res != GT_OK) goto cleanup;
	}

	if (path == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	lookup = X509_STORE_add_lookup(GT_truststore, X509_LOOKUP_file());
	if (lookup == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM)) {
		res = GT_PKI_BAD_DATA_FORMAT;
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

/**/

int GTTruststore_addLookupDir(const char *path)
{
	int res = GT_UNKNOWN_ERROR;
	X509_LOOKUP *lookup = NULL;

	if (GT_truststore == NULL) {
		/* Create an empty trustrore. */
		res = GTTruststore_init(0);
		if (res != GT_OK) goto cleanup;
	}

	if (path == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	lookup = X509_STORE_add_lookup(GT_truststore, X509_LOOKUP_hash_dir());
	if (lookup == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
		res = GT_PKI_BAD_DATA_FORMAT;
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

/**/

int GTTruststore_reset(int keep_defaults)
{
	assert(GT_truststore != NULL);

	GTTruststore_finalize();
	return GTTruststore_init(keep_defaults);
}

int GTTruststore_addCert(const char *pem) {
	int res = GT_UNKNOWN_ERROR;
	BIO *bio = NULL;
	X509 *cert = NULL;

	if (GT_truststore == NULL) {
		res = GTTruststore_init(0);
		if (res != GT_OK) goto cleanup;
	}


	bio = BIO_new_mem_buf((char *) pem, -1);
	if (bio == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (cert == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!X509_STORE_add_cert(GT_truststore, cert)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	res = GT_OK;

cleanup:
	BIO_free(bio);
	X509_free(cert);

	return res;
}
