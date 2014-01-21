/*
 * $Id: gt_base.c 174 2014-01-16 16:23:29Z ahto.truu $
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

#ifdef _WIN32
#include <windows.h>
#else /* _WIN32 */
#include <pthread.h>
#endif /* not _WIN32 */

#include <openssl/evp.h>
#include <openssl/err.h>

#include "gt_internal.h"

#if (OPENSSL_VERSION_NUMBER < 0x00908000L) || defined(OPENSSL_NO_SHA256)
#error "The default hash algorithm (SHA-256) is disabled!"
#endif

/*
 * The following global variable is incremented every time GT_init() is called
 * and decremented every time GT_finalize() is called. The actual initialization
 * and cleanup are done only when the value moves from and to zero.
 */
static int init_count = 0;

/*
 * The following global variable is incremented by one if thread setup has
 * been performed. This is necessary because on some platforms or
 * configurations it is possible that either application or some other
 * library has already provided their own callbacks and we dont want
 * mess with this in this case.
 */
static int thread_setup_done = 0;

#ifdef _WIN32

static HANDLE *lock_cs;

/**/

static void win32LockingCallback(
		int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		WaitForSingleObject(lock_cs[type], INFINITE);
	} else {
		ReleaseMutex(lock_cs[type]);
	}
}

/**/

static int threadSetup(void)
{
	int i;
	int j;

	if (CRYPTO_get_locking_callback() != NULL) {
		/* Locking callback is already installed, dont touch it. */
		return GT_OK;
	}

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
	if (lock_cs == NULL) {
		return GT_OUT_OF_MEMORY;
	}

	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
		if (lock_cs[i] == NULL) {
			for (j = 0; j < i; ++j) {
				CloseHandle(lock_cs[j]);
			}
			OPENSSL_free(lock_cs);
			return GT_OUT_OF_MEMORY;
		}
	}

	CRYPTO_set_locking_callback(win32LockingCallback);

	/* ID callback is not needed on windows according to OpenSSL
	 * documentation. */

	thread_setup_done = 1;

	return GT_OK;
}

/**/

static void threadCleanup(void)
{
	int i;

	if (thread_setup_done) {
		CRYPTO_set_locking_callback(NULL);

		for (i = 0; i < CRYPTO_num_locks(); ++i) {
			CloseHandle(lock_cs[i]);
		}

		OPENSSL_free(lock_cs);

		thread_setup_done = 0;
	}
}

#else /* _WIN32 */

static pthread_mutex_t *lock_cs;

/**/

static void pthreadsLockingCallback(
		int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

/**/

static unsigned long pthreadsThreadId(void)
{
	return (unsigned long) pthread_self();
}

/**/

static int threadSetup(void)
{
	int i;

	if (CRYPTO_get_locking_callback() != NULL) {
		/* Locking callback is already installed, dont touch it. */
		return GT_OK;
	}

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (lock_cs == NULL) {
		return GT_OUT_OF_MEMORY;
	}

	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_set_locking_callback(pthreadsLockingCallback);
	CRYPTO_set_id_callback(pthreadsThreadId);

	thread_setup_done = 1;

	return GT_OK;
}

/**/

static void threadCleanup(void)
{
	int i;

	if (thread_setup_done) {
		CRYPTO_set_locking_callback(NULL);
		CRYPTO_set_id_callback(NULL);

		for (i = 0; i < CRYPTO_num_locks(); ++i) {
			pthread_mutex_destroy(&(lock_cs[i]));
		}

		OPENSSL_free(lock_cs);

		thread_setup_done = 0;
	}
}

#endif /* not _WIN32 */

/**/

int GT_init(void)
{
	int res = GT_UNKNOWN_ERROR;

	if (init_count++ > 0) {
		/* Nothing to do: already initialized. */
		return GT_OK;
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

#if !defined(_WIN32) || defined(OPENSSL_CA_FILE) || defined(OPENSSL_CA_DIR)
	res = GTTruststore_init(1);
	if (res != GT_OK) {
		goto cleanup;
	}
#endif

	/* Create NID for the id-gt-TimeSignatureAlg. */
	ERR_clear_error();
	GT_id_gt_time_signature_alg_nid = OBJ_create(
			GT_ID_GT_TIME_SIGNATURE_ALG_OID,
			GT_ID_GT_TIME_SIGNATURE_ALG_SN,
			GT_ID_GT_TIME_SIGNATURE_ALG_LN);
	if (GT_id_gt_time_signature_alg_nid == 0) {
		res = GT_isMallocFailure() ? GT_OUT_OF_MEMORY : GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	GT_id_gt_time_signature_alg = OBJ_nid2obj(GT_id_gt_time_signature_alg_nid);
	if (GT_id_gt_time_signature_alg == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	res = threadSetup();

cleanup:

	return res;

}

/**/

void GT_finalize(void)
{
	if (--init_count > 0) {
		/* Do nothing: still being used by someone. */
		return;
	}
	/* In theory we should also check for init_count < 0, but
	 * in practice nothing could be done in this case... */
	threadCleanup();
	OBJ_cleanup();
#if !defined(_WIN32) || defined(OPENSSL_CA_FILE) || defined(OPENSSL_CA_DIR)
	GTTruststore_finalize();
#endif
	ERR_free_strings();
	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

/**/

void *GT_malloc(size_t s)
{
	return malloc(s);
}

void *GT_calloc(size_t n, size_t s)
{
	return calloc(n, s);
}

void *GT_realloc(void *p, size_t s)
{
	return realloc(p, s);
}

void GT_free(void *p)
{
	free(p);
}

/**/

const char *GT_getErrorString(int error)
{
	switch (error) {
		case GT_OK:
			return "Success";
		case GT_EARLIER:
			return "Timestamp is earlier";
		case GT_NOT_EARLIER:
			return "Timestamp is not earlier";
		case GT_EXTENDED:
			return "Timestamp is extended";
		case GT_NOT_EXTENDED:
			return "Timestamp is not extended";
		case GT_INVALID_ARGUMENT:
			return "Invalid argument";
		case GT_INVALID_FORMAT:
			return "Invalid format";
		case GT_UNTRUSTED_HASH_ALGORITHM:
			return "Untrusted hash algorithm";
		case GT_UNTRUSTED_SIGNATURE_ALGORITHM:
			return "Untrusted signature algorithm";
		case GT_INVALID_LINKING_INFO:
			return "Missing or malformed linking info";
		case GT_UNSUPPORTED_FORMAT:
			return "Unsupported format";
		case GT_DIFFERENT_HASH_ALGORITHMS:
			return "Compared hashes are created using different "
				"hash algorithms";
		case GT_PKI_BAD_ALG:
			return "Unrecognized or unsupported hash algorithm";
		case GT_PKI_BAD_REQUEST:
			return "Bad request";
		case GT_PKI_BAD_DATA_FORMAT:
			 return "Bad data format";
		case GT_PROTOCOL_MISMATCH:
			return "Protocol mismatch, extension(s) found in request";
		case GT_NONSTD_EXTEND_LATER:
			return "Data not yet available - try to extend later";
		case GT_NONSTD_EXTENSION_OVERDUE:
			return "Timestamp is no longer extendable";
		case GT_UNACCEPTED_POLICY:
			return "Unaccepted policy";
		case GT_WRONG_DOCUMENT:
			return "The timestamp is for a different document";
		case GT_WRONG_SIZE_OF_HISTORY:
			return "The number of historic digests does not match "
				"the timestamp identifier";
		case GT_REQUEST_TIME_MISMATCH:
			return "The two aggregation chains in the stamp have "
				"different shapes";
		case GT_INVALID_LENGTH_BYTES:
			return "Level restriction bytes in the location hash chain "
				"steps are not strictly increasing";
		case GT_INVALID_AGGREGATION:
			return "Verification of aggregation data failed";
		case GT_INVALID_SIGNATURE:
			return "Invalid signature";
		case GT_WRONG_SIGNED_DATA:
			return "The value of the MessageDigest signed attribute "
				"is not equal to the digest of the TSTInfo structure";
		case GT_TRUST_POINT_NOT_FOUND:
			return "Trust point not found";
		case GT_INVALID_TRUST_POINT:
			return "Published data has different digests";
		case GT_CANNOT_EXTEND:
			return "Cannot extend timestamp";
		case GT_ALREADY_EXTENDED:
			return "Timestamp is already extended";
		case GT_KEY_NOT_PUBLISHED:
			return "RSA key is not published";
		case GT_CERT_TICKET_TOO_OLD:
			return "RSA key used before it's published";
		case GT_CERT_NOT_TRUSTED:
			return "The publications file signing key could not be "
				"traced to a trusted CA root";
		case GT_OUT_OF_MEMORY:
			return "Out of memory";
		case GT_IO_ERROR:
			return "I/O error";
		case GT_TIME_OVERFLOW:
			return "Time value outside the range of time_t";
		case GT_CRYPTO_FAILURE:
			return "Cryptographic operation failed";
		case GT_PKI_SYSTEM_FAILURE:
			return "Internal error";
		case GT_UNKNOWN_ERROR:
			return "Unknown error";
		default:
			return "<Not a valid GuardTime status code>";
	}
}

/**/

int GT_getVersion(void)
{
	return GT_VERSION;
}
