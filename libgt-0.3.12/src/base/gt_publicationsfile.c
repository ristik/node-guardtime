/*
 * $Id: gt_publicationsfile.c 203 2014-01-28 23:16:24Z risto.laanoja $
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

/* HACK: we need to include Windows headers before any OpenSSL ones
 * so the re-definitions of X509 related symbols happen in an order
 * that leaves intact the ones we will need below; should probably
 * move the Windows-specific things to another file instead. */
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

#include "gt_publicationsfile.h"

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "hashchain.h"
#include "base32.h"

#ifdef _WIN32
#define snprintf _snprintf
#endif

/* Hide the following line to deactivate. */
#define MAGIC_EMAIL "publications@guardtime.com"

/* Shared resourse initialized by #GTTruststore_init(). */
extern X509_STORE *GT_truststore;

/*
 * Internal static function for reading network byte ordered 16-bit unsigned
 * integer value.
 */
static int readUInt16(const unsigned char *addr)
{
	return (addr[0] << 8) | addr[1];
}

/*
 * Internal static function for reading network byte ordered 32-bit integer
 * value.
 */
static int readInt32(const unsigned char *addr)
{
	int i;
	int retval;

	retval = (signed char) *addr;
	for (i = 3; i; --i) {
		retval <<= 8;
		retval |= *++addr;
	}

	return retval;
}

/*
 * Internal static function for reading network byte ordered 64-bit integer
 * value.
 */
static long long readInt64(const unsigned char *addr)
{
	int i;
	long long retval;

	retval = (signed char) *addr;
	for (i = 7; i; --i) {
		retval <<= 8;
		retval |= *++addr;
	}

	return retval;
}

/*
 * Internal static function for decoding of the header fields.
 */
static int decodeHeader(GTPublicationsFile *pubfile)
{
	size_t data_block_size;
	size_t hash_data_block_size;

	assert(sizeof(int) >= 4);
	assert(sizeof(long long) >= 8);

	if (pubfile->data_length < 1) {
		return GT_INVALID_FORMAT;
	}

	pubfile->version = readUInt16(pubfile->data +
			GTPublicationsFile_HeaderOffset_version);

	if (pubfile->version != GTPublicationsFile_CurrentVersion) {
		return GT_UNSUPPORTED_FORMAT;
	}

	if (pubfile->data_length < GTPublicationsFile_HeaderLength) {
		return GT_INVALID_FORMAT;
	}

	pubfile->first_publication_ident = readInt64(pubfile->data +
			GTPublicationsFile_HeaderOffset_firstPublicationIdent);
	pubfile->data_block_begin = readInt32(pubfile->data +
			GTPublicationsFile_HeaderOffset_dataBlockBegin);
	pubfile->publication_cell_size = readUInt16(pubfile->data +
			GTPublicationsFile_HeaderOffset_publicationCellSize);
	pubfile->number_of_publications = readInt32(pubfile->data +
			GTPublicationsFile_HeaderOffset_numberOfPublications);
	pubfile->key_hashes_begin = readInt32(pubfile->data +
			GTPublicationsFile_HeaderOffset_keyHashesBegin);
	pubfile->key_hash_cell_size = readUInt16(pubfile->data +
			GTPublicationsFile_HeaderOffset_keyHashCellSize);
	pubfile->number_of_key_hashes = readUInt16(pubfile->data +
			GTPublicationsFile_HeaderOffset_numberOfKeyHashes);
	pubfile->pub_reference_begin = readInt32(pubfile->data +
			GTPublicationsFile_HeaderOffset_pubReferenceBegin);
	pubfile->signature_block_begin = readInt32(pubfile->data +
			GTPublicationsFile_HeaderOffset_signatureBlockBegin);

	if (pubfile->data_block_begin < GTPublicationsFile_HeaderLength ||
			pubfile->data_block_begin > pubfile->data_length) {
		return GT_INVALID_FORMAT;
	}

	if (pubfile->key_hashes_begin < pubfile->data_block_begin ||
			pubfile->key_hashes_begin > pubfile->data_length) {
		return GT_INVALID_FORMAT;
	}

	if (pubfile->pub_reference_begin < pubfile->key_hashes_begin ||
			pubfile->pub_reference_begin > pubfile->data_length) {
		return GT_INVALID_FORMAT;
	}

	if (pubfile->signature_block_begin < pubfile->pub_reference_begin ||
			pubfile->signature_block_begin > pubfile->data_length) {
		return GT_INVALID_FORMAT;
	}

	data_block_size = pubfile->key_hashes_begin - pubfile->data_block_begin;
	hash_data_block_size =
		pubfile->signature_block_begin - pubfile->key_hashes_begin;

	/* Using integer division instead of multiply ensures that there will
	 * be no overflows and thus no false positives in case of invalid values
	 * of publication_cell_size or number_of_publications. */
	if (data_block_size / pubfile->publication_cell_size <
			pubfile->number_of_publications) {
		return GT_INVALID_FORMAT;
	}

	if (hash_data_block_size / pubfile->key_hash_cell_size <
			pubfile->number_of_key_hashes) {
		return GT_INVALID_FORMAT;
	}

	return GT_OK;
}

/*
 * Internal static function for decoding of the single publication cell.
 */
static int decodePublicationCell(
		const unsigned char *cell_addr, size_t cell_offset, size_t cell_size,
		GTPublicationsFile_Cell *cell)
{
	int hash_alg;

	if (cell_size < GTPublicationsFile_CellOffset_publicationImprint + 1) {
		return GT_INVALID_FORMAT;
	}

	cell->publication_identifier = readInt64(
			cell_addr + GTPublicationsFile_CellOffset_publicationIdentifier);

	hash_alg = cell_addr[GTPublicationsFile_CellOffset_publicationImprint];
	if (!GT_isSupportedHashAlgorithm(hash_alg)) {
		return GT_UNTRUSTED_HASH_ALGORITHM;
	}

	cell->publication_imprint_size = GT_getHashSize(hash_alg) + 1;
	if (cell->publication_imprint_size <= 1) {
		return GT_CRYPTO_FAILURE;
	}
	if (cell_size < (cell->publication_imprint_size +
			GTPublicationsFile_CellOffset_publicationImprint)) {
		return GT_INVALID_FORMAT;
	}

	cell->publication_imprint_offset =
		cell_offset + GTPublicationsFile_CellOffset_publicationImprint;

	return GT_OK;
}

/*
 * Internal static function for decoding of the publication cells.
 */
static int decodePublicationCells(GTPublicationsFile *pubfile)
{
	unsigned int i;
	int rc;
	size_t cell_offset;
	const unsigned char *cell_addr;
	GTPublicationsFile_Cell *cell;

	assert(pubfile->publication_cells == NULL);

	pubfile->publication_cells = GT_malloc(
			sizeof(GTPublicationsFile_Cell) * pubfile->number_of_publications);
	if (pubfile->publication_cells == NULL) {
		return GT_OUT_OF_MEMORY;
	}

	for (i = 0; i < pubfile->number_of_publications; ++i) {
		cell_offset = pubfile->data_block_begin +
			i * pubfile->publication_cell_size;
		cell_addr = pubfile->data + cell_offset;
		cell = pubfile->publication_cells + i;

		rc = decodePublicationCell(
				cell_addr, cell_offset, pubfile->publication_cell_size, cell);
		if (rc != GT_OK) {
			return rc;
		}
	}

	return GT_OK;
}

/*
 * Internal static function for decoding of the single key hash cell.
 */
static int decodeKeyHashCell(
		const unsigned char *cell_addr, size_t cell_offset, size_t cell_size,
		GTPublicationsFile_KeyHashCell *cell)
{
	int hash_alg;
	long long key_publication_time;

	if (cell_size < GTPublicationsFile_KeyHashCellOffset_keyHashImprint + 1) {
		return GT_INVALID_FORMAT;
	}

	key_publication_time = readInt64(cell_addr +
			GTPublicationsFile_KeyHashCellOffset_keyPublicationTime);
	cell->key_publication_time = key_publication_time;
	/* The following condition checks for time_t overflows on 32-bit platforms
	 * and should be optimized away if time_t is at least 64 bits long. */
	if (sizeof(time_t) < 8 &&
			cell->key_publication_time != key_publication_time) {
		/* This error code assumes that no-one uses 32-bit time_t after the
		 * year of 2038, so it is safe to say that file format is invalid
		 * before that. */
		return GT_INVALID_FORMAT;
	}

	hash_alg = cell_addr[GTPublicationsFile_KeyHashCellOffset_keyHashImprint];
	if (!GT_isSupportedHashAlgorithm(hash_alg)) {
		return GT_UNTRUSTED_HASH_ALGORITHM;
	}

	cell->key_hash_imprint_size = GT_getHashSize(hash_alg) + 1;
	if (cell->key_hash_imprint_size <= 1) {
		return GT_CRYPTO_FAILURE;
	}
	if (cell_size < (cell->key_hash_imprint_size +
				GTPublicationsFile_KeyHashCellOffset_keyHashImprint)) {
		return GT_INVALID_FORMAT;
	}

	cell->key_hash_imprint_offset =
		cell_offset + GTPublicationsFile_KeyHashCellOffset_keyHashImprint;

	return GT_OK;
}

/*
 * Internal static function for decoding of the key hash cells.
 */
static int decodeKeyHashCells(GTPublicationsFile *pubfile)
{
	unsigned int i;
	int rc;
	size_t cell_offset;
	const unsigned char *cell_addr;
	GTPublicationsFile_KeyHashCell *cell;

	assert(pubfile->key_hash_cells == NULL);

	pubfile->key_hash_cells = GT_malloc(
			sizeof(GTPublicationsFile_KeyHashCell) *
			pubfile->number_of_key_hashes);
	if (pubfile->key_hash_cells == NULL) {
		return GT_OUT_OF_MEMORY;
	}

	for (i = 0; i < pubfile->number_of_key_hashes; ++i) {
		cell_offset = pubfile->key_hashes_begin +
			i * pubfile->key_hash_cell_size;
		cell_addr = pubfile->data + cell_offset;
		cell = pubfile->key_hash_cells + i;

		rc = decodeKeyHashCell(
				cell_addr, cell_offset, pubfile->key_hash_cell_size, cell);
		if (rc != GT_OK) {
			return rc;
		}
	}

	return GT_OK;
}

/*
 * Internal static function for decoding of the publication reference.
 */
static int decodePubReference(GTPublicationsFile *pubfile)
{
	const unsigned char *p;

	assert(pubfile->pub_reference == NULL);

	p = pubfile->data + pubfile->pub_reference_begin;
	ERR_clear_error();
	pubfile->pub_reference = (GTReferences*) ASN1_item_d2i(NULL, &p,
			pubfile->signature_block_begin - pubfile->pub_reference_begin,
			ASN1_ITEM_rptr(GTReferences));
	if (pubfile->pub_reference == NULL) {
		return GT_isMallocFailure() ? GT_OUT_OF_MEMORY : GT_INVALID_FORMAT;
	}

	return GT_OK;
}

/*
 * Internal static function for decoding of the signature of the published
 * file.
 */
static int decodeSignature(GTPublicationsFile *pubfile)
{
	const unsigned char *p;

	assert(pubfile->signature == NULL);

	p = pubfile->data + pubfile->signature_block_begin;
	ERR_clear_error();
	pubfile->signature = d2i_PKCS7(
			NULL, &p, pubfile->data_length - pubfile->signature_block_begin);
	if (pubfile->signature == NULL) {
		return GT_isMallocFailure() ? GT_OUT_OF_MEMORY : GT_INVALID_FORMAT;
	}

	return GT_OK;
}

/**/

int GTPublicationsFile_DERDecode(const void *data, size_t data_length,
		GTPublicationsFile **publications_file)
{
	int retval = GT_UNKNOWN_ERROR;
	GTPublicationsFile *tmp_publications_file = NULL;

	if ((data == NULL && data_length != 0) || publications_file == NULL) {
		retval = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_publications_file = GT_malloc(sizeof(GTPublicationsFile));
	if (tmp_publications_file == NULL) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Do not waste time with copying of data until we are sure that input data
	 * is correct. */
	tmp_publications_file->data = data;
	tmp_publications_file->data_length = data_length;
	tmp_publications_file->data_owner = 0;
	tmp_publications_file->publication_cells = NULL;
	tmp_publications_file->key_hash_cells = NULL;
	tmp_publications_file->pub_reference = NULL;
	tmp_publications_file->signature = NULL;

	retval = decodeHeader(tmp_publications_file);
	if (retval != GT_OK) {
		goto cleanup;
	}

	retval = decodePublicationCells(tmp_publications_file);
	if (retval != GT_OK) {
		goto cleanup;
	}

	retval = decodeKeyHashCells(tmp_publications_file);
	if (retval != GT_OK) {
		goto cleanup;
	}

	retval = decodePubReference(tmp_publications_file);
	if (retval != GT_OK) {
		goto cleanup;
	}

	retval = decodeSignature(tmp_publications_file);
	if (retval != GT_OK) {
		goto cleanup;
	}

	retval = GT_UNKNOWN_ERROR;

	tmp_publications_file->data = GT_malloc(data_length);
	if (tmp_publications_file->data == NULL) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy((void*) tmp_publications_file->data, data, data_length);
	tmp_publications_file->data_owner = 1;

	*publications_file = tmp_publications_file;
	tmp_publications_file = NULL;

	retval = GT_OK;

cleanup:

	GTPublicationsFile_free(tmp_publications_file);

	return retval;
}

/**/

int GTPublicationsFile_getSigningCert(
		const GTPublicationsFile *publications_file,
		unsigned char **cert_der, size_t *cert_der_length)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *i2dp;
	unsigned char *tmp_der = NULL;
	int tmp_der_len;
	X509 *signing_cert = NULL;
	STACK_OF(X509) *certs = NULL;

	if (publications_file == NULL || publications_file->signature == NULL ||
			cert_der == NULL || cert_der_length == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	certs = PKCS7_get0_signers(publications_file->signature, NULL, 0);
	if (certs == NULL) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (sk_X509_num(certs) != 1) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	signing_cert = sk_X509_value(certs, 0);

	tmp_der_len = i2d_X509(signing_cert, NULL);
	if (tmp_der_len < 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	tmp_der = GT_malloc(tmp_der_len);
	if (tmp_der == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	i2dp = tmp_der;
	i2d_X509(signing_cert, &i2dp);

	*cert_der = tmp_der;
	tmp_der = NULL;
	*cert_der_length = tmp_der_len;

	res = GT_OK;

cleanup:
	GT_free(tmp_der);
	sk_X509_free(certs);

	return res;
}

/**/

int GTPublicationsFile_getKeyHash(const GTPublicationsFile* publications_file,
		unsigned int keyhash_index,
		const unsigned char** imprint, size_t* imprint_length)
{
	GTPublicationsFile_KeyHashCell *cell = NULL;

	if (publications_file == NULL ||
			keyhash_index >= publications_file->number_of_key_hashes) {
		return GT_INVALID_ARGUMENT;
	}

	cell = publications_file->key_hash_cells + keyhash_index;

	if (imprint != NULL) {
		*imprint = publications_file->data + cell->key_hash_imprint_offset;
	}

	if (imprint_length != NULL) {
		*imprint_length = cell->key_hash_imprint_size;
	}

	return GT_OK;
}

/**/

int GTPublicationsFile_getKeyHashByIndex(
		const GTPublicationsFile *publications_file,
		unsigned int key_hash_index, char **key_hash)
{
	int res = GT_UNKNOWN_ERROR;
	GTPublicationsFile_KeyHashCell *cell;
	GTPublishedData *published_data = NULL;

	if (publications_file == NULL ||
			key_hash_index >= publications_file->number_of_key_hashes ||
			key_hash == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	cell = publications_file->key_hash_cells + key_hash_index;

	published_data = GTPublishedData_new();
	if (published_data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!GT_uint64ToASN1Integer(
				published_data->publicationIdentifier,
				cell->key_publication_time)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!ASN1_STRING_set(
				published_data->publicationImprint,
				publications_file->data + cell->key_hash_imprint_offset,
				cell->key_hash_imprint_size)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = GT_publishedDataToBase32(published_data, key_hash);

cleanup:
	GTPublishedData_free(published_data);

	return res;
}

/* Helper function to get publication cell by index. */
static int getPublicationCell(
		const GTPublicationsFile *publications_file,
		unsigned int cell_index,
		const GTPublicationsFile_Cell **cell,
		GTPublicationsFile_Cell *decode_buffer)
{
	assert(cell_index < publications_file->number_of_publications);

	if (publications_file->publication_cells == NULL) {
		size_t cell_offset;
		const unsigned char *cell_addr;
		int retval;

		cell_offset = publications_file->data_block_begin +
			cell_index * publications_file->publication_cell_size;
		cell_addr = publications_file->data + cell_offset;

		retval = decodePublicationCell(cell_addr, cell_offset,
				publications_file->publication_cell_size, decode_buffer);
		if (retval == GT_OK) {
			*cell = decode_buffer;
		}

		return retval;
	}

	*cell = publications_file->publication_cells + cell_index;

	return GT_OK;
}

/* Helper function to create \p GTPubFileVerificationInfo. */
static int createPubFileVerificationInfo(
		const GTPublicationsFile *publications_file,
		GTPubFileVerificationInfo **verification_info)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res = GT_UNKNOWN_ERROR;
	GTPubFileVerificationInfo *tmp_info = NULL;
	const GTPublicationsFile_Cell *cell = NULL;
	GTPublicationsFile_Cell cell_buf;
	unsigned char *cert_der = NULL;
	size_t cert_der_len;
	char *tmp_cert = NULL;

	assert(publications_file != NULL);
	assert(verification_info != NULL);

	tmp_info = GT_malloc(sizeof(GTPubFileVerificationInfo));
	if (tmp_info == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_info->publications_count = publications_file->number_of_publications;
	tmp_info->key_hash_count = publications_file->number_of_key_hashes;
	tmp_info->certificate = NULL;

	if (tmp_info->publications_count < 1) {
		tmp_info->first_publication_time = -1;
		tmp_info->last_publication_time = -1;
	} else {
		tmp_res = getPublicationCell(publications_file, 0, &cell, &cell_buf);
		if (tmp_res != GT_OK) {
			res = tmp_res;
			goto cleanup;
		}
		tmp_info->first_publication_time = cell->publication_identifier;

		if (tmp_info->publications_count > 1) {
			tmp_res = getPublicationCell(publications_file,
					tmp_info->publications_count - 1, &cell, &cell_buf);
			if (tmp_res != GT_OK) {
				res = tmp_res;
				goto cleanup;
			}
			tmp_info->last_publication_time = cell->publication_identifier;
		} else {
			tmp_info->last_publication_time = tmp_info->first_publication_time;
		}
	}

	tmp_res = GTPublicationsFile_getSigningCert(publications_file,
			&cert_der, &cert_der_len);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_cert = GT_base32Encode(cert_der, cert_der_len, 8);
	if (tmp_cert == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	/* This string duplication is necessary because we dont want to return
	 * OPENSSL_malloc()-ed data in public API. */
	tmp_info->certificate = GT_malloc(strlen(tmp_cert) + 1);
	if (tmp_info->certificate == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	strcpy(tmp_info->certificate, tmp_cert);

	*verification_info = tmp_info;
	tmp_info = NULL;
	res = GT_OK;

cleanup:
	GTPubFileVerificationInfo_free(tmp_info);
	GT_free(cert_der);
	OPENSSL_free(tmp_cert);

	return res;
}

#ifdef _WIN32

/* Helper function to trace the signing cert to a trusted CA root
 * in the Windows Certificate Store. */
static int checkCertCryptoAPI(const GTPublicationsFile *publications_file)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *cert_der = NULL;
	size_t cert_der_len;
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	CERT_ENHKEY_USAGE enhkeyUsage;
	CERT_USAGE_MATCH certUsage;
	CERT_CHAIN_PARA chainPara;
	CERT_CHAIN_POLICY_PARA policyPara;
	CERT_CHAIN_POLICY_STATUS policyStatus;
	char tmp_name[256];

	res = GTPublicationsFile_getSigningCert(publications_file, &cert_der, &cert_der_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Create a certificate context based on the above certificate. */
	pCertContext = CertCreateCertificateContext(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_der, cert_der_len);
	if (pCertContext == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

#ifdef MAGIC_EMAIL
	CertGetNameStringA(pCertContext, CERT_NAME_EMAIL_TYPE, 0, NULL,
			tmp_name, sizeof(tmp_name));
	if (strcmp(tmp_name, MAGIC_EMAIL) != 0) {
		return GT_INVALID_SIGNATURE;
	}
#endif

	/* Get the certificate chain of our certificate. */
	enhkeyUsage.cUsageIdentifier = 0;
	enhkeyUsage.rgpszUsageIdentifier = NULL;
	certUsage.dwType = USAGE_MATCH_TYPE_AND;
	certUsage.Usage = enhkeyUsage;
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage = certUsage;

	if (!CertGetCertificateChain(NULL, pCertContext, NULL, NULL,
			&chainPara, 0, NULL, &pChainContext)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
		res = GT_CERT_NOT_TRUSTED;
		goto cleanup;
	}

	/* Verify certificate chain. */
	policyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
	policyPara.dwFlags = 0;
	policyPara.pvExtraPolicyPara = NULL;

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE,
			pChainContext, &policyPara, &policyStatus)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (policyStatus.dwError) {
		res = GT_CERT_NOT_TRUSTED;
		goto cleanup;
	}

	res = GT_OK;

cleanup:
	GT_free(cert_der);
	if (pChainContext != NULL) {
		CertFreeCertificateChain(pChainContext);
	}
	if (pCertContext != NULL) {
		CertFreeCertificateContext(pCertContext);
	}

	return res;
}

#endif /* _WIN32 */

/**/

/* Helper function to trace the signing cert to a trusted CA root
 * in the OpenSSL Trust Store. */
static int checkCertOpenSSL(const GTPublicationsFile *publications_file)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *cert_der = NULL;
	size_t cert_der_len;
	unsigned char *cert_tmp;
	X509 *cert = NULL;
	X509_STORE_CTX *store_ctx = NULL;
	X509_NAME *subj = NULL;
	ASN1_OBJECT *oid = NULL;
	char tmp_name[256];
	int rc;

	res = GTPublicationsFile_getSigningCert(publications_file, &cert_der, &cert_der_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	/* Note that d2i_X509() spoils the pointer to the buffer, use a temporary copy. */
	cert_tmp = cert_der;
	cert = d2i_X509(NULL, (const unsigned char **) &cert_tmp, cert_der_len);
	if (cert == NULL) {
		res = GT_NOT_VALID_PUBLICATION;
		goto cleanup;
	}

#ifdef MAGIC_EMAIL
	subj = X509_get_subject_name(cert);
	if (subj == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	oid = OBJ_txt2obj("1.2.840.113549.1.9.1", 1);
	if (oid == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	rc = X509_NAME_get_text_by_OBJ(subj, oid, tmp_name, sizeof(tmp_name));
	if (rc < 0) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}
	if (strcmp(tmp_name, MAGIC_EMAIL) != 0) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}
#endif

	store_ctx = X509_STORE_CTX_new();
	if (store_ctx == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* The truststore is not initialized by default. */
	if (GT_truststore == NULL) {
		res = GTTruststore_init(1);
		if (res != GT_OK) goto cleanup;
	}

	if (!X509_STORE_CTX_init(store_ctx, GT_truststore, cert,
			publications_file->signature->d.sign->cert)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	rc = X509_verify_cert(store_ctx);
	if (rc < 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (rc != 1) {
		res = GT_CERT_NOT_TRUSTED;
		goto cleanup;
	}

	res = GT_OK;

cleanup:
	GT_free(cert_der);
	/* Do not free subj, it points into cert. */
	ASN1_OBJECT_free(oid);
	if (cert != NULL) {
		X509_free(cert);
	}
	if (store_ctx != NULL) {
		X509_STORE_CTX_free(store_ctx);
	}

	return res;
}

/**/

int GTPublicationsFile_verify(const GTPublicationsFile *publications_file,
		GTPubFileVerificationInfo **verification_info)
{
	int res = GT_UNKNOWN_ERROR;
	BIO *bio_in = NULL;
	int rc;

	if (publications_file == NULL || publications_file->signature == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Note that the cast to void * is needed in order to work around
	 * const-noncorrectness in the OpenSSL API --- this pointer is used
	 * only for reading. */
	bio_in = BIO_new_mem_buf((void *) publications_file->data,
			publications_file->signature_block_begin);
	if (bio_in == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	rc = PKCS7_verify(publications_file->signature, NULL, NULL, bio_in, NULL, PKCS7_NOVERIFY);
	if (rc < 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (rc != 1) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}

#ifdef _WIN32
	if (GT_truststore == NULL) {
		res = checkCertCryptoAPI(publications_file);
	} else {
		res = checkCertOpenSSL(publications_file);
	}
#else
	res = checkCertOpenSSL(publications_file);
#endif
	if (res != GT_OK) {
		goto cleanup;
	}

	res = createPubFileVerificationInfo(publications_file, verification_info);

cleanup:
	BIO_free(bio_in);

	return res;
}

/**/

void GTPublicationsFile_free(GTPublicationsFile *publications_file)
{
	if (publications_file != NULL) {
		if (publications_file->data_owner) {
			GT_free((void*) publications_file->data);
		}
		GT_free(publications_file->publication_cells);
		GT_free(publications_file->key_hash_cells);
		GTReferences_free(publications_file->pub_reference);
		PKCS7_free(publications_file->signature);
		GT_free(publications_file);
	}
}

/**/

static int cellToPublishedData(
		const GTPublicationsFile *publications_file,
		const GTPublicationsFile_Cell *cell,
		GTPublishedData **published_data)
{
	int retval = GT_UNKNOWN_ERROR;
	GTPublishedData *tmp_published_data = NULL;

	assert(publications_file != NULL);
	assert(cell != NULL);
	assert(published_data != NULL);

	tmp_published_data = GTPublishedData_new();
	if (tmp_published_data == NULL) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!GT_uint64ToASN1Integer(
				tmp_published_data->publicationIdentifier,
				cell->publication_identifier)) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!ASN1_STRING_set(
				tmp_published_data->publicationImprint,
				publications_file->data + cell->publication_imprint_offset,
				cell->publication_imprint_size)) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*published_data = tmp_published_data;
	tmp_published_data = NULL;

	retval = GT_OK;

cleanup:
	GTPublishedData_free(tmp_published_data);

	return retval;
}

/**/

int GTPublicationsFile_getPublishedData(
		const GTPublicationsFile *publications_file,
		GT_HashDBIndex publication_identifier,
		GTPublishedData **published_data)
{
	unsigned int i;
	int d;
	int rc;
	const GTPublicationsFile_Cell *cell;
	GTPublicationsFile_Cell cell_buf;

	if (publications_file == NULL || published_data == NULL) {
		return GT_INVALID_ARGUMENT;
	}

	cell = NULL;

	if (publications_file->number_of_publications > 0 &&
			publication_identifier >=
			publications_file->first_publication_ident) {

		i = (unsigned int)(publication_identifier -
				publications_file->first_publication_ident) / 86400;

		if (i >= publications_file->number_of_publications) {
			i = publications_file->number_of_publications - 1;
		}

		rc = getPublicationCell(publications_file, i, &cell, &cell_buf);
		if (rc != GT_OK) {
			return rc;
		}

		if (cell->publication_identifier != publication_identifier) {
			/* It is assumed that publications are sorted by their identifiers
			 * in ascending order to speed things up a little bit. */
			d = cell->publication_identifier < publication_identifier ? 1 : -1;
			cell = NULL;

			for (i = i + d;
					(int) i >= 0 &&
					i < publications_file->number_of_publications;
					i += d) {
				rc = getPublicationCell(publications_file, i, &cell, &cell_buf);
				if (rc != GT_OK) {
					return rc;
				}

				if (cell->publication_identifier == publication_identifier) {
					break;
				}

				cell = NULL;
			}
		}
	}

	if (cell == NULL) {
		/* TODO: Should we add new error code for this???
		 * WARNING: Timestamp verification code relies on this error code! */
		return GT_TRUST_POINT_NOT_FOUND;
	}

	assert(cell->publication_identifier == publication_identifier);

	return cellToPublishedData(publications_file, cell, published_data);
}

/**/

int GTPublicationsFile_getBase32PublishedData(
		const GTPublicationsFile *publications_file,
		GT_HashDBIndex publication_identifier, char **publication)
{
	int res = GT_UNKNOWN_ERROR;
	GTPublishedData *raw_published_data = NULL;

	if (publications_file == NULL || publication == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTPublicationsFile_getPublishedData(
			publications_file, publication_identifier, &raw_published_data);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GT_publishedDataToBase32(raw_published_data, publication);

cleanup:

	GTPublishedData_free(raw_published_data);

	return res;
}

/**/

int GTPublicationsFile_getByIndex(const GTPublicationsFile *publications_file,
		unsigned int publication_index, char **publication)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res = GT_UNKNOWN_ERROR;
	const GTPublicationsFile_Cell *cell = NULL;
	GTPublicationsFile_Cell cell_buf;
	GTPublishedData *published_data = NULL;
	char *tmp_pub_str = NULL;

	if (publications_file == NULL ||
			publication_index >= publications_file->number_of_publications ||
			publication == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_res = getPublicationCell(publications_file,
			publication_index, &cell, &cell_buf);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_res = cellToPublishedData(publications_file, cell, &published_data);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	tmp_res = GT_publishedDataToBase32(published_data, &tmp_pub_str);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	*publication = tmp_pub_str;
	tmp_pub_str = NULL;
	res = GT_OK;

cleanup:
	GTPublishedData_free(published_data);
	GT_free(tmp_pub_str);

	return res;
}

/**/

int GTPublicationsFile_extractTimeFromRawPublication(
		const char *publication, GT_Time_t64 *publication_time)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	GTPublishedData *published_data = NULL;
	GT_UInt64 publication_identifier;

	if (publication == NULL || publication_time == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp_res = GT_base32ToPublishedData(publication, -1, &published_data);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	if (!GT_asn1IntegerToUint64(&publication_identifier,
				published_data->publicationIdentifier)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	*publication_time = (GT_Time_t64) publication_identifier;

	res = GT_OK;

cleanup:
	GTPublishedData_free(published_data);

	return res;
}

/**/

void GTPubFileVerificationInfo_free(
		GTPubFileVerificationInfo *verification_info)
{
	if (verification_info != NULL) {
		if (verification_info->certificate != NULL) {
			GT_free(verification_info->certificate);
		}

		GT_free(verification_info);
	}
}
