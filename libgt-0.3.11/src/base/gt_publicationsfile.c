/*
 * $Id: gt_publicationsfile.c 106 2011-04-05 09:00:01Z ahto.truu $
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

#include "gt_publicationsfile.h"

#include <assert.h>
#include <string.h>

#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "hashchain.h"
#include "base32.h"

#ifdef _WIN32
#define snprintf _snprintf
#endif

/*
 * This is the trusted root certificate against which the signature
 * in the publications file is checked.
 */
static const unsigned char root_cert_der[] =
	"\x30\x82\x04\x1a\x30\x82\x03\x02\x02\x11\x00\x8b\x5b\x75\x56\x84"
	"\x54\x85\x0b\x00\xcf\xaf\x38\x48\xce\xb1\xa4\x30\x0d\x06\x09\x2a"
	"\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x30\x81\xca\x31\x0b\x30"
	"\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03"
	"\x55\x04\x0a\x13\x0e\x56\x65\x72\x69\x53\x69\x67\x6e\x2c\x20\x49"
	"\x6e\x63\x2e\x31\x1f\x30\x1d\x06\x03\x55\x04\x0b\x13\x16\x56\x65"
	"\x72\x69\x53\x69\x67\x6e\x20\x54\x72\x75\x73\x74\x20\x4e\x65\x74"
	"\x77\x6f\x72\x6b\x31\x3a\x30\x38\x06\x03\x55\x04\x0b\x13\x31\x28"
	"\x63\x29\x20\x31\x39\x39\x39\x20\x56\x65\x72\x69\x53\x69\x67\x6e"
	"\x2c\x20\x49\x6e\x63\x2e\x20\x2d\x20\x46\x6f\x72\x20\x61\x75\x74"
	"\x68\x6f\x72\x69\x7a\x65\x64\x20\x75\x73\x65\x20\x6f\x6e\x6c\x79"
	"\x31\x45\x30\x43\x06\x03\x55\x04\x03\x13\x3c\x56\x65\x72\x69\x53"
	"\x69\x67\x6e\x20\x43\x6c\x61\x73\x73\x20\x31\x20\x50\x75\x62\x6c"
	"\x69\x63\x20\x50\x72\x69\x6d\x61\x72\x79\x20\x43\x65\x72\x74\x69"
	"\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x41\x75\x74\x68\x6f\x72\x69"
	"\x74\x79\x20\x2d\x20\x47\x33\x30\x1e\x17\x0d\x39\x39\x31\x30\x30"
	"\x31\x30\x30\x30\x30\x30\x30\x5a\x17\x0d\x33\x36\x30\x37\x31\x36"
	"\x32\x33\x35\x39\x35\x39\x5a\x30\x81\xca\x31\x0b\x30\x09\x06\x03"
	"\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x0a"
	"\x13\x0e\x56\x65\x72\x69\x53\x69\x67\x6e\x2c\x20\x49\x6e\x63\x2e"
	"\x31\x1f\x30\x1d\x06\x03\x55\x04\x0b\x13\x16\x56\x65\x72\x69\x53"
	"\x69\x67\x6e\x20\x54\x72\x75\x73\x74\x20\x4e\x65\x74\x77\x6f\x72"
	"\x6b\x31\x3a\x30\x38\x06\x03\x55\x04\x0b\x13\x31\x28\x63\x29\x20"
	"\x31\x39\x39\x39\x20\x56\x65\x72\x69\x53\x69\x67\x6e\x2c\x20\x49"
	"\x6e\x63\x2e\x20\x2d\x20\x46\x6f\x72\x20\x61\x75\x74\x68\x6f\x72"
	"\x69\x7a\x65\x64\x20\x75\x73\x65\x20\x6f\x6e\x6c\x79\x31\x45\x30"
	"\x43\x06\x03\x55\x04\x03\x13\x3c\x56\x65\x72\x69\x53\x69\x67\x6e"
	"\x20\x43\x6c\x61\x73\x73\x20\x31\x20\x50\x75\x62\x6c\x69\x63\x20"
	"\x50\x72\x69\x6d\x61\x72\x79\x20\x43\x65\x72\x74\x69\x66\x69\x63"
	"\x61\x74\x69\x6f\x6e\x20\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20"
	"\x2d\x20\x47\x33\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86"
	"\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a"
	"\x02\x82\x01\x01\x00\xdd\x84\xd4\xb9\xb4\xf9\xa7\xd8\xf3\x04\x78"
	"\x9c\xde\x3d\xdc\x6c\x13\x16\xd9\x7a\xdd\x24\x51\x66\xc0\xc7\x26"
	"\x59\x0d\xac\x06\x08\xc2\x94\xd1\x33\x1f\xf0\x83\x35\x1f\x6e\x1b"
	"\xc8\xde\xaa\x6e\x15\x4e\x54\x27\xef\xc4\x6d\x1a\xec\x0b\xe3\x0e"
	"\xf0\x44\xa5\x57\xc7\x40\x58\x1e\xa3\x47\x1f\x71\xec\x60\xf6\x6d"
	"\x94\xc8\x18\x39\xed\xfe\x42\x18\x56\xdf\xe4\x4c\x49\x10\x78\x4e"
	"\x01\x76\x35\x63\x12\x36\xdd\x66\xbc\x01\x04\x36\xa3\x55\x68\xd5"
	"\xa2\x36\x09\xac\xab\x21\x26\x54\x06\xad\x3f\xca\x14\xe0\xac\xca"
	"\xad\x06\x1d\x95\xe2\xf8\x9d\xf1\xe0\x60\xff\xc2\x7f\x75\x2b\x4c"
	"\xcc\xda\xfe\x87\x99\x21\xea\xba\xfe\x3e\x54\xd7\xd2\x59\x78\xdb"
	"\x3c\x6e\xcf\xa0\x13\x00\x1a\xb8\x27\xa1\xe4\xbe\x67\x96\xca\xa0"
	"\xc5\xb3\x9c\xdd\xc9\x75\x9e\xeb\x30\x9a\x5f\xa3\xcd\xd9\xae\x78"
	"\x19\x3f\x23\xe9\x5c\xdb\x29\xbd\xad\x55\xc8\x1b\x54\x8c\x63\xf6"
	"\xe8\xa6\xea\xc7\x37\x12\x5c\xa3\x29\x1e\x02\xd9\xdb\x1f\x3b\xb4"
	"\xd7\x0f\x56\x47\x81\x15\x04\x4a\xaf\x83\x27\xd1\xc5\x58\x88\xc1"
	"\xdd\xf6\xaa\xa7\xa3\x18\xda\x68\xaa\x6d\x11\x51\xe1\xbf\x65\x6b"
	"\x9f\x96\x76\xd1\x3d\x02\x03\x01\x00\x01\x30\x0d\x06\x09\x2a\x86"
	"\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\xab\x66"
	"\x8d\xd7\xb3\xba\xc7\x9a\xb6\xe6\x55\xd0\x05\xf1\x9f\x31\x8d\x5a"
	"\xaa\xd9\xaa\x46\x26\x0f\x71\xed\xa5\xad\x53\x56\x62\x01\x47\x2a"
	"\x44\xe9\xfe\x3f\x74\x0b\x13\x9b\xb9\xf4\x4d\x1b\xb2\xd1\x5f\xb2"
	"\xb6\xd2\x88\x5c\xb3\x9f\xcd\xcb\xd4\xa7\xd9\x60\x95\x84\x3a\xf8"
	"\xc1\x37\x1d\x61\xca\xe7\xb0\xc5\xe5\x91\xda\x54\xa6\xac\x31\x81"
	"\xae\x97\xde\xcd\x08\xac\xb8\xc0\x97\x80\x7f\x6e\x72\xa4\xe7\x69"
	"\x13\x95\x65\x1f\xc4\x93\x3c\xfd\x79\x8f\x04\xd4\x3e\x4f\xea\xf7"
	"\x9e\xce\xcd\x67\x7c\x4f\x65\x02\xff\x91\x85\x54\x73\xc7\xff\x36"
	"\xf7\x86\x2d\xec\xd0\x5e\x4f\xff\x11\x9f\x72\x06\xd6\xb8\x1a\xf1"
	"\x4c\x0d\x26\x65\xe2\x44\x80\x1e\xc7\x9f\xe3\xdd\xe8\x0a\xda\xec"
	"\xa5\x20\x80\x69\x68\xa1\x4f\x7e\xe1\x6b\xcf\x07\x41\xfa\x83\x8e"
	"\xbc\x38\xdd\xb0\x2e\x11\xb1\x6b\xb2\x42\xcc\x9a\xbc\xf9\x48\x22"
	"\x79\x4a\x19\x0f\xb2\x1c\x3e\x20\x74\xd9\x6a\xc3\xbe\xf2\x28\x78"
	"\x13\x56\x79\x4f\x6d\x50\xea\x1b\xb0\xb5\x57\xb1\x37\x66\x58\x23"
	"\xf3\xdc\x0f\xdf\x0a\x87\xc4\xef\x86\x05\xd5\x38\x14\x60\x99\xa3"
	"\x4b\xde\x06\x96\x71\x2c\xf2\xdb\xb6\x1f\xa4\xef\x3f\xee";

/*
 * This is the mail address to which the signing certificate belonging
 * to the publications file signature must be issued.
 */
static const unsigned char cert_mail[] =
	"publications@guardtime.com";

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

/**/

int GTPublicationsFile_verify(const GTPublicationsFile *publications_file,
		GTPubFileVerificationInfo **verification_info)
{
	int res = GT_UNKNOWN_ERROR;
	BIO *bio_in = NULL;
	const unsigned char *root_cert_ptr = root_cert_der;
	X509 *root_cert = NULL;
	X509_STORE *root_store = NULL;
	STACK_OF(X509) *sig_certs = NULL;
	X509 *sig_cert = NULL;
	X509_NAME *sig_subj = NULL;
	ASN1_OBJECT *oid_mail = NULL;
	char sig_mail[sizeof(cert_mail) + 5];
	int rc;
	GTPubFileVerificationInfo *tmp_info = NULL;

	if (publications_file == NULL || publications_file->signature == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Note that cast to void * is needed in order to work around
	 * const-noncorrectness in the OpenSSL API --- this pointer is used
	 * only for reading. */
	bio_in = BIO_new_mem_buf((void *) publications_file->data,
			publications_file->signature_block_begin);
	if (bio_in == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	root_cert = d2i_X509(NULL, &root_cert_ptr, sizeof(root_cert_der));
	if (root_cert == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	root_store = X509_STORE_new();
	if (root_store == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	rc = X509_STORE_add_cert(root_store, root_cert);
	if (!rc) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	rc = PKCS7_verify(publications_file->signature, NULL, root_store, bio_in, NULL, 0);
	if (rc < 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (rc != 1) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}

	sig_certs = PKCS7_get0_signers(publications_file->signature, NULL, 0);
	if (sig_certs == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	if (sk_X509_num(sig_certs) != 1) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}
	sig_cert = sk_X509_value(sig_certs, 0);
	if (sig_cert == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	sig_subj = X509_get_subject_name(sig_cert);
	if (sig_subj == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	oid_mail = OBJ_txt2obj("1.2.840.113549.1.9.1", 1);
	if (oid_mail == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	rc = X509_NAME_get_text_by_OBJ(sig_subj, oid_mail, sig_mail, sizeof(sig_mail));
	if (rc < 0) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}
	if (strcmp(sig_mail, cert_mail) != 0) {
		res = GT_INVALID_SIGNATURE;
		goto cleanup;
	}

	res = createPubFileVerificationInfo(publications_file, &tmp_info);
	if (res == GT_OK) {
		*verification_info = tmp_info;
		tmp_info = NULL;
	}

cleanup:
	ASN1_OBJECT_free(oid_mail);
	// sig_subj points into sig_cert
	// sig_cert points into sig_certs
	sk_X509_free(sig_certs);
	X509_STORE_free(root_store);
	X509_free(root_cert);
	BIO_free(bio_in);
	GTPubFileVerificationInfo_free(tmp_info);

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
