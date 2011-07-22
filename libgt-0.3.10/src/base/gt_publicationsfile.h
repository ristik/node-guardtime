/*
 * $Id: gt_publicationsfile.h 74 2010-02-22 11:42:26Z ahto.truu $
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

#ifndef GT_PUBLICATIONSFILE_H_INCLUDED
#define GT_PUBLICATIONSFILE_H_INCLUDED

#include <stddef.h>
#include <time.h>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "gt_base.h"
#include "gt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This internal structure holds contents of the single publication cell.
 */
typedef struct GTPublicationsFile_Cell_st {
	/**
	 * Publication identifier.
	 */
	GT_HashDBIndex publication_identifier;
	/**
	 * Size of the publication imprint.
	 */
	size_t publication_imprint_size;
	/**
	 * Offset of the publication imprint in the published file.
	 */
	size_t publication_imprint_offset;
} GTPublicationsFile_Cell;

/**
 * This internal structure holds contents of the single key hash cell.
 */
typedef struct GTPublicationsFile_KeyHashCell_st {
	/**
	 * Time of publication of the key.
	 */
	time_t key_publication_time;
	/**
	 * Size of the key hash imprint.
	 */
	size_t key_hash_imprint_size;
	/**
	 * Offset of the key hash imprint in the published file.
	 */
	size_t key_hash_imprint_offset;
} GTPublicationsFile_KeyHashCell;

/**
 * This internal structure holds contents of the published file.
 */
struct GTPublicationsFile_st {
	/**
	 * Pointer to the beginning of the raw file contents. It is preserved after
	 * decoding for two things: it is needed for signature verification and
	 * hash values are still taken directly from this buffer.
	 */
	const unsigned char *data;
	/**
	 * Size of the file in bytes.
	 */
	size_t data_length;
	/**
	 * Non-zero, if file_data belongs to this structure and must be freed with
	 * it.
	 */
	int data_owner;
	/* Decoded header fields. */
	int version;
	GT_HashDBIndex first_publication_ident;
	size_t data_block_begin;
	size_t publication_cell_size;
	unsigned int number_of_publications;
	size_t key_hashes_begin;
	size_t key_hash_cell_size;
	unsigned int number_of_key_hashes;
	size_t pub_reference_begin;
	size_t signature_block_begin;
	/**
	 * Array of decoded publication cells.
	 */
	GTPublicationsFile_Cell *publication_cells;
	/**
	 * Array of decoded key hash cells.
	 */
	GTPublicationsFile_KeyHashCell *key_hash_cells;
	/**
	 * Decoded publication reference.
	 */
	GTReferences *pub_reference;
	/**
	 * Decoded PKCS7 signature.
	 */
	PKCS7 *signature;
};

/*
 * This anonymous enum defines file header structure.
 */
enum {
	GTPublicationsFile_CurrentVersion = 1,
	GTPublicationsFile_HeaderOffset_version = 0,
	GTPublicationsFile_HeaderOffset_firstPublicationIdent = 2,
	GTPublicationsFile_HeaderOffset_dataBlockBegin = 10,
	GTPublicationsFile_HeaderOffset_publicationCellSize = 14,
	GTPublicationsFile_HeaderOffset_numberOfPublications = 16,
	GTPublicationsFile_HeaderOffset_keyHashesBegin = 20,
	GTPublicationsFile_HeaderOffset_keyHashCellSize = 24,
	GTPublicationsFile_HeaderOffset_numberOfKeyHashes = 26,
	GTPublicationsFile_HeaderOffset_pubReferenceBegin = 28,
	GTPublicationsFile_HeaderOffset_signatureBlockBegin = 32,
	GTPublicationsFile_HeaderLength = 36
};

/**
 * This anonymous enum defines file cell structure.
 */
enum {
	GTPublicationsFile_CellOffset_publicationIdentifier = 0,
	GTPublicationsFile_CellOffset_publicationImprint = 8
	/* Cell length depends on the value of publicationImprint. */
};

/**
 * This anonymous enum defines file key hash cell structure.
 */
enum {
	GTPublicationsFile_KeyHashCellOffset_keyPublicationTime = 0,
	GTPublicationsFile_KeyHashCellOffset_keyHashImprint = 8
	/* Key hash cell length depends on the value of keyHashImprint. */
};

/**
 * This function returns the key hash (in data imprint format) at the
 * specified index.
 *
 * \param publications_file \c (in) - \c GTPublicationsFile object that is
 * 	to be freed.
 * \param keyhash_index \c (in) - index of the key hash in question
 * \param imprint \c (out) - the key hash. DO NOT free it up!
 * \param imprint_length \c (out) - the data imprint length
 * 	(e.g. 1 + hash length).
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GTPublicationsFile_getKeyHash(
		const GTPublicationsFile *publications_file,
		unsigned int keyhash_index,
		const unsigned char** imprint, size_t* imprint_length);

/**
 * Extracts published data with the given identifier from the publications
 * file.
 *
 * \param publications_file \c (in) - Publications file to extract from.
 *
 * \param publication_identifier \c (in) - Identifier of the publication to
 * extract.
 *
 * \param published_data \c (out) - Pointer to the pointer receiving output
 * value. This value must be freed with \c GTPublishedData_free when not
 * needed anymore.
 *
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GTPublicationsFile_getPublishedData(
		const GTPublicationsFile *publications_file,
		GT_HashDBIndex publication_identifier,
		GTPublishedData **published_data);

/**
 * Extracts publication with the given identifier from the published file.
 *
 * \param published_file \c (in) - Published file to extract from.
 *
 * \param publication_identifier \c (in) - Identifier of the publication to
 * extract.
 *
 * \param publication \c (out) - Pointer to the pointer receiving output value.
 * This value must be freed with \c GT_free when not needed anymore.
 *
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GTPublicationsFile_getBase32PublishedData(
		const GTPublicationsFile *publications_file,
		GT_HashDBIndex publication_identifier, char **publication);

/**
 * Extracts DER-encoded signing certificate from the given publicatin file.
 *
 * \param publications_file \c (in) - Pointer to publications file.
 *
 * \param cert_der \c (out) - Pointer to the variable that receives pointer
 * to the DER-encoded certificate. Note that this pointer must be freed with
 * \c GT_free() when not needed anymore.
 *
 * \param cert_der_length \c (out) - Pointer to the variable that receives
 * length of the DER-encoded certificate.
 *
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GTPublicationsFile_getSigningCert(
		const GTPublicationsFile *publications_file,
		unsigned char **cert_der, size_t *cert_der_length);

#ifdef __cplusplus
}
#endif

#endif /* not GT_PUBLICATIONSFILE_H_INCLUDED */
