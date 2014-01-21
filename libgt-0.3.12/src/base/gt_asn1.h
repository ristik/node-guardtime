/*
 * $Id: gt_asn1.h 177 2014-01-16 22:18:43Z ahto.truu $
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

#ifndef GT_ASN1_H_INCLUDED
#define GT_ASN1_H_INCLUDED

#include "gt_base.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>

#ifdef __cplusplus
extern"C" {
#endif

#define sk_ASN1_OCTET_STRING_num(st) SKM_sk_num(ASN1_OCTET_STRING, (st))
#define sk_ASN1_OCTET_STRING_value(st, i) SKM_sk_value(ASN1_OCTET_STRING, (st), (i))
#define sk_ASN1_OCTET_STRING_push(st, val) SKM_sk_push(ASN1_OCTET_STRING, (st), (val))
#define sk_ASN1_OCTET_STRING_new_null() SKM_sk_new_null(ASN1_OCTET_STRING)

/*
 * id-gt-TimeSignatureAlg OBJECT IDENTIFIER ::= {
 *     iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
 *     GuardTime(27868) algorithm(4) 1
 * }
 */
#define GT_ID_GT_TIME_SIGNATURE_ALG_OID "1.3.6.1.4.1.27868.4.1"
#define GT_ID_GT_TIME_SIGNATURE_ALG_SN "id-gt-TimeSignatureAlg"
#define GT_ID_GT_TIME_SIGNATURE_ALG_LN "GuardTime Time Signature Algorithm"
extern const ASN1_OBJECT *GT_id_gt_time_signature_alg;
extern int GT_id_gt_time_signature_alg_nid;

/*
 * MessageImprint ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier,
 *     hashedMessage  OCTET STRING
 * }
 */
typedef struct GTMessageImprint_st {
	X509_ALGOR *hashAlgorithm;
	ASN1_OCTET_STRING *hashedMessage;
} GTMessageImprint;

DECLARE_ASN1_FUNCTIONS(GTMessageImprint)
GTMessageImprint* GTMessageImprint_dup(GTMessageImprint *src);
int GTMessageImprint_cmp(const GTMessageImprint *a1,
		const GTMessageImprint *a2);

/*
 * TSAPolicyId ::= OBJECT IDENTIFIER
 *
 * TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE OPTIONAL,
 *     extensions     [0] Extensions OPTIONAL
 * }
 *
 * NOTE: reqPolicy and nonce aren't used in GuardTime.
 * NOTE: TSAPolicyId is of type ASN1_OBJECT, use OBJ_nid2obj() to set its value.
 */
typedef struct GTTimeStampReq_st {
	ASN1_INTEGER *version;
	GTMessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN certReq;
	STACK_OF(X509_EXTENSION) *extensions;
} GTTimeStampReq;

DECLARE_ASN1_FUNCTIONS(GTTimeStampReq)

/*
 * Accuracy ::= SEQUENCE {
 *     seconds        INTEGER            OPTIONAL,
 *     millis     [0] INTEGER (1..999)   OPTIONAL,
 *     micros     [1] INTEGER (1..999)   OPTIONAL
 * }
 */
typedef struct GTAccuracy_st {
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
} GTAccuracy;

DECLARE_ASN1_FUNCTIONS(GTAccuracy)
GTAccuracy* GTAccuracy_dup(GTAccuracy *src);

/*
 * TSAPolicyId ::= OBJECT IDENTIFIER
 *
 * TSTInfo ::= SEQUENCE {
 *     version                     INTEGER  { v1(1) },
 *     policy                      TSAPolicyId,
 *     messageImprint              MessageImprint,
 *         -- MUST have the same value as the similar field in
 *         -- TimeStampReq
 *     serialNumber                INTEGER,
 *         -- Time-Stamping users MUST be ready to accommodate integers
 *         -- up to 160 bits.
 *     genTime                     GeneralizedTime,
 *     accuracy                    Accuracy                OPTIONAL,
 *     ordering                    BOOLEAN                 DEFAULT FALSE,
 *     nonce                       INTEGER                 OPTIONAL,
 *         -- MUST be present if the similar field was present
 *         -- in TimeStampReq.  In that case it MUST have the same value.
 *     tsa                         [0] GeneralName         OPTIONAL,
 *     extensions                  [1] IMPLICIT Extensions OPTIONAL
 * }
 */
typedef struct GTTSTInfo_st {
	ASN1_INTEGER *version;
	ASN1_OBJECT *policy;
	GTMessageImprint *messageImprint;
	ASN1_INTEGER *serialNumber;
	ASN1_GENERALIZEDTIME *genTime;
	GTAccuracy *accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER *nonce;
	GENERAL_NAME *tsa;
	STACK_OF(X509_EXTENSION) *extensions;
} GTTSTInfo;

DECLARE_ASN1_FUNCTIONS(GTTSTInfo)

/*
 * PKIStatus ::= INTEGER {
 *     granted                 (0),
 *     grantedWithMods         (1),
 *     rejection               (2),
 *     waiting                 (3),
 *     revocationWarning       (4),
 *     revocationNotification  (5)
 * }
 */
typedef enum GTPKIStatus_en {
	GTPKIStatus_granted = 0,
	GTPKIStatus_grantedWithMods = 1,
	GTPKIStatus_rejection = 2,
	GTPKIStatus_waiting = 3,
	GTPKIStatus_revocationWarning = 4,
	GTPKIStatus_revocationNotification = 5
} GTPKIStatus;

/*
 * PKIFailureInfo ::= BIT STRING {
 *     badAlg               (0),
 *     badRequest           (2),
 *     badDataFormat        (5),
 *     timeNotAvailable     (14),
 *     unacceptedPolicy     (15),
 *     unacceptedExtension  (16),
 *     addInfoNotAvailable  (17),
 *     systemFailure        (25)
 * }
 */
typedef enum GTPKIFailureInfo_en {
	GTPKIFailureInfo_badAlg = 0,
	GTPKIFailureInfo_badRequest = 2,
	GTPKIFailureInfo_badDataFormat = 5,
	GTPKIFailureInfo_timeNotAvailable = 14,
	GTPKIFailureInfo_unacceptedPolicy = 15,
	GTPKIFailureInfo_unacceptedExtension = 16,
	GTPKIFailureInfo_addInfoNotAvailable = 17,
	GTPKIFailureInfo_systemFailure = 25,
	/* not standard error codes (e.g. not in RFC-3161) */
	GTPKIFailureInfo_extendLater = 100,
	GTPKIFailureInfo_extensionOverdue = 101
} GTPKIFailureInfo;

/*
 * FreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
 *     -- text encoded as UTF-8 String (note:  each UTF8String SHOULD
 *     -- include an RFC 1766 language tag to indicate the language
 *     -- of the contained text)
 *
 * PKIFailureInfo ::= BIT STRING
 *
 * PKIStatusInfo ::= SEQUENCE {
 *     status            PKIStatus,
 *     statusString      PKIFreeText OPTIONAL,
 *     failInfo          PKIFailureInfo OPTIONAL
 * }
 */
typedef struct GTPKIStatusInfo_st {
	ASN1_INTEGER *status;
	/* Note that there's no STACK_OF(ASN1_UTF8STRING) declared in
	 * OpenSSL as of 0.9.8, but it still works and looks better than
	 * plain STACK. */
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
} GTPKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(GTPKIStatusInfo)

/*
 * PublishedData ::= SEQUENCE {
 *     publicationIdentifier	INTEGER,
 *     publicationImprint	DataImprint,
 * }
 */
typedef struct GTPublishedData_st {
	ASN1_INTEGER *publicationIdentifier;
	ASN1_OCTET_STRING *publicationImprint;
} GTPublishedData;

DECLARE_ASN1_FUNCTIONS(GTPublishedData)
GTPublishedData* GTPublishedData_dup(GTPublishedData *src);

int GTPublishedData_cmp(const GTPublishedData *a1, const GTPublishedData *a2);

/*
 * Reference ::= OCTET STRING
 *
 * References ::= SET OF Reference
 */
typedef STACK_OF(ASN1_OCTET_STRING) GTReferences;

DECLARE_ASN1_ITEM(GTReferences)
DECLARE_ASN1_FUNCTIONS(GTReferences)
GTReferences* GTReferences_dup(GTReferences *src);

/*
 * SignatureInfo ::= SEQUENCE {
 *     signatureAlgorithm  AlgorithmIdentifier,
 *     signatureValue      OCTET STRING,
 *     keyCommitmentRef    [0] References OPTIONAL
 * }
 */
typedef struct GTSignatureInfo_st {
	X509_ALGOR *signatureAlgorithm;
	ASN1_OCTET_STRING *signatureValue;
	GTReferences *keyCommitmentRef;
} GTSignatureInfo;

DECLARE_ASN1_FUNCTIONS(GTSignatureInfo)

/*
 * HashChain ::= OCTET STRING
 *
 * TimeSignature ::= SEQUENCE {
 *     location        HashChain,
 *     history         HashChain,
 *     publishedData   PublishedData,
 *     pkSignature     [0] SignatureInfo OPTIONAL,
 *     pubReference    [1] References OPTIONAL,
 * }
 */
typedef struct GTTimeSignature_st {
	ASN1_OCTET_STRING *location;
	ASN1_OCTET_STRING *history;
	GTPublishedData *publishedData;
	GTSignatureInfo *pkSignature;
	GTReferences *pubReference;
} GTTimeSignature;

DECLARE_ASN1_FUNCTIONS(GTTimeSignature)

/*
 * TimeStampResp ::= SEQUENCE {
 *     status              PKIStatusInfo,
 *     timeStampToken      TimeStampToken  OPTIONAL
 * }
 *
 * Note that there's no need to declare id-ct-TSTInfo here because it is
 * already defined by OpenSSL as NID_id_smime_ct_TSTInfo.
 */
typedef struct GTTimeStampResp_st {
	GTPKIStatusInfo *status;
	PKCS7 *timeStampToken;
} GTTimeStampResp;

DECLARE_ASN1_FUNCTIONS(GTTimeStampResp)

/*
 * CertTokenRequest ::= SEQUENCE {
 *     version           INTEGER { v1(1) },
 *     historyIdentifier INTEGER,
 *     extensions        [0] Extensions OPTIONAL
 * }
 */
typedef struct GTCertTokenRequest_st {
	ASN1_INTEGER *version;
	ASN1_INTEGER *historyIdentifier;
	STACK_OF(X509_EXTENSION) *extensions;
} GTCertTokenRequest;

DECLARE_ASN1_FUNCTIONS(GTCertTokenRequest)

/*
 * HashChain ::= OCTET STRING
 *
 * CertToken ::= SEQUENCE {
 *     version         INTEGER { v1(1) },
 *     history         HashChain,
 *     publishedData   PublishedData,
 *     pubReference    References,
 *     extensions      [0] Extensions OPTIONAL
 * }
 */
typedef struct GTCertToken_st {
	ASN1_INTEGER *version;
	ASN1_OCTET_STRING *history;
	GTPublishedData *publishedData;
	GTReferences *pubReference;
	STACK_OF(X509_EXTENSION) *extensions;
} GTCertToken;

DECLARE_ASN1_FUNCTIONS(GTCertToken)

/*
 * CertTokenResponse ::= SEQUENCE {
 *     status      PKIStatusInfo,
 *     certToken   [0] CertToken OPTIONAL
 * }
 */
typedef struct GTCertTokenResponse_st {
	GTPKIStatusInfo *status;
	GTCertToken *certToken;
} GTCertTokenResponse;

DECLARE_ASN1_FUNCTIONS(GTCertTokenResponse)

#ifdef __cplusplus
}
#endif

#endif /* not GT_ASN1_H_INCLUDED */
