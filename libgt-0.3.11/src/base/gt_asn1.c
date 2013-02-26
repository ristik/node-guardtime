/*
 * $Id: gt_asn1.c 74 2010-02-22 11:42:26Z ahto.truu $
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

#include "gt_asn1.h"

#include <assert.h>

#include <openssl/asn1t.h>

/* id-gt-TimeSignatureAlg */

const ASN1_OBJECT *GT_id_gt_time_signature_alg = NULL;
int GT_id_gt_time_signature_alg_nid = NID_undef;

/* GTMessageImprint */

ASN1_SEQUENCE(GTMessageImprint) = {
	ASN1_SIMPLE(GTMessageImprint, hashAlgorithm, X509_ALGOR),
	ASN1_SIMPLE(GTMessageImprint, hashedMessage, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(GTMessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(GTMessageImprint)
IMPLEMENT_ASN1_DUP_FUNCTION(GTMessageImprint)

int GTMessageImprint_cmp(const GTMessageImprint *a1,
		const GTMessageImprint *a2)
{
	int ret;

	ret = OBJ_cmp(a1->hashAlgorithm->algorithm,
			a2->hashAlgorithm->algorithm);
	if (ret != 0) {
		return ret;
	}

	ret = ASN1_OCTET_STRING_cmp(a1->hashedMessage, a2->hashedMessage);
	return ret;
}

/* GTTimeStampReq */

ASN1_SEQUENCE(GTTimeStampReq) = {
	ASN1_SIMPLE(GTTimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(GTTimeStampReq, messageImprint, GTMessageImprint),
	ASN1_OPT(GTTimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT(GTTimeStampReq, nonce, ASN1_INTEGER),
	ASN1_OPT(GTTimeStampReq, certReq, ASN1_FBOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(
			GTTimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(GTTimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(GTTimeStampReq)

/* GTAccuracy */

ASN1_SEQUENCE(GTAccuracy) = {
	ASN1_OPT(GTAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(GTAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(GTAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(GTAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(GTAccuracy)
IMPLEMENT_ASN1_DUP_FUNCTION(GTAccuracy)

/* GTTSTInfo */

ASN1_SEQUENCE(GTTSTInfo) = {
	ASN1_SIMPLE(GTTSTInfo, version, ASN1_INTEGER),
	ASN1_SIMPLE(GTTSTInfo, policy, ASN1_OBJECT),
	ASN1_SIMPLE(GTTSTInfo, messageImprint, GTMessageImprint),
	ASN1_SIMPLE(GTTSTInfo, serialNumber, ASN1_INTEGER),
	ASN1_SIMPLE(GTTSTInfo, genTime, ASN1_GENERALIZEDTIME),
	ASN1_OPT(GTTSTInfo, accuracy, GTAccuracy),
	ASN1_OPT(GTTSTInfo, ordering, ASN1_FBOOLEAN),
	ASN1_OPT(GTTSTInfo, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(GTTSTInfo, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(GTTSTInfo, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(GTTSTInfo)

IMPLEMENT_ASN1_FUNCTIONS(GTTSTInfo)

/* GTPKIStatusInfo */

ASN1_SEQUENCE(GTPKIStatusInfo) = {
	ASN1_SIMPLE(GTPKIStatusInfo, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(GTPKIStatusInfo, statusString, ASN1_UTF8STRING),
	ASN1_OPT(GTPKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(GTPKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(GTPKIStatusInfo)

/* GTPublishedData */

ASN1_SEQUENCE(GTPublishedData) = {
	ASN1_SIMPLE(GTPublishedData, publicationIdentifier, ASN1_INTEGER),
	ASN1_SIMPLE(GTPublishedData, publicationImprint, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(GTPublishedData)

IMPLEMENT_ASN1_FUNCTIONS(GTPublishedData)
IMPLEMENT_ASN1_DUP_FUNCTION(GTPublishedData)

int GTPublishedData_cmp(const GTPublishedData *a1, const GTPublishedData *a2)
{
	int res;

	res = ASN1_INTEGER_cmp(
			a1->publicationIdentifier, a2->publicationIdentifier);
	if (res == 0) {
		res = ASN1_OCTET_STRING_cmp(
				a1->publicationImprint, a2->publicationImprint);
	}

	return res;
}

/* GTReferences */

ASN1_ITEM_TEMPLATE(GTReferences) =
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, GTReferences, ASN1_OCTET_STRING)
ASN1_ITEM_TEMPLATE_END(GTReferences)

IMPLEMENT_ASN1_FUNCTIONS(GTReferences)
IMPLEMENT_ASN1_DUP_FUNCTION(GTReferences)

/* GTSignatureInfo */

ASN1_SEQUENCE(GTSignatureInfo) = {
	ASN1_SIMPLE(GTSignatureInfo, signatureAlgorithm, X509_ALGOR),
	ASN1_SIMPLE(GTSignatureInfo, signatureValue, ASN1_OCTET_STRING),
	ASN1_IMP_SET_OF_OPT(
			GTSignatureInfo, keyCommitmentRef, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(GTSignatureInfo)

IMPLEMENT_ASN1_FUNCTIONS(GTSignatureInfo)

/* GTTimeSignature */

ASN1_SEQUENCE(GTTimeSignature) = {
	ASN1_SIMPLE(GTTimeSignature, location, ASN1_OCTET_STRING),
	ASN1_SIMPLE(GTTimeSignature, history, ASN1_OCTET_STRING),
	ASN1_SIMPLE(GTTimeSignature, publishedData, GTPublishedData),
	ASN1_IMP_OPT(GTTimeSignature, pkSignature, GTSignatureInfo, 0),
	ASN1_IMP_SET_OF_OPT(GTTimeSignature, pubReference, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(GTTimeSignature)

IMPLEMENT_ASN1_FUNCTIONS(GTTimeSignature)

/* GTTimeStampResp */

ASN1_SEQUENCE(GTTimeStampResp) = {
	ASN1_SIMPLE(GTTimeStampResp, status, GTPKIStatusInfo),
	ASN1_OPT(GTTimeStampResp, timeStampToken, PKCS7)
} ASN1_SEQUENCE_END(GTTimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(GTTimeStampResp)

/* GTCertTokenRequest */

ASN1_SEQUENCE(GTCertTokenRequest) = {
	ASN1_SIMPLE(GTCertTokenRequest, version, ASN1_INTEGER),
	ASN1_SIMPLE(GTCertTokenRequest, historyIdentifier, ASN1_INTEGER),
	ASN1_IMP_SEQUENCE_OF_OPT(
			GTCertTokenRequest, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(GTCertTokenRequest)

IMPLEMENT_ASN1_FUNCTIONS(GTCertTokenRequest)

/* GTCertToken */

ASN1_SEQUENCE(GTCertToken) = {
	ASN1_SIMPLE(GTCertToken, version, ASN1_INTEGER),
	ASN1_SIMPLE(GTCertToken, history, ASN1_OCTET_STRING),
	ASN1_SIMPLE(GTCertToken, publishedData, GTPublishedData),
	ASN1_SET_OF(GTCertToken, pubReference, ASN1_OCTET_STRING),
	ASN1_IMP_SEQUENCE_OF_OPT(GTCertToken, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(GTCertToken)

IMPLEMENT_ASN1_FUNCTIONS(GTCertToken)

/* GTCertTokenResponse */

ASN1_SEQUENCE(GTCertTokenResponse) = {
	ASN1_SIMPLE(GTCertTokenResponse, status, GTPKIStatusInfo),
	ASN1_IMP_OPT(GTCertTokenResponse, certToken, GTCertToken, 0)
} ASN1_SEQUENCE_END(GTCertTokenResponse)

IMPLEMENT_ASN1_FUNCTIONS(GTCertTokenResponse)
