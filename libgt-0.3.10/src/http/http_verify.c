/*
 * $Id: http_verify.c 98 2010-12-01 13:19:04Z ahto.truu $
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
 *
 *
 * This is an example of verifying a timestamp using the GuardTime SDK.
 *
 * To compile the example under Linux, use a command along the lines of
 *    gcc http_verify.c -o http_verify -I/usr/local/gt/include
 *    -L/usr/local/gt/lib -L/usr/local/curl/lib -L/usr/local/ssl/lib
 *    -lgthttp -lgtbase -lcurl -lcrypto -lrt
 * replacing /usr/local/gt, /usr/local/curl, and /usr/local/ssl
 * with the directories where you unpacked the GuardTime, cURL, and
 * OpenSSL libraries, of course (you can skip the -I and -L options
 * if you installed everything in standard system locations).
 *
 * To compile the example under Windows, use a command along the lines of
 *    cl.exe http_verify.c /MT /I C:\gt\include
 *    /link /libpath:C:\gt\lib /libpath:C:\openssl\lib
 *    libgthttpMT.lib libgtbaseMT.lib libeay32MT.lib wininet.lib
 *    wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib
 * replacing C:\gt and C:\openssl with the directories where you unpacked
 * the GuardTime and OpenSSL libraries, of course.
 *
 * To run the compiled example, use a command along the lines of
 *    http_verify timestamp_in_file data_in_file publications_url verifier_url
 * for example
 *    http_verify TestData.txt.gtts TestData.txt
 *    http://verify.guardtime.com/gt-controlpublications.bin
 *    http://verifier.guardtime.net/gt-extendingservice
 * Check the GuardTime website for the URLs of nearest public services.
 */

#include "gt_base.h"
#include "gt_http.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char* argv[])
{
	int res = GT_OK;

	char *timestamp_file = NULL;
	char *data_file = NULL;
	char *publications_url = NULL;
	char *tsa_url = NULL;

	unsigned char *stamp_der = NULL;
	size_t stamp_der_len;
	GTTimestamp *timestamp = NULL;

	int hash_algo;
	GTDataHash *data_hash = NULL;

	GTVerificationInfo *ver = NULL;

	/* Read arguments. */
	if (argc != 5) {
		printf("Usage: %s timestamp_in_file data_in_file "
				"publications_url <verifier_url | \"-\">\n", argv[0]);
		goto cleanup;
	}
	timestamp_file = argv[1];
	data_file = argv[2];
	publications_url = argv[3];
	tsa_url = strcmp(argv[4], "-") == 0 ? NULL : argv[4];

	/* Init GuardTime libraries. */
	res = GT_init();
	if (res != GT_OK) {
		fprintf(stderr, "GT_init() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		goto cleanup;
	}
	res = GTHTTP_init("C SDK example", 1);
	if (res != GT_OK) {
		fprintf(stderr, "GTHTTP_init() failed: %d (%s)\n",
				res, GTHTTP_getErrorString(res));
		goto cleanup;
	}

	/* Read timestamp file. */
	res = GT_loadFile(timestamp_file, &stamp_der, &stamp_der_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot load timestamp file %s: %d (%s)\n",
				timestamp_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* Decode timestamp. */
	res = GTTimestamp_DERDecode(stamp_der, stamp_der_len, &timestamp);
	if (res != GT_OK) {
		fprintf(stderr, "GTTimestamp_DERDecode() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		goto cleanup;
	}

	/* Hash data file. */
	res = GTTimestamp_getAlgorithm(timestamp, &hash_algo);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GT_hashFile(data_file, hash_algo, &data_hash);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot hash data file %s: %d (%s)\n",
				data_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* Verify timestamp. */
	res = GTHTTP_verifyTimestampHash(timestamp, data_hash,
		tsa_url, NULL, NULL, publications_url, 0, &ver);
	if (res != GT_OK) {
		fprintf(stderr, "GTHTTP_verifyTimestampHash() failed: %d (%s)\n",
				res, GTHTTP_getErrorString(res));
		goto cleanup;
	}

	GTVerificationInfo_print(stderr, 0, ver);
	if (ver->verification_errors == GT_NO_FAILURES) {
		printf("Verification succeeded!\n");
	}

cleanup:

	GTVerificationInfo_free(ver);
	GTDataHash_free(data_hash);
	GTTimestamp_free(timestamp);
	GT_free(stamp_der);

	/* Finalize GuardTime libraries. */
	GTHTTP_finalize();
	GT_finalize();

	return res == GT_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
