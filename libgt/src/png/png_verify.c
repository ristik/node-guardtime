/*
 * $Id: png_verify.c 98 2010-12-01 13:19:04Z ahto.truu $
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
 * This is an example of verifying a timestamp embedded in a PNG image
 * using the GuardTime SDK.
 *
 * To compile the example under Linux, use a command along the lines of
 *    gcc png_verify.c -o png_verify -I/usr/local/gt/include
 *    -L/usr/local/gt/lib -L/usr/local/curl/lib -L/usr/local/ssl/lib
 *    -lgtpng -lgthttp -lgtbase -lcurl -lcrypto -lrt
 * replacing /usr/local/gt, /usr/local/curl, and /usr/local/ssl
 * with the directories where you unpacked the GuardTime, cURL, and
 * OpenSSL libraries, of course (you can skip the -I and -L options
 * if you installed everything in standard system locations).
 *
 * To compile the example under Windows, use a command along the lines of
 *    cl.exe png_verify.c /MT /I C:\gt\include
 *    /link /libpath:C:\gt\lib /libpath:C:\openssl\lib
 *    libgtpngMT.lib libgthttpMT.lib libgtbaseMT.lib libeay32MT.lib wininet.lib
 *    wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib
 * replacing C:\gt and C:\openssl with the directories where you unpacked
 * the GuardTime and OpenSSL libraries, of course.
 *
 * To run the compiled example, use a command along the lines of
 *    png_verify data_in_file publications_url verifier_url
 * for example
 *    png_verify TestData.png
 *    http://verify.guardtime.com/gt-controlpublications.bin
 *    http://verifier.guardtime.net/gt-extendingservice
 * Check the GuardTime website for the URLs of nearest public services.
 */

#include "gt_base.h"
#include "gt_http.h"
#include "gt_png.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char* argv[])
{
	int res = GT_OK;

	char *data_file = NULL;
	char *publications_url = NULL;
	char *tsa_url = NULL;

	unsigned char *data = NULL;
	size_t data_len;

	GTVerificationInfo *ver = NULL;

	/* Read arguments. */
	if (argc != 4) {
		printf("Usage: %s data_in_file publications_url "
				"<verifier_url | \"-\">\n", argv[0]);
		goto cleanup;
	}
	data_file = argv[1];
	publications_url = argv[2];
	tsa_url = strcmp(argv[3], "-") == 0 ? NULL : argv[3];

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

	/* Read data file. */
	res = GT_loadFile(data_file, &data, &data_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot load image file %s: %d (%s)\n",
				data_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* Verify timestamp. */
	res = GTPNG_verifyTimestamp(data, data_len,
		tsa_url, NULL, NULL, publications_url, 0, &ver);
	if (res != GT_OK) {
		fprintf(stderr, "GTPNG_verifyTimestamp() failed: %d (%s)\n",
				res, GTPNG_getErrorString(res));
		goto cleanup;
	}

	GTVerificationInfo_print(stderr, 0, ver);
	if (ver->verification_errors == GT_NO_FAILURES) {
		printf("Verification succeeded!\n");
	}

cleanup:

	GTVerificationInfo_free(ver);
	GT_free(data);

	/* Finalize GuardTime libraries. */
	GTHTTP_finalize();
	GT_finalize();

	return res == GT_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
