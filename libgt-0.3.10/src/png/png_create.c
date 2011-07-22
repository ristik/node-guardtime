/*
 * $Id: png_create.c 98 2010-12-01 13:19:04Z ahto.truu $
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
 * This is an example of adding a timestamp to a PNG image
 * using the GuardTime SDK.
 *
 * To compile the example under Linux, use a command along the lines of
 *    gcc png_create.c -o png_create -I/usr/local/gt/include
 *    -L/usr/local/gt/lib -L/usr/local/curl/lib -L/usr/local/ssl/lib
 *    -lgtpng -lgthttp -lgtbase -lcurl -lcrypto -lrt
 * replacing /usr/local/gt, /usr/local/curl, and /usr/local/ssl
 * with the directories where you unpacked the GuardTime, cURL, and
 * OpenSSL libraries, of course (you can skip the -I and -L options
 * if you installed everything in standard system locations).
 *
 * To compile the example under Windows, use a command along the lines of
 *    cl.exe png_create.c /MT /I C:\gt\include
 *    /link /libpath:C:\gt\lib /libpath:C:\openssl\lib
 *    libgtpngMT.lib libgthttpMT.lib libgtbaseMT.lib libeay32MT.lib wininet.lib
 *    wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib
 * replacing C:\gt and C:\openssl with the directories where you unpacked
 * the GuardTime and OpenSSL libraries, of course.
 *
 * To run the compiled example, use a command along the lines of
 *    png_create data_in_file data_out_file stamper_url
 * for example
 *    png_create TestData.png TestData.png
 *    http://stamper.guardtime.net/gt-signingservice
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

	char *in_file = NULL;
	char *out_file = NULL;
	char *tsa_url = NULL;

	unsigned char *in_data = NULL;
	size_t in_data_len;
	unsigned char *out_data = NULL;
	size_t out_data_len;

	/* Read arguments. */
	if (argc != 4) {
		printf("Usage: %s data_in_file data_out_file stamper_url\n", argv[0]);
		goto cleanup;
	}
	in_file = argv[1];
	out_file = argv[2];
	tsa_url = argv[3];

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
	res = GT_loadFile(in_file, &in_data, &in_data_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot load image file %s: %d (%s)\n",
				in_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* Add timestamp to the image. */
	res = GTPNG_createTimestamp(in_data, in_data_len, tsa_url, &out_data, &out_data_len);
	if (res != GT_OK) {
		fprintf(stderr, "GTPNG_createTimestamp() failed: %d (%s)\n",
				res, GTPNG_getErrorString(res));
		goto cleanup;
	}

	/* Save the new image to file. */
	res = GT_saveFile(out_file, out_data, out_data_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot save image to file %s: %d (%s)\n",
				out_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	printf("Timestamping succeeded!\n");

cleanup:

	GT_free(out_data);
	GT_free(in_data);

	/* Finalize GuardTime libraries. */
	GTHTTP_finalize();
	GT_finalize();

	return res == GT_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
