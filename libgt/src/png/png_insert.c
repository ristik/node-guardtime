/*
 * $Id: png_insert.c 98 2010-12-01 13:19:04Z ahto.truu $
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
 * This is an example of inserting a timestamp from an external file
 * into a PNG image using the GuardTime SDK.
 *
 * To compile the example under Linux, use a command along the lines of
 *    gcc png_insert.c -o png_insert -I/usr/local/gt/include
 *    -L/usr/local/gt/lib -L/usr/local/curl/lib -L/usr/local/ssl/lib
 *    -lgtpng -lgthttp -lgtbase -lcurl -lcrypto -lrt
 * replacing /usr/local/gt, /usr/local/curl, and /usr/local/ssl
 * with the directories where you unpacked the GuardTime, cURL, and
 * OpenSSL libraries, of course (you can skip the -I and -L options
 * if you installed everything in standard system locations).
 *
 * To compile the example under Windows, use a command along the lines of
 *    cl.exe png_insert.c /MT /I C:\gt\include
 *    /link /libpath:C:\gt\lib /libpath:C:\openssl\lib
 *    libgtpngMT.lib libgthttpMT.lib libgtbaseMT.lib libeay32MT.lib wininet.lib
 *    wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib
 * replacing C:\gt and C:\openssl with the directories where you unpacked
 * the GuardTime and OpenSSL libraries, of course.
 *
 * To run the compiled example, use a command along the lines of
 *    png_insert data_in_file timestamp_in_file data_out_file
 * for example
 *    png_insert TestData.png TestData.png.gtts TestData.png
 * (Note that this usage would update the image file in-place.)
 */

#include "gt_base.h"
#include "gt_png.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char* argv[])
{
	int res = GT_OK;

	char *data_in_file = NULL;
	char *ts_in_file = NULL;
	char *data_out_file = NULL;

	unsigned char *data = NULL;
	size_t data_len;
	size_t buf_len;
	unsigned char *ts = NULL;
	size_t ts_len;

	/* Read arguments. */
	if (argc != 4) {
		printf("Usage: %s data_in_file timestamp_in_file data_out_file\n", argv[0]);
		goto cleanup;
	}
	data_in_file = argv[1];
	ts_in_file = argv[2];
	data_out_file = argv[3];

	/* Init GuardTime libraries. */
	res = GT_init();
	if (res != GT_OK) {
		fprintf(stderr, "GT_init() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		goto cleanup;
	}

	/* Read data file. */
	res = GT_loadFile(data_in_file, &data, &data_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot load image file %s: %d (%s)\n",
				data_in_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* Check if the image already has a timestamp. */
	res = GTPNG_extract(data, data_len, NULL, NULL);
	if (res == GT_OK) {
		fprintf(stdout, "Note: the source file is already timestamped\n");
		fprintf(stdout, "\tthe existing timestamp will not be copied\n");
	} else if (res != GTPNG_NO_GTTS) {
		fprintf(stderr, "Invalid PNG file %s: %d (%s)\n",
				data_in_file, res, GTPNG_getErrorString(res));
	}

	/* Read timestamp file. */
	res = GT_loadFile(ts_in_file, &ts, &ts_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot load timestamp file %s: %d (%s)\n",
				ts_in_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	/* NOTE: In real life, we should verify the timestamp before using it,
	 * but our point here is the handling of the PNG file, so we skip the
	 * verification step. */

	/* Increase the memory buffer. */
	buf_len = data_len + (4 + 4 + 1 + ts_len + 4);
	data = GT_realloc(data, buf_len);
	if (data == NULL) {
		res = GT_OUT_OF_MEMORY;
		fprintf(stderr, "Cannot allocate memory: %d (%s)\n",
				res, GTPNG_getErrorString(res));
		goto cleanup;
	}

	/* Insert the timestamp in the image. */
	res = GTPNG_insert(data, &data_len, buf_len, ts, ts_len);
	if (res != GT_OK) {
		fprintf(stderr, "GTPNG_insert() failed: %d (%s)\n",
				res, GTPNG_getErrorString(res));
		goto cleanup;
	}

	/* Save the new image to file. */
	res = GT_saveFile(data_out_file, data, data_len);
	if (res != GT_OK) {
		fprintf(stderr, "Cannot save image to file %s: %d (%s)\n",
				data_out_file, res, GT_getErrorString(res));
		if (res == GT_IO_ERROR) {
			fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
		}
		goto cleanup;
	}

	printf("Inserting succeeded!\n");

cleanup:

	GT_free(ts);
	GT_free(data);

	/* Finalize GuardTime libraries. */
	GT_finalize();

	return res == GT_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
