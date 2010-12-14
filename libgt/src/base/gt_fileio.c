/*
 * $Id: gt_fileio.c 74 2010-02-22 11:42:26Z ahto.truu $
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
#include "gt_internal.h"

#include <stdio.h>
#include <errno.h>

/**/

int GT_loadFile(const char *path, unsigned char **out_data, size_t *out_size)
{
	int retval = GT_UNKNOWN_ERROR;
	FILE *f = NULL;
	unsigned char *tmp_data = NULL;
	long tmp_size;
	size_t read_size;

	f = fopen(path, "rb");
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}

	if (fseek(f, 0, SEEK_END)) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}

	tmp_size = ftell(f);
	if (tmp_size < 0) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}

	rewind(f);

	tmp_data = GT_malloc(tmp_size + 1);
	if (tmp_data == NULL) {
		retval = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp_data[tmp_size] = '\0';

	read_size = fread(tmp_data, 1, tmp_size, f);
	if (read_size != tmp_size) {
		retval = GT_IO_ERROR;
		if (!ferror(f)) {
			/* It looks like file was truncated during read? Use "Broken pipe"
			 * as error code in this case. */
			errno = EPIPE;
		}
		goto cleanup;
	}

	*out_data = tmp_data;
	tmp_data = NULL;
	*out_size = tmp_size;
	retval = 0;

cleanup:

	if (f != NULL) {
		fclose(f);
	}
	GT_free(tmp_data);

	return retval;
}

/**/

int GT_saveFile(const char *path, const void *in_data, size_t in_size)
{
	int retval = GT_UNKNOWN_ERROR;
	FILE *f = NULL;

	f = fopen(path, "wb");
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}

	if (fwrite(in_data, 1, in_size, f) != in_size) {
		retval = GT_IO_ERROR;
		if (!ferror(f)) {
			/* Should never happen (at least on regular files), use "I/O error"
			 * as error code in this case. */
			errno = EIO;
		}
		goto cleanup;
	}

	if (fclose(f)) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}
	f = NULL;

	retval = 0;

cleanup:

	if (f != NULL) {
		fclose(f);
	}

	return retval;
}

/**/

int GT_hashFile(const char *path, int hash_algorithm, GTDataHash **data_hash)
{
	int retval = GT_UNKNOWN_ERROR;
	GTDataHash *tmp_data_hash = NULL;
	FILE *f = NULL;
	unsigned char buf[32 * 1024];
	size_t read_size;

	retval = GTDataHash_open(hash_algorithm, &tmp_data_hash);
	if (retval != GT_OK) {
		goto cleanup;
	}

	f = fopen(path, "rb");
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}

	do {
		read_size = fread(buf, 1, sizeof(buf), f);
		if (ferror(f)) {
			retval = GT_IO_ERROR;
			goto cleanup;
		}
		retval = GTDataHash_add(tmp_data_hash, buf, read_size);
		if (retval != GT_OK) {
			goto cleanup;
		}
	} while (!feof(f));

	retval = GTDataHash_close(tmp_data_hash);
	if (retval != GT_OK) {
		goto cleanup;
	}

	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;

	retval = GT_OK;

cleanup:

	if (f != NULL) {
		fclose(f);
	}
	GTDataHash_free(tmp_data_hash);

	return retval;
}
