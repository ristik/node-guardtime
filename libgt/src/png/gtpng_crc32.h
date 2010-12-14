/*
 * $Id: gtpng_crc32.h 74 2010-02-22 11:42:26Z ahto.truu $
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

#ifndef GTPNG_CRC_H_INCLUDED
#define GTPNG_CRC_H_INCLUDED

#ifdef _WIN32
#ifndef UINT32_T_DEFINED
typedef unsigned __int32 uint32_t;
#define UINT32_T_DEFINED
#endif /* not UINT32_T_DEFINED */
#else /* _WIN32 */
#include <stdint.h>
#endif /* not _WIN32 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Calculates the PNG CRC32 checksum.
 *
 * \param buf \c (in) Pointer to the data.
 * \param len \c (in) Length of the data.
 * \return CRC32 of the data.
 */
uint32_t GTPNG_crc32(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* not GTPNG_CRC_H_INCLUDED */
