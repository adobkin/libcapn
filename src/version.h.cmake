/* 
 * Copyright (c) 2013, 2014 Anton Dobkin
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __APN_VERSION_H__
#define	__APN_VERSION_H__

/**
 * Library version as string
 * @ingroup version
 */
#define APN_VERSION_STRING "${CAPN_VERSION_MAJOR}.${CAPN_VERSION_MINOR}.${CAPN_VERSION_PATCH}"

/**
 * Major part of the library version
 * @ingroup version
 */
#define APN_VERSION_MAJOR  ${CAPN_VERSION_MAJOR}

/**
 * Minor part of the library version
 * @ingroup version
 */
#define APN_VERSION_MINOR  ${CAPN_VERSION_MINOR}

/**
 * Patch part of the library version
 * @ingroup version
 */
#define APN_VERSION_PATCH  ${CAPN_VERSION_PATCH}

/**
 * Library version as 3-byte hexadecimal.
 *
 * E.g. 0x010000 for version 1.0.0, 0x010100 for version 1.1.0
 * @ingroup version
 */
#define APN_VERSION_NUM  ((APN_VERSION_MAJOR  << 16) | (APN_VERSION_MINOR << 8) | (APN_VERSION_PATCH << 0))

#endif	/* __APN_VERSION_H__ */

