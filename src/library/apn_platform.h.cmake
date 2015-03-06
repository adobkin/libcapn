/* 
 * Copyright (c) 2013, 2014, 2015 Anton Dobkin
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

#ifndef __APN_PLATFORM_H__
#define __APN_PLATFORM_H__

#ifndef HAVE_UNISTD_H
#cmakedefine HAVE_UNISTD_H
#endif
#ifndef HAVE_INTTYPES_H
#cmakedefine HAVE_INTTYPES_H
#endif
#ifndef HAVE_STDINT_H
#cmakedefine HAVE_STDINT_H
#endif
#ifndef HAVE_NETINET_IN_H
#cmakedefine HAVE_NETINET_IN_H
#endif
#ifndef HAVE_ARPA_INET_H
#cmakedefine HAVE_ARPA_INET_H
#endif
#ifndef HAVE_NETDB_H
#cmakedefine HAVE_NETDB_H
#endif
#ifndef HAVE_CTYPE_H
#cmakedefine HAVE_CTYPE_H
#endif
#ifndef HAVE_SYS_FCNTL_H
#cmakedefine HAVE_SYS_FCNTL_H
#endif
#ifndef HAVE_STRINGS_H
#cmakedefine HAVE_STRINGS_H
#endif

#cmakedefine HAVE_STRERROR_R
#cmakedefine HAVE_GLIBC_STRERROR_R
#cmakedefine HAVE_POSIX_STRERROR_R

typedef enum __apn_return {
    APN_SUCCESS,
    APN_ERROR
} apn_return;

#ifdef _WIN32
	#define __apn_export__ __declspec(dllexport)
	#define __apn_attribute_nonnull__(i)
	#define __apn_attribute_warn_unused_result__

	#include <winsock2.h>

	#define CLOSE_SOCKET(__socket) closesocket(__socket)
	#ifndef ETIMEDOUT
		#define ETIMEDOUT WSAETIMEDOUT
	#endif
#else 
	#if defined (__clang__) 
		#define __apn_export__ __attribute__ ((visibility("default")))
		#define __apn_attribute_nonnull__(i)  __attribute__((nonnull i))
		#define __apn_attribute_warn_unused_result__  __attribute__((warn_unused_result))
	#else
		#define __apn_attribute_nonnull__(i)  __attribute__((nonnull i))
		#define __apn_attribute_warn_unused_result__  __attribute__((warn_unused_result))
		#define __apn_export__ __attribute__ ((visibility("default")))
	#endif
	#define CLOSE_SOCKET(__socket) close(__socket)
	typedef int SOCKET;
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include <limits.h>

#if defined(HAVE_STDINT_H)
	#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
	#include <inttypes.h>
#elif defined(_MSC_VER)
	#if (_MSC_VER < 1300)
		typedef unsigned char     uint8_t;
		typedef unsigned short    uint16_t;
		typedef unsigned int      uint32_t;
		typedef signed   char     int8_t;
	#else
		typedef signed __int8     int8_t;
		typedef unsigned __int8   uint8_t;
		typedef unsigned __int16  uint16_t;
		typedef unsigned __int32  uint32_t;
	#endif
	#define UINT16_MAX   _UI16_MAX
	#define UINT32_MAX   _UI32_MAX
		typedef unsigned    __int64     uint64_t;
		typedef signed      __int64     int64_t;
		typedef signed      __int32     int32_t;
	#endif

#endif

