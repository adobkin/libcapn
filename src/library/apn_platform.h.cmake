/*
 * Copyright (c) 2013-2015 Anton Dobkin <anton.dobkin@gmail.com>
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

#cmakedefine APN_HAVE_UNISTD_H
#cmakedefine APN_HAVE_INTTYPES_H
#cmakedefine APN_HAVE_STDINT_H
#cmakedefine APN_HAVE_NETINET_IN_H
#cmakedefine APN_HAVE_ARPA_INET_H
#cmakedefine APN_HAVE_NETDB_H
#cmakedefine APN_HAVE_CTYPE_H
#cmakedefine APN_HAVE_FCNTL_H
#cmakedefine APN_HAVE_STRINGS_H
#cmakedefine APN_HAVE_NETINET_IN_H
#cmakedefine APN_HAVE_SYS_SOCKET_H

#cmakedefine APN_HAVE_STRERROR_R
#cmakedefine APN_HAVE_GLIBC_STRERROR_R
#cmakedefine APN_HAVE_POSIX_STRERROR_R

typedef enum __apn_return {
    APN_SUCCESS,
    APN_ERROR
} apn_return;

#ifdef _WIN32
	#define __apn_export__ __declspec(dllexport)
	#define __apn_attribute_nonnull__(i)
	#define __apn_attribute_warn_unused_result__

	#include <winsock2.h>
	#include <windows.h>
    #include <ws2tcpip.h>

    #define SHUT_RDWR SD_BOTH
	#ifndef ETIMEDOUT
		#define ETIMEDOUT WSAETIMEDOUT
	#endif

	#define APN_CLOSE_SOCKET(__socket) closesocket(__socket)
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
	#define APN_CLOSE_SOCKET(__socket) close(__socket)
	typedef int SOCKET;
#endif

#ifdef APN_HAVE_MALLOC_H
#include <malloc.h>
#endif

#include <limits.h>

#if defined(APN_HAVE_STDINT_H)
	#include <stdint.h>
#elif defined(APN_HAVE_INTTYPES_H)
	#include <inttypes.h>
#endif

#endif

