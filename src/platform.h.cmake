/* 
 * Copyright (c) 2013, Anton Dobkin
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
 
#ifndef HAVE_UNISTD_H
#cmakedefine HAVE_UNISTD_H
#endif
#ifndef HAVE_MALLOC_H
#cmakedefine HAVE_MALLOC_H
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
#ifndef HAVE_SYS_SOCKET_H
#cmakedefine HAVE_SYS_SOCKET_H
#endif
#ifndef HAVE_CTYPE_H
#cmakedefine HAVE_CTYPE_H
#endif

#if defined(__OpenBSD__)
#undef HAVE_MALLOC_H
#endif

#ifndef __APN_ATTRIBUTES_H__
#define	__APN_ATTRIBUTES_H__

#ifndef __GNUC_PREREQ
    #if defined __GNUC__ && defined __GNUC_MINOR__
        #define __GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
    #else
        #define __GNUC_PREREQ(maj, min) 0
    #endif
#endif

#ifdef WIN32
  #define __apn_export__ __declspec(dllexport)
#else 
  #if defined (__clang__) 
     #if __has_attribute(visibility)
         #define __apn_export__ __attribute__ ((visibility("default")))
     #endif
     #if __has_attribute(nonnull)
         #define __apn_attribute_nonnull__(i)  __attribute__((nonnull i))
     #endif
     #if __has_attribute(warn_unused_result) 
         #define __apn_attribute_warn_unused_result__  __attribute__((warn_unused_result))
     #endif
  #else
     #if __GNUC_PREREQ(3,3)
         #define __apn_attribute_nonnull__(i)  __attribute__((nonnull i))
     #endif
     #if __GNUC_PREREQ(3,4) 
         #define __apn_attribute_warn_unused_result__  __attribute__((warn_unused_result))
     #endif 
     #if __GNUC_PREREQ(4,0)
         #define __apn_export__ __attribute__ ((visibility("default")))
     #endif      
  #endif
#endif

#ifndef __apn_export__
#define __apn_export__
#endif

#ifndef __apn_attribute_nonnull__
#define __apn_attribute_nonnull__(i)
#endif

#ifndef __apn_attribute_warn_unused_result__
#define __apn_attribute_warn_unused_result__
#endif

#ifdef _WIN32
#include <winsock2.h>
#define CLOSE_SOCKET(__socket) closesocket(__socket)
#else
#define CLOSE_SOCKET(__socket) close(__socket)
#define WSACleanup()
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
#if _MSC_VER > 1000
#pragma once
#endif
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
typedef unsigned    int         uint;
#endif

#endif	/* __APN_ATTRIBUTES_H__ */

