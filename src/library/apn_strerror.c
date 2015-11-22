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

#include <errno.h>
#include "apn_strerror.h"

#ifdef APN_HAVE_STRERROR_R
#if(!defined(HAVE_POSIX_STRERROR_R) && !defined(HAVE_GLIBC_STRERROR_R) || defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R))
#    error "strerror_r MUST be either POSIX, glibc or vxworks-style"
#  endif
#endif

void apn_strerror(int errnum, char *buf, size_t buff_size) {
#ifdef _WIN32
    if (strerror_s(buf, buff_size, errnum) != 0) {
        if (buf[0] == '\0') {
            apn_snprintf(buf, buff_size, "Error code %d", errnum);
        }
    }
#elif defined(APN_HAVE_STRERROR_R) && defined(APN_HAVE_POSIX_STRERROR_R)
    if (0 != strerror_r(errnum, buf, buff_size)) {
        if (buf[0] == '\0') {
            apn_snprintf(buf, buff_size, "Error code %d", errnum);
        }
    }
#elif defined(APN_HAVE_STRERROR_R) && defined(APN_HAVE_GLIBC_STRERROR_R)
    char tmp_buff[256];
    char *str_error = strerror_r(errnum, tmp_buff, sizeof(tmp_buff));
    if(str_error) {
        apn_strncpy(buf, str_error, buff_size, strlen(str_error));
    } else {
        apn_snprintf(buf, buff_size, "Error code %d", errnum);
    }
#else
    char *str_error = strerror(errnum);
    if (str_error) {
        apn_strncpy(buf, str_error, buff_size, strlen(str_error));
    } else {
        apn_snprintf(buf, buff_size, "Error code %d", errnum);
    }
#endif
}
