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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

#include "apn_strings.h"

static int _apn_seq_octets(uint8_t ch);

char *apn_strndup(const char *str, size_t len) {
    char *str_copy = NULL;
    char *p = NULL;
    size_t str_copy_len = 0;
	
	assert(str && len > 0);

    str_copy_len = len + 1;
    str_copy = malloc(str_copy_len * sizeof(char));
    p = str_copy;

    if(!str_copy) {
        return NULL;
    }
    while (--str_copy_len != 0) {
        if ((*p++ = *str++) == '\0') {
            return str_copy;
        }
    }
    *p = '\0';
    return str_copy;
}

static int _apn_seq_octets(uint8_t ch) {
    if ((ch >> 7) == 0x0) {
        return 1;
    } else if ((ch >> 5) == 0x6) {
        return 2;
    } else if ((ch >> 4) == 0xE) {
        return 3;
    } else if ((ch >> 3) == 0x1E) {
        return 4;
    }
    return -1;
}

uint8_t apn_string_is_utf8(const char *str) {
    uint8_t ch = 0;
    uint8_t j = 0;
    int s_octets = 0;
    size_t i = 0;
    size_t str_len = 0;
	
	assert(str);

    str_len = strlen(str);

    for(i = 0; i < str_len; ){
	    ch = (uint8_t) str[i];
	    s_octets = _apn_seq_octets(ch);
        if(s_octets == -1) {
            return 0;
        }
        for(j = 1; j < s_octets; j++) {
            ch = (uint8_t) str[i+j];
            if(ch < 0x80 || ch > 0xFB) {
                return 0;
            }
        }
        i += (size_t)s_octets;
    }

    return 1;
}

void apn_strfree(char **str) {
    if (*str != NULL) {
	    free(*str);
        *str = NULL;
    }
}

int apn_snprintf(char * s, size_t n, const char * format, ...) {
    va_list args;
    int ret = 0;
	
	assert(s);
    assert(format);

    va_start(args, format);
#ifdef _WIN32
    ret = vsnprintf_s(s, n, _TRUNCATE, format, args);
#else
    ret = vsnprintf(s, n, format, args);
#endif

    va_end(args);
    return ret;
}

void apn_strncpy(char *dst, const char * const src, size_t dst_len, size_t src_len) {
    size_t tmp_src_len = 0;
    char *buff = dst;
    const char *s = src;
	
	assert(dst);
    assert(src);

    if (dst_len == 0) {
        return;
    }
    if (src_len == 0) {
        *buff = '\0';
        return;
    }

    if (dst_len <= src_len) {
        tmp_src_len = dst_len - 1;
    } else {
        tmp_src_len = src_len;
    }
    if (tmp_src_len > 0) {
        while (tmp_src_len-- != 0) {
            if ((*buff++ = *s++) == '\0') {
                return;
            }
        }
    }
    *buff = '\0';
}
