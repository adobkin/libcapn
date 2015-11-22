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
#include <errno.h>

#include "apn_strings.h"

static int _apn_seq_octets(uint8_t ch);

char *apn_strndup(const char *str, size_t len) {
    char *str_copy = NULL;
    char *p = NULL;
    size_t str_copy_len = 0;
	
	assert(str);

    str_copy_len = len + 1;
    str_copy = malloc(str_copy_len * sizeof(char));
    p = str_copy;

    if(!str_copy) {
        errno = ENOMEM;
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

void apn_substr(char *dst, const char *src, size_t dst_size, size_t start, size_t stop) {
    assert(src);
    assert(dst);
    if (dst_size == 0) {
        return;
    }
    size_t count = stop - start;
    if (count >= (dst_size - 1)) {
        count = dst_size;
    }
    apn_strncpy(dst, src + start, dst_size, count);
}

void apn_strncpy(char *dst, const char * const src, size_t dst_size, size_t src_size) {
	assert(dst);
    assert(src);

    if (dst_size == 0) {
        return;
    }

    char *buff = dst;

    if (src_size == 0) {
        *buff = '\0';
        return;
    }
    size_t tmp_src_size = 0;
    if (dst_size <= src_size) {
        tmp_src_size = src_size - 1;
    } else {
        tmp_src_size = src_size;
    }
    if (tmp_src_size > 0) {
        const char *s = src;
        while (tmp_src_size-- != 0) {
            if ((*buff++ = *s++) == '\0') {
                return;
            }
        }
    }
    *buff = '\0';
}

void apn_strcat(char * dst, const char *src, size_t dst_size, size_t src_size) {
    assert(dst);
    assert(src);
    if (dst_size == 0) {
        return;
    }
    char *buff = dst;
    while (*buff != '\0') {
        buff++;
    }
    size_t size = dst_size - (buff - dst);
    apn_strncpy(buff, src, size, src_size);
}

static void __apn_str_dtor(char *const token) {
    free(token);
}

apn_array_t * apn_strsplit(char * const string, const char * const delim) {
    assert(string);
    assert(delim);
    apn_array_t *array = apn_array_init(10, (apn_array_dtor)__apn_str_dtor, NULL);
    if(array) {
        char *token = NULL;
#ifdef _WIN32
        char *context = NULL;
        token = strtok_s(string, delim, &context);
#else
        token = strtok(string, delim);
#endif
        while (token) {
            char *substr = apn_strndup(token, strlen(token));
            if(!substr) {
                apn_array_free(array);
                return NULL;
            }
            apn_array_insert(array, substr);
#ifdef _WIN32
            token = strtok_s(NULL, delim, &context);
#else
            token = strtok(NULL, delim);
#endif
        }
    }
    return array;
}

