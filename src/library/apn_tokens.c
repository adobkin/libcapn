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

#include "apn_tokens.h"
#include "apn_strings.h"

#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

uint8_t *apn_token_hex_to_binary(const char *const token) {
	assert(token);

    uint8_t *binary_token = malloc(APN_TOKEN_BINARY_SIZE);
    if (!binary_token) {
        errno = ENOMEM;
        return NULL;
    }
    memset(binary_token, 0, APN_TOKEN_BINARY_SIZE);

    uint16_t j = 0;
    uint16_t i = 0;
    for (; i < APN_TOKEN_BINARY_SIZE * 2; i += 2, j++) {
        char tmp[3] = {token[i], token[i + 1], '\0'};
        uint32_t tmp_binary = 0;
#ifdef _WIN32
        sscanf_s(tmp, "%x", &tmp_binary);
#else
        sscanf(tmp, "%x", &tmp_binary);
#endif
        binary_token[j] = (uint8_t) tmp_binary;
    }
    return binary_token;
}

char *apn_token_binary_to_hex(const uint8_t *const binary_token) {
    assert(binary_token);

    uint32_t token_size = (APN_TOKEN_BINARY_SIZE * 2) + 1;
    char *token = malloc(token_size);
    if (!token) {
        errno = ENOMEM;
        return NULL;
    }
    char *p = token;

    uint16_t i = 0;
    for (; i < APN_TOKEN_BINARY_SIZE; i++) {
#ifdef _WIN32
        _snprintf_s(p, token_size, 3, "%2.2hhX", (unsigned char) binary_token[i]);
#else
        snprintf(p, 3, "%2.2hhX", (uint8_t) binary_token[i]);
#endif
        p += 2;
    }
    return token;
}

uint8_t apn_hex_token_is_valid(const char *const token) {
	assert(token);

    char *p = (char *) token;
    size_t token_length = strlen(token);
    if(token_length < APN_TOKEN_LENGTH || token_length > APN_TOKEN_LENGTH) {
        return 0;
    }
    while (*p != '\0') {
        if (!isxdigit(*p)) {
            return 0;
        }
        p++;
    }
    return 1;
}
