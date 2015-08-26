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

#ifndef __APN_TOKENS_H__
#define __APN_TOKENS_H__

#include "apn_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APN_TOKEN_BINARY_SIZE 32
#define APN_TOKEN_LENGTH 64

uint8_t * apn_token_hex_to_binary(const char * const token)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

char * apn_token_binary_to_hex(const uint8_t * const binary_token)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

uint8_t apn_hex_token_is_valid(const char * const token)
        __apn_attribute_nonnull__((1));

#ifdef __cplusplus
}
#endif

#endif
