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

#ifndef __APN_BINARY_MESSAGE_H__
#define __APN_BINARY_MESSAGE_H__

#include "apn_platform.h"
#include "apn_payload.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __apn_binary_message_t apn_binary_message_t;

__apn_export__ apn_binary_message_t *apn_create_binary_message(const apn_payload_t * const payload)
        __apn_attribute_warn_unused_result__
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_binary_message_set_token(apn_binary_message_t * const binary_message, const uint8_t * const token)
        __apn_attribute_nonnull__((1,2));

__apn_export__ void apn_binary_message_free(apn_binary_message_t *binary_message)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_binary_message_set_token_hex(apn_binary_message_t * const binary_message, const char * const token_hex)
        __apn_attribute_nonnull__((1,2));

__apn_export__ const char * apn_binary_message_token_hex(apn_binary_message_t * const binary_message)
        __apn_attribute_nonnull__((1));

#ifdef __cplusplus
}
#endif

#endif
