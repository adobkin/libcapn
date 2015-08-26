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

#ifndef __APN_BINARY_MESSSAGE_PRIVATE_H__
#define __APN_BINARY_MESSSAGE_PRIVATE_H__

#include "apn_platform.h"
#include "apn_binary_message.h"

#ifdef __cplusplus
extern "C" {
#endif

struct __apn_binary_message {
    uint32_t payload_size;
    uint32_t size;
    uint8_t *token_position;
    uint8_t *id_position;
    uint8_t *message;
    char *token_hex;
};

apn_binary_message_ref apn_binary_message_init(uint32_t size)
        __apn_attribute_warn_unused_result__;

void apn_binary_message_set_id(apn_binary_message_ref binary_message, uint32_t id)
        __apn_attribute_nonnull__((1));

#ifdef __cplusplus
}
#endif

#endif
