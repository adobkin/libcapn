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

#ifndef __APN_SSL_H__
#define __APN_SSL_H__

#include "apn_platform.h"
#include "apn.h"
#include <openssl/err.h>
#include <openssl/pkcs12.h>

void apn_ssl_init();
void apn_ssl_free();

apn_return apn_ssl_connect(apn_ctx_t *const ctx)
        __apn_attribute_nonnull__((1));

void apn_ssl_close(apn_ctx_t *const ctx)
        __apn_attribute_nonnull__((1));

int apn_ssl_write(const apn_ctx_t *const ctx, const uint8_t *message, size_t length)
        __apn_attribute_nonnull__((1,2));

int apn_ssl_read(const apn_ctx_t *const ctx, char *buff, size_t length)
        __apn_attribute_nonnull__((1,2));

#endif
