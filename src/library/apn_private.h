/*
 * Copyright (c) 2013, 2104, 2015 Anton Dobkin
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


#ifndef __APN_PRIVATE_H__
#define __APN_PRIVATE_H__

#include <stddef.h>
#include <time.h>
#include "apn_platform.h"
#include "apn.h"

#ifdef __cplusplus
extern "C" {
#endif

struct __apn_ctx {
    apn_log_level log_level;
    uint8_t feedback;
    apn_connection_mode mode;
    SOCKET sock;
    char *certificate_file;
    char *private_key_file;
    char *private_key_pass;
    char *pkcs12_file;
    char *pkcs12_pass;
    SSL *ssl;
    log_cb log_cb;
    invalid_token_cb invalid_token_cb;
};


#ifdef __cplusplus
}
#endif

#endif
