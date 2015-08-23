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

#ifndef __APN_H__
#define __APN_H__

#include <openssl/ssl.h>
#include "apn_platform.h"
#include "apn_payload.h"
#include "apn_binary_message.h"
#include "apn_array.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum __apn_connection_mode {
    APN_MODE_PRODUCTION = 0,
    APN_MODE_SANDBOX = 1
} apn_connection_mode;

typedef enum __apn_errors {
    APN_ERR_FAILED_INIT = 9000,
    APN_ERR_NOT_CONNECTED,
    APN_ERR_NOT_CONNECTED_FEEDBACK,
    APN_ERR_CONNECTION_CLOSED,
    APN_ERR_CONNECTION_TIMEDOUT,
    APN_ERR_NETWORK_UNREACHABLE,
    APN_ERR_TOKEN_INVALID,
    APN_ERR_TOKEN_TOO_MANY,
    APN_ERR_CERTIFICATE_IS_NOT_SET,
    APN_ERR_PRIVATE_KEY_IS_NOT_SET,
    APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE,
    APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY,
    APN_ERR_COULD_NOT_INITIALIZE_CONNECTION,
    APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION,
    APN_ERR_SSL_WRITE_FAILED,
    APN_ERR_SSL_READ_FAILED,
    APN_ERR_INVALID_PAYLOAD_SIZE,
    APN_ERR_PAYLOAD_BADGE_INVALID_VALUE,
    APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED,
    APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT,
    APN_ERR_PAYLOAD_ALERT_IS_NOT_SET,
    APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS,
    APN_ERR_PROCESSING_ERROR,
    APN_ERR_SERVICE_SHUTDOWN,
    APN_ERR_UNKNOWN
} apn_errors;

typedef enum __apn_log_level {
    APN_LOG_LEVEL_INFO =  1 << 0,
    APN_LOG_LEVEL_ERROR = 1 << 1,
    APN_LOG_LEVEL_DEBUG = 1 << 2
} apn_log_level;

typedef struct __apn_ctx apn_ctx;
typedef struct __apn_ctx *apn_ctx_ref;

typedef void (*invalid_token_cb)(const char * const token);
typedef void (*log_cb)(apn_log_level level, const char * const log_message, uint32_t message_len);

__apn_export__ apn_return apn_library_init()
        __apn_attribute_warn_unused_result__;

__apn_export__ void apn_library_free();

__apn_export__ uint32_t apn_version();

__apn_export__ const char *apn_version_string();

__apn_export__ apn_ctx_ref apn_init(const char *const cert, const char *const private_key, const char *const private_key_pass)
        __apn_attribute_warn_unused_result__;

__apn_export__ void apn_free(apn_ctx_ref *ctx);

__apn_export__ apn_return apn_connect(const apn_ctx_ref ctx)
        __apn_attribute_warn_unused_result__;

__apn_export__ void apn_close(apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_set_mode(apn_ctx_ref ctx, apn_connection_mode mode)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_set_log_cb(apn_ctx_ref ctx, log_cb funct)
        __apn_attribute_nonnull__((1,2));

__apn_export__ void apn_set_invalid_token_cb(apn_ctx_ref ctx, invalid_token_cb funct)
        __apn_attribute_nonnull__((1,2));

__apn_export__ apn_return apn_set_certificate(apn_ctx_ref ctx, const char *const cert)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_set_private_key(apn_ctx_ref ctx, const char *const key, const char *const pass)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_add_token(apn_ctx_ref ctx, const char *const token)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ void apn_remove_all_tokens(apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_connection_mode apn_mode(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ const char *apn_certificate(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_private_key(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_private_key_pass(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ apn_return apn_send(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens, char **invalid_token)
        __apn_attribute_nonnull__((1,2,3));

__apn_export__ apn_return apn_send2(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens)
        __apn_attribute_nonnull__((1,2,3));

__apn_export__ apn_return apn_feedback(const apn_ctx_ref ctx, apn_array_ref *tokens)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_feedback_connect(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ char *apn_error_string(int err_code);

#ifdef __cplusplus
}
#endif

#endif
