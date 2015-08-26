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
    APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12,
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

typedef enum __apn_log_levels {
    APN_LOG_LEVEL_INFO =  1 << 0,
    APN_LOG_LEVEL_ERROR = 1 << 1,
    APN_LOG_LEVEL_DEBUG = 1 << 2
} apn_log_levels;

typedef struct __apn_ctx apn_ctx;
typedef struct __apn_ctx *apn_ctx_ref;

typedef void (*invalid_token_cb)(const char * const token, uint32_t index);
typedef void (*log_cb)(apn_log_levels level, const char * const log_message, uint32_t message_len);

__apn_export__ apn_return apn_library_init()
        __apn_attribute_warn_unused_result__;

__apn_export__ void apn_library_free();

/**
 * Returns a 3-byte hexadecimal representation of the
 * library version.
 *
 * E.g. 0x010000 for version 1.0.0, 0x020000 for version 2.0.0
 * This is useful in numeric comparisons:
 *
 * @code {.c}
 * if(apn_version() <= 0x020000) {
 *      ...
 * }
 * @endcode
 *
 * @return hexadecimal
 */
__apn_export__ uint32_t apn_version();

/**
 * Returns a string representation of the
 * version library.
 *
 * E.g. "1.0.0", "2.0.0"
 *
 * @sa ::APN_VERSION_NUM
 * @sa ::APN_VERSION_STRING
 * @sa apn_version()
 *
 * @return string
 */
__apn_export__ const char *apn_version_string();

/**
* Creates a new connection context which is needed to hold the data for a connection to
* Apple Push Notification/Feedback Service.
*
* This function allocates memory for a connection context which should be freed - call ::apn_free() function
* for it.
*
* @sa apn_free()
* @return
*      - Pointer to new `::apn_ctx` structure on success
*      - NULL on failure with error information stored to `errno`
*/
__apn_export__ apn_ctx_ref apn_init()
        __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for a connection context.
 *
 * @param[in, out] ctx - Pointer to pointer to `::apn_ctx` structure
 *
 */
__apn_export__ void apn_free(apn_ctx_ref *ctx);

/**
 * Opens Apple Push Notification Service connection
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored in `errno`
 */
__apn_export__ apn_return apn_connect(const apn_ctx_ref ctx)
        __apn_attribute_warn_unused_result__;

/**
 * Closes Apple Push Notification/Feedback Service connection.
 *
 * @param[in] ctx - Pointer to an initialized `apn_ctx` structure
 */
__apn_export__ void apn_close(apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

/**
 * Sets connection mode.
 *
 * Each connection limited to one of two modes, each with its own assigned IP address:
 *
 * ::APN_MODE_PRODUCTION - Use the production mode when building the production version of the provider
 * application.  This mode uses gateway.push.apple.com, outbound TCP port 2195.
 *
 * ::APN_MODE_SANDBOX -  Use the sandbox mode for initial development and testing of the provider
 * application. It provides the same set of services as the production mode. The sandbox mode also acts
 * as a virtual device, enabling simulated end-to-end testing. This mode uses
 * gateway.sandbox.push.apple.com, outbound TCP port 2195.
 *
 * @attention You must get separate certificates for the sandbox mode and the production mode.
 *
 * Default mode is ::APN_MODE_PRODUCTION
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] mode -  Mode, must be ::APN_MODE_SANDBOX, or ::APN_MODE_PRODUCTION.
 *
 */
__apn_export__ void apn_set_mode(apn_ctx_ref ctx, apn_connection_mode mode)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_set_log_level(apn_ctx_ref ctx, uint16_t level)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_set_log_cb(apn_ctx_ref ctx, log_cb funct)
        __apn_attribute_nonnull__((1,2));

__apn_export__ void apn_set_invalid_token_cb(apn_ctx_ref ctx, invalid_token_cb funct)
        __apn_attribute_nonnull__((1,2));

/**
 * Sets path to an SSL certificate which will be used to establish secure connection
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] cert - Path to a SSL certificate file. Must be a valid NULL-terminated string
 * @param[in] key - Path to a private key file. Must be a valid NULL-terminated string
 * @param[in] pass - Private key passphrase. Can be NULL
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored in `errno`
 */
__apn_export__ apn_return apn_set_certificate(apn_ctx_ref ctx, const char *const cert, const char *const key, const char *const pass)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_set_pkcs12_file(apn_ctx_ref ctx, const char *const pkcs12_file, const char *const pass)
        __apn_attribute_nonnull__((1, 2,3));

/**
 * Returns the connection mode.
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @return ::APN_MODE_PRODUCTION or ::APN_MODE_SANDBOX
 */
__apn_export__ apn_connection_mode apn_mode(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ uint16_t apn_log_level(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

/**
 * Returns a path to an SSL certificate used to establish secure connection.
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @return Pointer to NULL-terminated string or NULL if certificate is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_certificate(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
* Returns a path to private key which used to establish secure connection
*
* @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
* @return Pointer to NULL-terminated string or NULL if private key is not set
*
* The returned value is read-only and must not be modified or freed
*/
__apn_export__ const char *apn_private_key(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a private key passphrase
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @return  Pointer to NULL-terminated string or null if passphrase is not set
 *
 *  The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_private_key_pass(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Sends push notification.
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] payload - Pointer to `::apn_payload_ctx` structure. Cannot be NULL
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored in `errno`
 */
__apn_export__ apn_return apn_send(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens, char **invalid_token)
        __apn_attribute_nonnull__((1,2,3));

__apn_export__ apn_return apn_send2(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens)
        __apn_attribute_nonnull__((1,2,3));

__apn_export__ apn_return apn_feedback(const apn_ctx_ref ctx, apn_array_ref *tokens)
        __apn_attribute_nonnull__((1, 2));

/**
 * Opens Apple Push Feedback Service connection
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored in `errno`
 */
__apn_export__ apn_return apn_feedback_connect(const apn_ctx_ref ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ char *apn_error_string(int err_code);

#ifdef __cplusplus
}
#endif

#endif
