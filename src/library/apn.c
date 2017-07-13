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

#include "apn_platform.h"

#include <errno.h>
#include <assert.h>

#include "apn_strings.h"
#include "apn_tokens.h"
#include "apn_version.h"
#include "apn_paload_private.h"
#include "apn_private.h"
#include "apn_binary_message_private.h"
#include "apn_array_private.h"
#include "apn_memory.h"
#include "apn_strerror.h"
#include "apn_log.h"
#include "apn_ssl.h"

#ifdef APN_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef APN_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef APN_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef APN_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef APN_HAVE_NETDB_H
#include <netdb.h>
#endif

typedef enum __apn_apple_errors {
    APN_APNS_ERR_PROCESSING_ERROR = 1,
    APN_APNS_ERR_MISSING_DEVICE_TOKEN,
    APN_APNS_ERR_MISSING_TOPIC,
    APN_APNS_ERR_MISSING_PAYLOAD,
    APN_APNS_ERR_INVALID_TOKEN_SIZE,
    APN_APNS_ERR_INVALID_TOPIC_SIZE,
    APN_APNS_ERR_INVALID_PAYLOAD_SIZE,
    APN_APNS_ERR_INVALID_TOKEN,
    APN_APNS_ERR_SERVICE_SHUTDOWN = 10,
    APN_APNS_ERR_NONE = 255
} apn_apple_errors;

struct __apn_apple_server {
    char *host;
    uint16_t port;
};

static struct __apn_apple_server __apn_apple_servers[4] = {
        {"gateway.sandbox.push.apple.com",  2195},
        {"gateway.push.apple.com",          2195},
        {"feedback.sandbox.push.apple.com", 2196},
        {"feedback.push.apple.com",         2196}
};

static apn_return __apn_send_binary_message(const apn_ctx_t *const ctx,
                                            apn_binary_message_t *const binary_message,
                                            apn_array_t *tokens,
                                            uint32_t token_index,
                                            uint8_t *apple_error_code,
                                            uint32_t *invalid_token_index);
static apn_return __apn_connect(apn_ctx_t *const ctx, struct __apn_apple_server server);
static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id);
static apn_binary_message_t *__apn_payload_to_binary_message(const apn_ctx_t *const ctx,
                                                             const apn_payload_t *const payload);
static int __apn_convert_apple_error(uint8_t apple_error_code);
static void __apn_invalid_token_dtor(char *const token);

apn_return apn_library_init() {
    static uint8_t library_initialized = 0;
    if (!library_initialized) {
        apn_ssl_init();
        library_initialized = 1;
#ifdef _WIN32
        WSADATA wsa_data;
        if(WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            errno = APN_ERR_FAILED_INIT;
            return APN_ERROR;
        }
#endif
    }
    return APN_SUCCESS;
}

void apn_library_free() {
    apn_ssl_free();
#ifdef _WIN32
    WSACleanup();
#endif
}

apn_ctx_t *apn_init() {
    apn_ctx_t *ctx = NULL;
    if (APN_ERROR == apn_library_init()) {
        return NULL;
    }
    ctx = malloc(sizeof(apn_ctx_t));
    if (!ctx) {
        errno = ENOMEM;
        return NULL;
    }
    ctx->sock = -1;
    ctx->ssl = NULL;
    ctx->certificate_file = NULL;
    ctx->private_key_file = NULL;
    ctx->pkcs12_file = NULL;
    ctx->pkcs12_pass = NULL;
    ctx->feedback = 0;
    ctx->private_key_pass = NULL;
    ctx->mode = APN_MODE_PRODUCTION;
    ctx->log_callback = NULL;
    ctx->log_level = APN_LOG_LEVEL_ERROR;
    ctx->invalid_token_callback = NULL;
    return ctx;
}

void apn_free(apn_ctx_t *ctx) {
    if (ctx) {
        apn_close(ctx);
        apn_mem_free(ctx->certificate_file);
        apn_mem_free(ctx->private_key_file);
        apn_mem_free(ctx->private_key_pass);
        apn_mem_free(ctx->pkcs12_file);
        apn_mem_free(ctx->pkcs12_pass);
        free(ctx);
    }
}

void apn_close(apn_ctx_t *const ctx) {
    assert(ctx);
    if(-1 == ctx->sock) {
        return;
    }
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection closing...");
    apn_ssl_close(ctx);
    APN_CLOSE_SOCKET(ctx->sock);
    ctx->sock = -1;
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection closed");
}

apn_return apn_set_certificate(apn_ctx_t *const ctx, const char *const cert, const char *const key,
                               const char *const pass) {
    assert(ctx);

    apn_strfree(&ctx->certificate_file);
    apn_strfree(&ctx->private_key_file);
    apn_strfree(&ctx->private_key_pass);

    if (cert && strlen(cert) > 0) {
        if (NULL == (ctx->certificate_file = apn_strndup(cert, strlen(cert)))) {
            return APN_ERROR;
        }
        if (key && strlen(key) > 0) {
            if (NULL == (ctx->private_key_file = apn_strndup(key, strlen(key)))) {
                return APN_ERROR;
            }
            if (pass && strlen(pass) > 0) {
                if (NULL == (ctx->private_key_pass = apn_strndup(pass, strlen(pass)))) {
                    return APN_ERROR;
                }
            }
        }
    }
    return APN_SUCCESS;
}

apn_return apn_set_pkcs12_file(apn_ctx_t *const ctx, const char *const pkcs12_file, const char *const pass) {
    assert(ctx);

    apn_strfree(&ctx->pkcs12_file);
    apn_strfree(&ctx->pkcs12_pass);

    if (pkcs12_file && strlen(pkcs12_file) > 0) {
        if (NULL == (ctx->pkcs12_file = apn_strndup(pkcs12_file, strlen(pkcs12_file)))) {
            return APN_ERROR;
        }
        assert(pass && strlen(pass) > 0);
        if (NULL == (ctx->pkcs12_pass = apn_strndup(pass, strlen(pass)))) {
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

void apn_set_mode(apn_ctx_t *const ctx, apn_connection_mode mode) {
    assert(ctx);
    if (mode == APN_MODE_SANDBOX) {
        ctx->mode = APN_MODE_SANDBOX;
    } else {
        ctx->mode = APN_MODE_PRODUCTION;
    }
}

void apn_set_behavior(apn_ctx_t * const ctx, uint32_t options) {
    assert(ctx);
    ctx->options = options;
}

void apn_set_log_level(apn_ctx_t *const ctx, uint16_t level) {
    assert(ctx);
    ctx->log_level = level;
}

void apn_set_log_callback(apn_ctx_t *const ctx, log_callback funct) {
    assert(ctx);
    ctx->log_callback = funct;
}

void apn_set_invalid_token_callback(apn_ctx_t *const ctx, invalid_token_callback funct) {
    assert(ctx);
    ctx->invalid_token_callback = funct;
}

apn_connection_mode apn_mode(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->mode;
}

uint16_t apn_log_level(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->log_level;
}

uint32_t apn_behavior(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->options;
}

const char *apn_certificate(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->certificate_file;
}

const char *apn_private_key(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->private_key_file;
}

const char *apn_private_key_pass(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->private_key_pass;
}

apn_return apn_connect(apn_ctx_t *const ctx) {
    struct __apn_apple_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_apple_servers[0];
    } else {
        server = __apn_apple_servers[1];
    }
    return __apn_connect(ctx, server);
}

#define __APN_CHECK_CONNECTION(__ctx) \
    if (!__ctx->ssl || __ctx->feedback) {\
        apn_log(__ctx, APN_LOG_LEVEL_ERROR, "Connection was not opened");\
        errno = APN_ERR_NOT_CONNECTED;\
        return APN_ERROR;\
    }


apn_return apn_send(apn_ctx_t *const ctx, const apn_payload_t *payload, apn_array_t *tokens,
                    apn_array_t **invalid_tokens) {
    assert(ctx);
    assert(payload);
    assert(tokens);
    assert(apn_array_count(tokens) > 0);

    __APN_CHECK_CONNECTION(ctx)

    apn_binary_message_t *binary_message = __apn_payload_to_binary_message(ctx, payload);
    if (!binary_message) {
        return APN_ERROR;
    }

    apn_log(ctx, APN_LOG_LEVEL_INFO, "Sending notification to %d device(s)...", apn_array_count(tokens));

    apn_array_t *_invalid_tokens = NULL;
    uint32_t start_index = 0;
    uint8_t auto_reconnect = 0;

    apn_return ret = APN_SUCCESS;

    for (;;) {
        if (1 == auto_reconnect) {
            apn_log(ctx, APN_LOG_LEVEL_INFO, "Reconnecting...");
            apn_close(ctx);
#ifndef _WIN32
    	    sleep(1);
#else
	    Sleep(1000);
#endif
            if (APN_ERROR == (ret = apn_connect(ctx))) {
                break;
            }
        }

        uint32_t invalid_token_index = 0;
        uint8_t apple_error_code = 0;
        ret = __apn_send_binary_message(ctx, binary_message, tokens, start_index, &apple_error_code,
                                        &invalid_token_index);
        if (ret == APN_SUCCESS) {
            break;
        } else {
            uint16_t errcode = apple_error_code > 0 ? __apn_convert_apple_error(apple_error_code) : errno;
            if (errcode == APN_ERR_TOKEN_INVALID) {
                const char *const invalid_token = (const char *const) apn_array_item_at_index(tokens,
                                                                                              invalid_token_index);
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Invalid token: %s (index: %u)", invalid_token,
                          invalid_token_index);
                if (invalid_tokens) {
                    if (!_invalid_tokens) {
                        if (NULL ==
                            (_invalid_tokens = apn_array_init(10, (apn_array_dtor) __apn_invalid_token_dtor, NULL))) {
                            apn_binary_message_free(binary_message);
                            return APN_ERROR;
                        }
                    }
                    apn_array_insert(_invalid_tokens, apn_strndup(invalid_token, APN_TOKEN_LENGTH));
                    if (ctx->invalid_token_callback) {
                        ctx->invalid_token_callback(invalid_token, invalid_token_index);
                    }
                }
            }

            char *error_string = apn_error_string(errcode);
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not send notification: %s (errno: %d)", error_string, errcode);
            apn_strfree(&error_string);

            start_index = (errcode == APN_ERR_TOKEN_INVALID) ? invalid_token_index + 1 : invalid_token_index;

            uint32_t options = apn_behavior(ctx);
            if (start_index < apn_array_count(tokens)) {
                if (options & APN_OPTION_RECONNECT &&
                    (errcode == APN_ERR_CONNECTION_CLOSED
                     || errcode == APN_ERR_SERVICE_SHUTDOWN
                     || errcode == APN_ERR_NETWORK_TIMEDOUT
                     || errcode == APN_ERR_NETWORK_UNREACHABLE
                     || (errcode == APN_ERR_TOKEN_INVALID))) {
                    auto_reconnect = 1;
                    continue;
                }
            } else if (errcode == APN_ERR_TOKEN_INVALID) {
                errno = 0;
                ret = APN_SUCCESS;
                break;
            } else {
                errno = errcode;
                break;
            }
        }
    }

    apn_binary_message_free(binary_message);
    if (invalid_tokens && _invalid_tokens) {
        *invalid_tokens = _invalid_tokens;
    }
    return ret;
}

apn_return apn_feedback_connect(apn_ctx_t *const ctx) {
    struct __apn_apple_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_apple_servers[2];
    } else {
        server = __apn_apple_servers[3];
    }
    ctx->feedback = 1;
    return __apn_connect(ctx, server);
}

apn_return apn_feedback(const apn_ctx_t *const ctx, apn_array_t **tokens) {
    assert(ctx);
    assert(tokens);

    fd_set read_set;
    struct timeval timeout = {3, 0};

    if (!ctx->ssl || ctx->feedback) {
        errno = APN_ERR_NOT_CONNECTED;
        return APN_ERROR;
    }

    *tokens = apn_array_init(10, (apn_array_dtor)__apn_invalid_token_dtor, NULL);
    if (!*tokens) {
        return APN_ERROR;
    }

    for (; ;) {
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &read_set);

        int select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
        if (select_returned < 0) {
            if (errno == EINTR) {
                continue;
            }
            return APN_ERROR;
        }

        if (select_returned == 0) {
            /* select() timed out */
            break;
        }

        if (FD_ISSET(ctx->sock, &read_set)) {
            char buffer[38];
            int bytes_read = apn_ssl_read(ctx, buffer, sizeof(buffer));
            if (bytes_read < 0) {
                return APN_ERROR;
            } else if (bytes_read > 0) {
                char *buffer_ref = buffer;
                uint16_t token_length = 0;
                uint8_t binary_token[APN_TOKEN_BINARY_SIZE];

                buffer_ref += sizeof(uint32_t);
                memcpy(&token_length, buffer_ref, sizeof(token_length));
                buffer_ref += sizeof(token_length);
                token_length = ntohs(token_length);
                memcpy(&binary_token, buffer_ref, sizeof(binary_token));
                char *token_hex = apn_token_binary_to_hex(binary_token);
                if (NULL == token_hex) {
                    apn_array_free(*tokens);
                    return APN_ERROR;
                }
                apn_array_insert(*tokens, token_hex);
            }
            break;
        }
    }

    return APN_SUCCESS;
}

uint32_t apn_version() {
    return APN_VERSION_NUM;
}

const char *apn_version_string() {
    return APN_VERSION_STRING;
}

char *apn_error_string(int errnum) {
    char error[250] = {0};
    switch (errnum) {
        case APN_ERR_FAILED_INIT:
            apn_snprintf(error, sizeof(error) - 1, "unable to initialize library");
            break;
        case APN_ERR_NOT_CONNECTED:
            apn_snprintf(error, sizeof(error) - 1, "no opened connection to Apple Push Notification Service");
            break;
        case APN_ERR_NOT_CONNECTED_FEEDBACK:
            apn_snprintf(error, sizeof(error) - 1, "no opened connection to Apple Feedback Service");
            break;
        case APN_ERR_CONNECTION_CLOSED:
            apn_snprintf(error, sizeof(error) - 1, "connection was closed");
            break;
        case APN_ERR_NETWORK_TIMEDOUT:
            apn_snprintf(error, sizeof(error) - 1, "connection timed out");
            break;
        case APN_ERR_NETWORK_UNREACHABLE:
            apn_snprintf(error, sizeof(error) - 1, "network unreachable");
            break;
        case APN_ERR_TOKEN_INVALID:
            apn_snprintf(error, sizeof(error) - 1, "invalid device token");
            break;
        case APN_ERR_TOKEN_TOO_MANY:
            apn_snprintf(error, sizeof(error) - 1, "too many device tokens");
            break;
        case APN_ERR_CERTIFICATE_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1, "certificate is not set");
            break;
        case APN_ERR_PRIVATE_KEY_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1, "private key is not set");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified certificate");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified private key");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified PKCS12 file");
            break;
        case APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "unable to establish connection");
            break;
        case APN_ERR_UNABLE_TO_ESTABLISH_SSL_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "unable to establish ssl connection");
            break;
        case APN_ERR_SSL_WRITE_FAILED:
            apn_snprintf(error, sizeof(error) - 1, "SSL_write failed");
            break;
        case APN_ERR_SSL_READ_FAILED:
            apn_snprintf(error, sizeof(error) - 1, "SSL_read failed");
            break;
        case APN_ERR_INVALID_PAYLOAD_SIZE:
            apn_snprintf(error, sizeof(error) - 1, "invalid notification payload size");
            break;
        case APN_ERR_PAYLOAD_BADGE_INVALID_VALUE:
            apn_snprintf(error, sizeof(error) - 1, "incorrect number to display as the badge on application icon");
            break;
        case APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED:
            apn_snprintf(error, sizeof(error) - 1, "specified custom property name is already used");
            break;
        case APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT:
            apn_snprintf(error, sizeof(error) - 1, "could not create json document");
            break;
        case APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS:
            apn_snprintf(error, sizeof(error) - 1, "non-UTF8 symbols detected in a string");
            break;
        case APN_ERR_PROCESSING_ERROR:
            apn_snprintf(error, sizeof(error) - 1, "processing error");
            break;
        case APN_ERR_SERVICE_SHUTDOWN:
            apn_snprintf(error, sizeof(error) - 1, "server closed the connection (service shutdown)");
            break;
        case APN_ERR_PAYLOAD_ALERT_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1,
                         "alert message text or key used to get a localized alert-message string or content-available flag must be set");
            break;
        default:
            apn_strerror(errnum, error, sizeof(error) - 1);
            break;
    }
    return apn_strndup(error, sizeof(error));
}

static apn_return __apn_connect(apn_ctx_t *const ctx, struct __apn_apple_server server) {
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connecting to %s:%d...", server.host, server.port);

    if (!ctx->pkcs12_file) {
        if (!ctx->certificate_file) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Certificate file not set (errno: %d)", APN_ERR_CERTIFICATE_IS_NOT_SET);
            errno = APN_ERR_CERTIFICATE_IS_NOT_SET;
            return APN_ERROR;
        }
        if (!ctx->private_key_file) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Private key file not set (errno: %d)", APN_ERR_PRIVATE_KEY_IS_NOT_SET);
            errno = APN_ERR_PRIVATE_KEY_IS_NOT_SET;
            return APN_ERROR;
        }
    }

    if (ctx->sock == -1) {
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Resolving server hostname...");

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        char str_port[6];
        apn_snprintf(str_port, sizeof(str_port) - 1, "%d", server.port);

        struct addrinfo *addrinfo = NULL;
        if (0 != getaddrinfo(server.host, str_port, &hints, &addrinfo)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to resolve hostname: getaddrinfo() failed");
            errno  = APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION;
            return APN_ERROR;
        }

        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Creating socket...");

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            char *error = apn_error_string(errno);
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to create socket: socket() failed: %s (errno: %d)", error,
                      errno);
            free(error);
            return APN_ERROR;
        }
	    
        ctx->sock = sock;

#ifndef _WIN32
        int sock_flags = fcntl(ctx->sock, F_GETFL, 0);
        fcntl(ctx->sock, F_SETFL, sock_flags | O_NONBLOCK);
#else
        int sock_flags = 1;
        ioctlsocket(ctx->sock, FIONBIO, (u_long *) &sock_flags);
#endif
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Socket successfully created");

        uint8_t connected = 0;
        while (addrinfo) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (void *) &((struct sockaddr_in *) addrinfo->ai_addr)->sin_addr, ip, sizeof(ip));
            apn_log(ctx, APN_LOG_LEVEL_INFO, "Trying to connect to %s...", ip);
            if (connect(ctx->sock, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
                char *error = apn_error_string(errno);
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not to connect to: %s (errno: %d)", error, errno);
                free(error);
            } else {
                connected = 1;
                break;
            }
            addrinfo = addrinfo->ai_next;
        }

        freeaddrinfo(addrinfo);
	    
        if (!connected) {
            errno = APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION;
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to establish connection");
            apn_close(ctx);
            return APN_ERROR;
        }

        apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection has been established");
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Initializing SSL connection...");

        return apn_ssl_connect(ctx);
    }
    return APN_SUCCESS;
}

static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id) {
    uint8_t cmd = 0;
    memcpy(&cmd, apns_error, sizeof(uint8_t));
    apns_error += sizeof(uint8_t);
    if (8 == cmd) {
        uint8_t error_code = 0;
        memcpy(&error_code, apns_error, sizeof(uint8_t));
        apns_error += sizeof(uint8_t);
        if (apns_error_code) {
            *apns_error_code = error_code;
        }
        if (APN_APNS_ERR_INVALID_TOKEN == error_code && id) {
            uint32_t token_id = 0;
            memcpy(&token_id, apns_error, sizeof(uint32_t));
            *id = ntohl(token_id);
        }
    }
}

#define APN_MACRO_BREAK1 break;
#define APN_MACRO_BREAK0
#define APN_LOOP_BREAK(__loop) APN_MACRO_BREAK##__loop

#define __API_SOCKET_READ(__ctx, __read_set, __buffer, __apple_error_flag, __loop, __current_tix, __invalid_tix) \
    __apple_error_flag = 0; \
    if (FD_ISSET(__ctx->sock, __read_set)) { \
        apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "Socket has data for read"); \
        apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "Reading data from a socket..."); \
        int __bytes_read = apn_ssl_read(__ctx, __buffer, sizeof(__buffer)); \
        if (0 < __bytes_read) { \
            apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "%d byte(s) has been read from a socket", __bytes_read); \
            __apple_error_flag = 1; \
            APN_LOOP_BREAK(__loop) \
        } else { \
            char *__error_str = apn_error_string(errno); \
            apn_log(__ctx, APN_LOG_LEVEL_ERROR, "Unable to read data from a socket: %s (errno: %d)", __error_str, errno); \
            free(__error_str); \
            if(__invalid_tix) {\
                *__invalid_tix = __current_tix;\
            }\
            return APN_ERROR; \
        } \
    }

#define __APN_SELECT_ERROR(__returned_code) \
    if(__returned_code < 0) { \
        char *__error_str = apn_error_string(errno); \
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "select() failed: %s (errno: %d)", __error_str, errno); \
        free(__error_str); \
        return APN_ERROR;\
    }

static apn_return __apn_send_binary_message(const apn_ctx_t *const ctx,
                                            apn_binary_message_t *const binary_message,
                                            apn_array_t *tokens,
                                            uint32_t token_start_index,
                                            uint8_t *apple_error_code,
                                            uint32_t *invalid_token_index) {

    assert(token_start_index < apn_array_count(tokens));

    fd_set write_set, read_set;
    struct timeval timeout = {10, 0};
    uint8_t apple_returned_error = 0;
    int select_returned = 0;
    char apple_error_str[6];

    uint32_t i = token_start_index;
    for (; i < apn_array_count(tokens); i++) {
        const char *token = (const char *) apn_array_item_at_index(tokens, i);
        apn_binary_message_set_id(binary_message, i);
        apn_binary_message_set_token_hex(binary_message, token);

        apn_log(ctx, APN_LOG_LEVEL_INFO, "Sending notificaton to device with token %s...", token);

        do {
            FD_ZERO(&write_set);
            FD_ZERO(&read_set);
            FD_SET(ctx->sock, &write_set);
            FD_SET(ctx->sock, &read_set);
            select_returned = select(ctx->sock + 1, &read_set, &write_set, NULL, &timeout);
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "select() returned %d", select_returned);
        } while (0 == select_returned || (0 > select_returned && EINTR == errno));

        __APN_SELECT_ERROR(select_returned)
        __API_SOCKET_READ(ctx, &read_set, apple_error_str, apple_returned_error, 1, i, invalid_token_index)

        if (FD_ISSET(ctx->sock, &write_set)) {
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Socket is ready for writing");
            int bytes_written = apn_ssl_write(ctx, binary_message->message, binary_message->size);
            if (0 >= bytes_written) {
                char *error = apn_error_string(errno);
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to write data to a socket: %s (errno: %d)", error, errno);
                free(error);
                return APN_ERROR;
            }
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "%d byte(s) has been written to a socket", bytes_written);
        }
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Notification has been sent");
    }

    if (!apple_returned_error) {
        timeout.tv_sec = 1;
        do {
            FD_ZERO(&read_set);
            FD_SET(ctx->sock, &read_set);
            select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "select() returned %d", select_returned);
        } while (0 > select_returned && EINTR == errno);

        __APN_SELECT_ERROR(select_returned)
        __API_SOCKET_READ(ctx, &read_set, apple_error_str, apple_returned_error, 0, i, invalid_token_index)
    }
    if (apple_returned_error) {
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Parsing Apple response...", *apple_error_code);
        __apn_parse_apns_error(apple_error_str, apple_error_code, invalid_token_index);
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "Apple returned error code %d", *apple_error_code);
        return APN_ERROR;
    }
    return APN_SUCCESS;
}

static apn_binary_message_t *__apn_payload_to_binary_message(const apn_ctx_t *const ctx,
                                                             const apn_payload_t *const payload) {
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Creating binary message from payload...");
    apn_binary_message_t *binary_message = apn_create_binary_message(payload);
    if (!binary_message) {
        char *error = apn_error_string(errno);
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to create binary message: %s (errno: %d)", error, errno);
        free(error);
        return NULL;
    }
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Binary message sucessfully created");
    return binary_message;
}

static int __apn_convert_apple_error(uint8_t apple_error_code) {
    if (apple_error_code > 0) {
        switch (apple_error_code) {
            case APN_APNS_ERR_PROCESSING_ERROR:
                return APN_ERR_PROCESSING_ERROR;
            case APN_APNS_ERR_INVALID_PAYLOAD_SIZE:
                return APN_ERR_INVALID_PAYLOAD_SIZE;
            case APN_APNS_ERR_SERVICE_SHUTDOWN:
                return APN_ERR_SERVICE_SHUTDOWN;
            case APN_APNS_ERR_INVALID_TOKEN:
            case APN_APNS_ERR_INVALID_TOKEN_SIZE:
                return APN_ERR_TOKEN_INVALID;
            default:
                return APN_ERR_UNKNOWN;
        }
    }
    return 0;
}

static void __apn_invalid_token_dtor(char *const token) {
    free(token);
}
