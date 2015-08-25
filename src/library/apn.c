/*
* Copyright (c) 2013, 2014, 2015 Anton Dobkin
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

#include <errno.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include "apn_strings.h"
#include "apn_tokens.h"
#include "apn_version.h"
#include "apn_paload_private.h"
#include "apn_private.h"
#include "apn_binary_message_private.h"
#include "apn_array_private.h"

#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
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

static void __apn_log(apn_ctx_ref ctx, apn_log_levels level, const char *const message, ...);
static apn_return __apn_send_binary_message(const apn_ctx_ref ctx,
                                            const apn_binary_message_ref binary_message,
                                            apn_array_ref tokens,
                                            uint32_t token_index,
                                            uint8_t *apple_error_code,
                                            uint32_t *invalid_token_index);
static int __apn_password_cd(char *buf, int size, int rwflag, void *password);
static apn_return __apn_connect(const apn_ctx_ref ctx, struct __apn_apple_server server);
static int __ssl_write(const apn_ctx_ref ctx, const uint8_t *message, size_t length);
static int __ssl_read(const apn_ctx_ref ctx, char *buff, size_t length);
static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id);
static void __apn_strerror_r(int errnum, char *buf, size_t buff_size);
static apn_binary_message_ref __apn_payload_to_binary_message(const apn_ctx_ref ctx, const apn_payload_ref payload);
static void __apn_convert_apple_error(uint8_t apple_error_code);
static apn_return __apn_tls_connect(const apn_ctx_ref ctx);
static void __apn_ssl_info_callback(const SSL *ssl, int where, int ret);

apn_return apn_library_init() {
    static uint8_t library_initialized = 0;
#ifdef _WIN32
    WSADATA wsa_data;
#endif
    if (!library_initialized) {
        SSL_load_error_strings();
        SSL_library_init();
        library_initialized = 1;
#ifdef _WIN32
        if(WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            errno = APN_ERR_FAILED_INIT;
            return APN_ERROR;
        }
#endif
    }
    return APN_SUCCESS;
}

void apn_library_free() {
    ERR_free_strings();
    EVP_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
}

apn_ctx_ref apn_init() {
    apn_ctx_ref ctx = NULL;
    if (APN_ERROR == apn_library_init()) {
        return NULL;
    }
    ctx = malloc(sizeof(apn_ctx));
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
    ctx->log_cb = NULL;
    ctx->invalid_token_cb = NULL;
    ctx->log_level = APN_LOG_LEVEL_ERROR;
    return ctx;
}

void apn_free(apn_ctx_ref *ctx) {
    if (ctx && *ctx) {
        apn_close(*ctx);

        if ((*ctx)->certificate_file) {
            free((*ctx)->certificate_file);
        }
        if ((*ctx)->private_key_file) {
            free((*ctx)->private_key_file);
        }
        if ((*ctx)->private_key_pass) {
            free((*ctx)->private_key_pass);
        }
        if ((*ctx)->pkcs12_file) {
            free((*ctx)->pkcs12_file);
        }
        if ((*ctx)->pkcs12_pass) {
            free((*ctx)->pkcs12_pass);
        }
        free((*ctx));
        *ctx = NULL;
    }
}

void apn_close(apn_ctx_ref ctx) {
    assert(ctx);
    __apn_log(ctx, APN_LOG_LEVEL_INFO,  "Connection closing...");
    if (ctx->ssl) {
        SSL_shutdown(ctx->ssl);
        SSL_clear(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        shutdown(ctx->sock, SHUT_RDWR);
        APN_CLOSE_SOCKET(ctx->sock);
        ctx->sock = -1;
    }
    __apn_log(ctx, APN_LOG_LEVEL_INFO,  "Connection closed");
}

apn_return apn_set_certificate(apn_ctx_ref ctx, const char *const cert, const char *const key, const char *const pass) {
    assert(ctx);

    if (ctx->certificate_file) {
        apn_strfree(&ctx->certificate_file);
    }
    if (ctx->private_key_file) {
        apn_strfree(&ctx->private_key_file);
    }

    if (ctx->private_key_pass) {
        apn_strfree(&ctx->private_key_pass);
    }

    if (cert && strlen(cert) > 0) {
        if (NULL == (ctx->certificate_file = apn_strndup(cert, strlen(cert)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }

        if (key && strlen(key) > 0) {
            if (NULL == (ctx->private_key_file = apn_strndup(key, strlen(key)))) {
                errno = ENOMEM;
                return APN_ERROR;
            }

            if (pass && strlen(pass) > 0) {
                if (NULL == (ctx->private_key_pass = apn_strndup(pass, strlen(pass)))) {
                    errno = ENOMEM;
                    return APN_ERROR;
                }
            }
        }
    }
    return APN_SUCCESS;
}

apn_return apn_set_pkcs12_file(apn_ctx_ref ctx, const char *const pkcs12_file, const char *const pass) {
    assert(ctx);

    if (ctx->pkcs12_file) {
        apn_strfree(&ctx->pkcs12_file);
    }

    if (ctx->pkcs12_pass) {
        apn_strfree(&ctx->pkcs12_pass);
    }

    if (pkcs12_file && strlen(pkcs12_file) > 0) {
        if (NULL == (ctx->pkcs12_file = apn_strndup(pkcs12_file, strlen(pkcs12_file)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        assert(pass && strlen(pass) > 0);
        if (NULL == (ctx->pkcs12_pass = apn_strndup(pass, strlen(pass)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

void apn_set_mode(apn_ctx_ref ctx, apn_connection_mode mode) {
    assert(ctx);
    if (mode == APN_MODE_SANDBOX) {
        ctx->mode = APN_MODE_SANDBOX;
    } else {
        ctx->mode = APN_MODE_PRODUCTION;
    }
}

void apn_set_log_level(apn_ctx_ref ctx, uint16_t level) {
    assert(ctx);
    ctx->log_level = level;
}

void apn_set_log_cb(apn_ctx_ref ctx, log_cb funct) {
    assert(ctx);
    ctx->log_cb = funct;
}

void apn_set_invalid_token_cb(apn_ctx_ref ctx, invalid_token_cb funct) {
    assert(ctx);
    ctx->invalid_token_cb = funct;
}

apn_connection_mode apn_mode(const apn_ctx_ref ctx) {
    assert(ctx);
    return ctx->mode;
}

uint16_t apn_log_level(const apn_ctx_ref ctx) {
    return ctx->log_level;
}

const char *apn_certificate(const apn_ctx_ref ctx) {
    assert(ctx);
    return ctx->certificate_file;
}

const char *apn_private_key(const apn_ctx_ref ctx) {
    assert(ctx);
    return ctx->private_key_file;
}

const char *apn_private_key_pass(const apn_ctx_ref ctx) {
    assert(ctx);
    return ctx->private_key_pass;
}

apn_return apn_connect(const apn_ctx_ref ctx) {
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
        __apn_log(__ctx, APN_LOG_LEVEL_ERROR, "Connection was not opened");\
        errno = APN_ERR_NOT_CONNECTED;\
        return APN_ERROR;\
    }


apn_return apn_send2(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens) {
    apn_return ret;
    uint8_t apple_error_code = 0;
    uint32_t invalid_token_index = 0;
    apn_binary_message *binary_message = NULL;
    uint32_t index = 0;

    assert(ctx);
    assert(payload);
    assert(tokens && apn_array_count(tokens) > 0);

    __apn_log(ctx, APN_LOG_LEVEL_INFO, "Sending notification to %d device(s)...", apn_array_count(tokens));

    __APN_CHECK_CONNECTION(ctx)

    binary_message = __apn_payload_to_binary_message(ctx, payload);
    if(!binary_message){
        return APN_ERROR;
    }

    for(;;){
        ret = __apn_send_binary_message(ctx, binary_message, tokens, index, &apple_error_code, &invalid_token_index);
        if(ret == APN_SUCCESS) {
            break;
        } else {
            if (apple_error_code == APN_APNS_ERR_INVALID_TOKEN) {
                const char * const invalid_token = (const char * const) apn_array_item_at_index(tokens, invalid_token_index);
                __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Invalid token: %s (index: %u)", invalid_token, invalid_token_index);
                if(ctx->invalid_token_cb) {
                    ctx->invalid_token_cb(invalid_token, invalid_token_index);
                }
                __apn_log(ctx, APN_LOG_LEVEL_INFO, "Reconnecting...");
                apn_close(ctx);
                sleep(1);
                if(APN_ERROR == apn_connect(ctx)) {
                    ret = APN_ERROR;
                    break;
                }
                if((invalid_token_index + 1) < apn_array_count(tokens)) {
                    index = invalid_token_index + 1;
                } else {
                    break;
                }
            } else {
                __apn_convert_apple_error(apple_error_code);
                break;
            }
        }
    }

    apn_binary_message_free(binary_message);

    return ret;
}

apn_return apn_send(const apn_ctx_ref ctx, const apn_payload_ref payload, apn_array_ref tokens, char **invalid_token) {
    apn_binary_message *binary_message = NULL;
    apn_return ret;
    uint8_t apple_error_code = 0;
    uint32_t invalid_token_index = 0;

    assert(ctx);
    assert(payload);
    assert(tokens && apn_array_count(tokens) > 0);

    __apn_log(ctx, APN_LOG_LEVEL_INFO, "Sending notification to %d device(s)...", apn_array_count(tokens));

    __APN_CHECK_CONNECTION(ctx)

    binary_message = __apn_payload_to_binary_message(ctx, payload);
    if(!binary_message){
        return APN_ERROR;
    }

    ret = __apn_send_binary_message(ctx, binary_message, tokens, 0, &apple_error_code, &invalid_token_index);
    apn_binary_message_free(binary_message);

    if (ret == APN_ERROR) {
        if (apple_error_code == APN_APNS_ERR_INVALID_TOKEN) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Invalid token: %s (index: %u)",
                      (const char *) apn_array_item_at_index(tokens, invalid_token_index), invalid_token_index);
            if (invalid_token) {
                *invalid_token = (char *) apn_array_item_at_index(tokens, invalid_token_index);
            }
        }
        __apn_convert_apple_error(apple_error_code);
    }

    return ret;
}

apn_return apn_feedback_connect(const apn_ctx_ref ctx) {
    struct __apn_apple_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_apple_servers[2];
    } else {
        server = __apn_apple_servers[3];
    }
    ctx->feedback = 1;
    return __apn_connect(ctx, server);
}

apn_return apn_feedback(const apn_ctx_ref ctx, apn_array_ref *tokens) {
    char buffer[38]; /* Buffer to read data */
    char *buffer_ref = buffer; /* Pointer to buffer */
    fd_set read_set;
    struct timeval timeout = {3, 0};
    uint16_t token_length = 0;
    uint8_t binary_token[APN_TOKEN_BINARY_SIZE];
    int bytes_read = 0; /* Number of bytes read */
    char *token_hex = NULL; /* Token as HEX string */
    int select_returned = 0;

    assert(ctx);
    assert(tokens);

    *tokens = apn_array_init(10, NULL, NULL);
    if (!*tokens) {
        return APN_ERROR;
    }

    if (!ctx->ssl || ctx->feedback) {
        errno = APN_ERR_NOT_CONNECTED;
        return APN_ERROR;
    }

    for (; ;) {
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &read_set);

        select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
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
            bytes_read = __ssl_read(ctx, buffer, sizeof(buffer));
            if (bytes_read < 0) {
                return APN_ERROR;
            } else if (bytes_read > 0) {
                buffer_ref += sizeof(uint32_t);
                memcpy(&token_length, buffer_ref, sizeof(token_length));
                buffer_ref += sizeof(token_length);
                token_length = ntohs(token_length);
                memcpy(&binary_token, buffer_ref, sizeof(binary_token));
                token_hex = apn_token_binary_to_hex(binary_token);
                if (token_hex == NULL) {
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
        case APN_ERR_CONNECTION_TIMEDOUT:
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
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified SSL certificate");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified private key");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified PKCS12 file");
            break;
        case APN_ERR_COULD_NOT_INITIALIZE_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "could not initialize connection");
            break;
        case APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "could not initialize ssl connection");
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
            __apn_strerror_r(errnum, error, sizeof(error) - 1);
            break;
    }
    return apn_strndup(error, sizeof(error));
}

static int __apn_password_cd(char *buf, int size, int rwflag, void *password) {
    (void) rwflag;
    if (!password || size <= 0) {
        return 0;
    }
#ifdef _WIN32
    strncpy_s(buf, size, (char *) password, size);
#else
    strncpy(buf, (char *) password, (size_t) size);
#endif
    buf[size - 1] = '\0';

    return (int) strlen(buf);
}

static apn_return __apn_connect(const apn_ctx_ref ctx, struct __apn_apple_server server) {
    struct addrinfo *addrinfo = NULL;
    struct addrinfo hints;
    SOCKET sock;
    int sock_flags = 0;
    int ret = 0;
    uint8_t connected = 0;
    char str_port[6];
    char ip[INET_ADDRSTRLEN];
    char *error = NULL;
    apn_return ssl_connect_ret = APN_SUCCESS;

    __apn_log(ctx, APN_LOG_LEVEL_INFO, "Connecting to %s:%d...", server.host, server.port);

    if(!ctx->pkcs12_file) {
        if (!ctx->certificate_file) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Certificate file not set, errno: %d", APN_ERR_CERTIFICATE_IS_NOT_SET);
            errno = APN_ERR_CERTIFICATE_IS_NOT_SET;
            return APN_ERROR;
        }

        if (!ctx->private_key_file) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Private key file not set, errno: %d", APN_ERR_PRIVATE_KEY_IS_NOT_SET);
            errno = APN_ERR_PRIVATE_KEY_IS_NOT_SET;
            return APN_ERROR;
        }
    }

    if (ctx->sock == -1) {
        __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Resolving server hostname...");

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        apn_snprintf(str_port, sizeof(str_port) - 1, "%d", server.port);
        ret = getaddrinfo(server.host, str_port, &hints, &addrinfo);
        if (0 != ret) {
            error = apn_error_string(errno);
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to resolve hostname: getaddrinfo() failed: %s (errno: %d)", error,
                      errno);
            free(error);
            return APN_ERROR;
        }

        __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Creating socket...");

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            error = apn_error_string(errno);
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to create socket: socket() failed: %s(errno: %d)", error, errno);
            free(error);
            return APN_ERROR;
        }

#ifndef _WIN32
        sock_flags = fcntl(ctx->sock, F_GETFL, 0);
        fcntl(ctx->sock, F_SETFL, sock_flags | O_NONBLOCK);
#else
        sock_flags = 1;
        ioctlsocket(ctx->sock, FIONBIO, (u_long *) &sock_flags);
#endif

        __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Socket successfully created");

        while (addrinfo) {
            inet_ntop(AF_INET, (void *) &((struct sockaddr_in *) addrinfo->ai_addr)->sin_addr, ip, sizeof(ip));
            __apn_log(ctx, APN_LOG_LEVEL_INFO, "Trying to connect to %s...", ip);
            if (connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
                error = apn_error_string(errno);
                __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not to connect to: %s (errno: %d)", error, errno);
                free(error);
            } else {
                connected = 1;
                break;
            }
            addrinfo = addrinfo->ai_next;
        }

        freeaddrinfo(addrinfo);

        if (!connected) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to establish connection");
            return APN_ERROR;
        }

        __apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection has been established");
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "Initializing SSL connection...");

        ctx->sock = sock;

        ssl_connect_ret =__apn_tls_connect(ctx);
        if(APN_ERROR == ssl_connect_ret) {
            return ssl_connect_ret;
        }

        X509 *cert = SSL_get_peer_certificate(ctx->ssl);
        if (cert) {
            char *line = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            __apn_log(ctx, APN_LOG_LEVEL_INFO, "Certificate subject name: %s", line);
            OPENSSL_free(line);

            line = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
            __apn_log(ctx, APN_LOG_LEVEL_INFO, "Certificate issuer name: %s", line);
            OPENSSL_free(line);
            X509_free(cert);
        }
    }
    return APN_SUCCESS;
}

static int __ssl_write(const apn_ctx_ref ctx, const uint8_t *message, size_t length) {
    int bytes_written = 0;
    int bytes_written_total = 0;

    while (length > 0) {
        bytes_written = SSL_write(ctx->ssl, message, (int) length);
        if (bytes_written <= 0) {
            switch (SSL_get_error(ctx->ssl, bytes_written)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_SYSCALL:
                    switch (errno) {
                        case EINTR:
                            continue;
                        case EPIPE:
                            errno = APN_ERR_NETWORK_UNREACHABLE;
                            return -1;
                        case ETIMEDOUT:
                            errno = APN_ERR_CONNECTION_TIMEDOUT;
                            return -1;
                        default:
                            errno = APN_ERR_SSL_WRITE_FAILED;
                            return -1;
                    }
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_NONE:
                    errno = APN_ERR_CONNECTION_CLOSED;
                    return -1;
                default:
                    errno = APN_ERR_SSL_WRITE_FAILED;
                    return -1;
            }
        }
        message += bytes_written;
        bytes_written_total += bytes_written;
        length -= bytes_written;
    }
    return bytes_written_total;
}

static int __ssl_read(const apn_ctx_ref ctx, char *buff, size_t length) {
    int read;
    for (;;) {
        read = SSL_read(ctx->ssl, buff, (int) length);
        if (read > 0) {
            break;
        }
        switch (SSL_get_error(ctx->ssl, read)) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                continue;
            case SSL_ERROR_SYSCALL:
                switch (errno) {
                    case EINTR:
                        continue;
                    case EPIPE:
                        errno = APN_ERR_NETWORK_UNREACHABLE;
                        return -1;
                    case ETIMEDOUT:
                        errno = APN_ERR_CONNECTION_TIMEDOUT;
                        return -1;
                    default:
                        errno = APN_ERR_SSL_READ_FAILED;
                        return -1;
                }
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_NONE:
                errno = APN_ERR_CONNECTION_CLOSED;
                return -1;
            default:
                errno = APN_ERR_SSL_READ_FAILED;
                return -1;
        }
    }
    return read;
}

static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id) {
    uint8_t cmd = 0;
    uint32_t token_id = 0;
    uint8_t error_code = 0;
    memcpy(&cmd, apns_error, sizeof(uint8_t));
    apns_error += sizeof(uint8_t);
    if (8 == cmd) {
        memcpy(&error_code, apns_error, sizeof(uint8_t));
        apns_error += sizeof(uint8_t);
        if (apns_error_code) {
            *apns_error_code = error_code;
        }
        if (APN_APNS_ERR_INVALID_TOKEN == error_code && id) {
            memcpy(&token_id, apns_error, sizeof(uint32_t));
            *id = ntohl(token_id);
        }
    }
}

#ifdef HAVE_STRERROR_R
#if(!defined(HAVE_POSIX_STRERROR_R) && !defined(HAVE_GLIBC_STRERROR_R) || defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R))
#    error "strerror_r MUST be either POSIX, glibc or vxworks-style"
#  endif
#endif

static void __apn_strerror_r(int errnum, char *buf, size_t buff_size) {
#ifdef _WIN32
    if (strerror_s(buf, buff_size, errnum) != 0) {
        if (buf[0] == '\0') {
            apn_snprintf(buf, buff_size, "Error code %d", errnum);
        }
    }
#elif defined(HAVE_STRERROR_R) && defined(HAVE_POSIX_STRERROR_R)
    if (0 != strerror_r(errnum, buf, buff_size)) {
        if (buf[0] == '\0') {
            apn_snprintf(buf, buff_size, "Error code %d", errnum);
        }
    }
#elif defined(HAVE_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R)
    char tmp_buff[256];
    char *str_error = strerror_r(errnum, tmp_buff, sizeof(tmp_buff));
    if(str_error) {
        apn_strncpy(buf, str_error, buff_size, strlen(str_error));
    } else {
        apn_snprintf(buf, buff_size, "Error code %d", errnum);
    }
#else
    char *str_error = strerror(errnum);
    if (str_error) {
        apn_strncpy(buf, str_error, buff_size, strlen(str_error));
    } else {
        apn_snprintf(buf, buff_size, "Error code %d", errnum);
    }
#endif
}

static void __apn_log(apn_ctx_ref ctx, apn_log_levels level, const char *const message, ...) {
    if (ctx && ctx->log_cb && (ctx->log_level & level)) {
        va_list args;
        va_start(args, message);
        int len = 0;
#ifdef _WIN32
        len = vsnprintf_s(NULL, 0, _TRUNCATE, message, args);
#else
        len = vsnprintf(NULL, 0, message, args);
#endif
        va_end(args);

        if (len <= 0) {
            return;
        }

        uint32_t buff_len = (uint32_t) (len + 1);
        char buffer[buff_len];
        va_start(args, message);

#ifdef _WIN32
        vsnprintf_s(buffer, buff_len, _TRUNCATE, message, args);
#else
        vsnprintf(buffer, buff_len, message, args);
#endif

        ctx->log_cb(level, buffer, buff_len);
        va_end(args);
    }
}

#define __APN_CODE(...) \
    {__VA_ARGS__}

#define __API_SOCKET_READ(__ctx, __read_set, __buffer, __bytes_read, __apple_error_flag, __code, __break_code) \
    __apple_error_flag = 0; \
    if (FD_ISSET(__ctx->sock, __read_set)) { \
        __apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "Socket has data for read"); \
        __apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "Reading data from a socket..."); \
        __bytes_read = __ssl_read(__ctx, __buffer, sizeof(__buffer)); \
        if (__bytes_read > 0) { \
            __apn_log(__ctx, APN_LOG_LEVEL_DEBUG, "%d byte(s) has been read from a socket", __bytes_read); \
            __apple_error_flag = 1; \
        } else { \
            char *__error = apn_error_string(errno); \
            __apn_log(__ctx, APN_LOG_LEVEL_ERROR, "Unable to read data from a socket: %s (errno: %d)", __error, errno); \
            free(__error); \
            __code\
            return APN_ERROR; \
        } \
        __break_code\
    }

#define __APN_SELECT_ERROR(__returned_code, __code) \
    if(__returned_code < 0) { \
        char *__error = apn_error_string(errno); \
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "select() failed: %s (errno: %d)", __error, errno); \
        free(__error); \
        __code \
        return APN_ERROR;\
    }

static apn_return __apn_send_binary_message(const apn_ctx_ref ctx,
                                            const apn_binary_message_ref binary_message,
                                            apn_array_ref tokens,
                                            uint32_t token_index,
                                            uint8_t *apple_error_code,
                                            uint32_t *invalid_token_index) {
    int bytes_read = 0;
    int bytes_written = 0;
    fd_set write_set, read_set;
    uint32_t i = 0;
    struct timeval timeout = {10, 0};
    char *error = NULL;
    const char *token = NULL;
    uint8_t apple_returned_error = 0;
    int select_returned = 0;
    char apple_error_str[6];

    assert(token_index < apn_array_count(tokens));

#define __APN_TOKEN_INDEX if(invalid_token_index){*invalid_token_index = i;}

    i = token_index;

    for (; i < apn_array_count(tokens); i++) {
        token = (const char *) apn_array_item_at_index(tokens, i);
        apn_binary_message_set_id(binary_message, i);
        apn_binary_message_set_token_hex(binary_message, token);

        __apn_log(ctx, APN_LOG_LEVEL_INFO, "Sending notificaton to device with token %s...", token);

        do {
            FD_ZERO(&write_set);
            FD_ZERO(&read_set);
            FD_SET(ctx->sock, &write_set);
            FD_SET(ctx->sock, &read_set);

            select_returned = select(ctx->sock + 1, &read_set, &write_set, NULL, &timeout);
            __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "select() returned %d", select_returned);
        } while (0 == select_returned || (0 > select_returned  && EINTR == errno));

        __APN_SELECT_ERROR(select_returned, __APN_CODE(__APN_TOKEN_INDEX))
        __API_SOCKET_READ(ctx,
                          &read_set,
                          apple_error_str,
                          bytes_read,
                          apple_returned_error,
                          __APN_CODE(__APN_TOKEN_INDEX),
                          __APN_CODE(break;)
        )

        if (FD_ISSET(ctx->sock, &write_set)) {
            __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Socket is ready for writing");
            bytes_written = __ssl_write(ctx, binary_message->message, binary_message->size);
            if (bytes_written <= 0) {
                error = apn_error_string(errno);
                __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to write data to a socket: %s (errno: %d)", error, errno);
                free(error);
                return APN_ERROR;
            }
            __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "%d byte(s) has been written to a socket");
        }
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "Notification has been sent");
    }

    if (!apple_returned_error) {
        timeout.tv_sec = 5;
        do {
            FD_ZERO(&read_set);
            FD_SET(ctx->sock, &read_set);
            select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
            __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "select() returned %d", select_returned);
        } while (0 > select_returned && EINTR == errno);
        __APN_SELECT_ERROR(select_returned, __APN_CODE(__APN_TOKEN_INDEX))
        __API_SOCKET_READ(ctx, &read_set, apple_error_str, bytes_read, apple_returned_error, __APN_CODE(__APN_TOKEN_INDEX), __APN_CODE())
    }

    if (apple_returned_error) {
        __apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Parsing Apple response...", *apple_error_code);
        __apn_parse_apns_error(apple_error_str, apple_error_code, invalid_token_index);
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Apple returned error code %d", *apple_error_code);
        return APN_ERROR;
    }
    return APN_SUCCESS;
}

static apn_binary_message_ref __apn_payload_to_binary_message(const apn_ctx_ref ctx, const apn_payload_ref payload) {
    apn_binary_message *binary_message = NULL;
    char *error = NULL;
    __apn_log(ctx, APN_LOG_LEVEL_INFO, "Creating binary message from payload...");
    binary_message = apn_create_binary_message(payload);
    if (!binary_message) {
        error = apn_error_string(errno);
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to create binary message: %s (errno: %d)", error, errno);
        free(error);
        return NULL;
    }
    __apn_log(ctx, APN_LOG_LEVEL_INFO, "Binary message sucessfully created");
    return binary_message;
}

static void __apn_convert_apple_error(uint8_t apple_error_code) {
    if(apple_error_code > 0) {
        switch (apple_error_code) {
            case APN_APNS_ERR_PROCESSING_ERROR:
                errno = APN_ERR_PROCESSING_ERROR;
                break;
            case APN_APNS_ERR_INVALID_PAYLOAD_SIZE:
                errno = APN_ERR_INVALID_PAYLOAD_SIZE;
                break;
            case APN_APNS_ERR_SERVICE_SHUTDOWN:
                errno = APN_ERR_SERVICE_SHUTDOWN;
                break;
            case APN_APNS_ERR_INVALID_TOKEN:
                errno = APN_ERR_TOKEN_INVALID;
                break;
            default:
                errno = APN_ERR_UNKNOWN;
                break;
        }
    }
}

static apn_return __apn_tls_connect(const apn_ctx_ref ctx) {
    char *error = NULL;
    FILE *pkcs12_file = NULL;
    PKCS12 *pkcs12_cert = NULL;
    EVP_PKEY *private_key = NULL;
    X509 *cert = NULL;
    char *password = NULL;
    SSL_CTX *ssl_ctx = NULL;
    int ret = 0;

    assert(ctx);

    ssl_ctx = SSL_CTX_new(TLSv1_client_method());

    if (!ssl_ctx) {
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not initialize SSL context: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return APN_ERROR;
    }

    SSL_CTX_set_timeout(ssl_ctx, 300);
    SSL_CTX_set_ex_data(ssl_ctx, 0, ctx);
    SSL_CTX_set_info_callback(ssl_ctx, __apn_ssl_info_callback);

    if(ctx->pkcs12_file && ctx->pkcs12_pass) {
        pkcs12_file = fopen(ctx->pkcs12_file, "r");
        if (!pkcs12_file) {
            error = apn_error_string(errno);
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to open file %s: %s (errno: %d)", ctx->pkcs12_file, error,
                      errno);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }

        d2i_PKCS12_fp(pkcs12_file, &pkcs12_cert);
        fclose(pkcs12_file);

        if (!PKCS12_parse(pkcs12_cert, ctx->pkcs12_pass, &private_key, &cert, NULL)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            PKCS12_free(pkcs12_cert);
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }
        PKCS12_free(pkcs12_cert);

        if (!SSL_CTX_use_certificate(ssl_ctx, cert)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            X509_free(cert);
            EVP_PKEY_free(private_key);
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }
        X509_free(cert);

        if (!SSL_CTX_use_PrivateKey(ssl_ctx, private_key)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            EVP_PKEY_free(private_key);
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }
        EVP_PKEY_free(private_key);
    } else {
        if (!SSL_CTX_use_certificate_file(ssl_ctx, ctx->certificate_file, SSL_FILETYPE_PEM)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified certificate: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }

        SSL_CTX_set_default_passwd_cb(ssl_ctx, __apn_password_cd);

        if (ctx->private_key_pass) {
            password = apn_strndup(ctx->private_key_pass, strlen(ctx->private_key_pass));
            if (!password) {
                errno = ENOMEM;
                SSL_CTX_free(ssl_ctx);
                return APN_ERROR;
            }
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, password);
        } else {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, NULL);
        }

        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->private_key_file, SSL_FILETYPE_PEM)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified private key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            if (password) {
                free(password);
            }
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }

        if (password) {
            free(password);
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified private key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }
    }

    ctx->ssl = SSL_new(ssl_ctx);
    SSL_CTX_free(ssl_ctx);

    if (!ctx->ssl) {
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not initialize SSL");
        errno = APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION;
        return APN_ERROR;
    }

    ret = SSL_set_fd(ctx->ssl, ctx->sock);
    if (-1 == ret) {
        __apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to attach socket to SSL: SSL_set_fd() failed (%d)",
                  SSL_get_error(ctx->ssl, ret));
        errno = APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION;
        return APN_ERROR;
    }

    ret = SSL_connect(ctx->ssl);
    if (ret < 1) {
        error = apn_error_string(errno);
        __apn_log(ctx, APN_LOG_LEVEL_ERROR,
                  "Could not initialize SSL connection: SSL_connect() failed: %s, %s (errno: %d):",
                  ERR_error_string((unsigned long) SSL_get_error(ctx->ssl, ret), NULL), error, errno);
        free(error);
        return APN_ERROR;
    }

    __apn_log(ctx, APN_LOG_LEVEL_INFO, "SSL connection has been established");
    return APN_SUCCESS;
}

static void __apn_ssl_info_callback(const SSL *ssl, int where, int ret) {
    apn_ctx_ref ctx = SSL_CTX_get_ex_data(ssl->ctx, 0);
    if(!ctx) {
        return;
    }

    if (where & SSL_CB_LOOP) {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: %s:%s:%s",
                  (where & SSL_ST_CONNECT) ? "connect" : "undef",
                  SSL_state_string_long(ssl),
                  SSL_get_cipher_name(ssl));
    } else if (where & SSL_CB_EXIT) {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: %s:%s", (where & SSL_ST_CONNECT) ? "connect" : "undef", SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: alert %s:%s", (where & SSL_CB_READ) ? "read" : "write", SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_HANDSHAKE_START) {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: handshake started %s:%s:%s", (where & SSL_CB_READ) ? "read" : "write", SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_HANDSHAKE_DONE) {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: handshake done %s:%s:%s", (where & SSL_CB_READ) ? "read" : "write", SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    }  else {
        __apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: state %s:%s:%s", SSL_state_string_long(ssl), SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
}
