/*
* Copyright (c) 2013, 2014 Anton Dobkin
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

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <openssl/err.h>

#include "apn_strings.h"
#include "apn_tokens.h"
#include "apn_memory.h"
#include "apn_version.h"
#include "apn_paload_private.h"
#include "apn.h"

#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#define APN_PAYLOAD_MAX_SIZE  2048

enum __apn_apple_errors {
    APN_APNS_ERR_NO_ERRORS = 0,
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
};

struct __apn_apple_server {
    char *host;
    int port;
};

static struct __apn_apple_server __apn_apple_servers[4] = {
    {"gateway.sandbox.push.apple.com", 2195},
    {"gateway.push.apple.com", 2195},
    {"feedback.sandbox.push.apple.com", 2196},
    {"feedback.push.apple.com", 2196}
};

typedef struct __apn_binary_message {
    uint32_t payload_size;
    uint32_t message_size;
    uint8_t *token_position;
    uint8_t *id_position;
    uint8_t *message; 
} apn_binary_message;

typedef apn_binary_message *apn_binary_message_ref;

static int __apn_password_cd(char *buf, int size, int rwflag, void *password);
static apn_return __apn_connect(const apn_ctx_ref ctx, struct __apn_apple_server server);
static int __ssl_write(const apn_ctx_ref ctx, const uint8_t *message, size_t length);
static int __ssl_read(const apn_ctx_ref ctx, char *buff, size_t length);
static void __apn_parse_apns_error(char *apns_error, uint16_t *errcode, uint32_t *id);
static void __apn_strerror_r(int errnum, char *buf, size_t buff_size);

static apn_binary_message * __apn_create_binary_message(const apn_payload_ref payload);
static void __apn_binary_message_set_id(apn_binary_message_ref binary_message, uint32_t id);
static void __apn_binary_message_set_token(apn_binary_message_ref binary_message, uint8_t *token);
static apn_binary_message_ref __apn_binary_message_init(uint32_t message_size);
static void __apn_binary_message_free(apn_binary_message_ref binary_message);

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

apn_ctx_ref apn_init(const char *const cert, const char *const private_key, const char *const private_key_pass) {
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
    ctx->tokens_count = 0;
    ctx->certificate_file = NULL;
    ctx->private_key_file = NULL;
    ctx->tokens = NULL;
    ctx->feedback = 0;
    ctx->private_key_pass = NULL;
    ctx->mode = APN_MODE_PRODUCTION;

    if (APN_SUCCESS != apn_set_certificate(ctx, cert)) {
        apn_free(&ctx);
        return NULL;
    }

    if (APN_SUCCESS != apn_set_private_key(ctx, private_key, private_key_pass)) {
        apn_free(&ctx);
        return NULL;
    }
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
        apn_tokens_array_free((*ctx)->tokens, (*ctx)->tokens_count);
        free((*ctx));
        *ctx = NULL;
    }
}

void apn_close(apn_ctx_ref ctx) {
    assert(ctx);
    if (ctx->ssl) {
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->sock != -1) {
        CLOSE_SOCKET(ctx->sock);
        ctx->sock = -1;
    }
}

apn_return apn_set_certificate(apn_ctx_ref ctx, const char *const cert) {
    assert(ctx);
    if (ctx->certificate_file) {
        apn_strfree(&ctx->certificate_file);
    }
    if (cert && strlen(cert) > 0) {
        if (NULL == (ctx->certificate_file = apn_strndup(cert, strlen(cert)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

apn_return apn_set_private_key(apn_ctx_ref ctx, const char *const key, const char *const pass) {
    assert(ctx);
    if (ctx->private_key_file) {
        apn_strfree(&ctx->private_key_file);
    }
    if (key && strlen(key) > 0) {
        if (NULL == (ctx->private_key_file = apn_strndup(key, strlen(key)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    if (ctx->private_key_pass) {
        apn_strfree(&ctx->private_key_pass);
    }
    if (pass && strlen(pass) > 0) {
        if (NULL == (ctx->private_key_pass = apn_strndup(pass, strlen(pass)))) {
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

apn_return apn_add_token(apn_ctx_ref ctx, const char *const token) {
    uint8_t *binary_token = NULL;
    uint8_t **tokens = NULL;

    assert(ctx);
    assert(token);

    if (ctx->tokens_count >= UINT32_MAX) {
        errno = APN_ERR_TOKEN_TOO_MANY;
        return APN_ERROR;
    }

    if (!apn_hex_token_is_valid(token)) {
        errno = APN_ERR_TOKEN_INVALID;
        return APN_ERROR;
    }

    tokens = (uint8_t **) apn_realloc(ctx->tokens, (ctx->tokens_count + 1) * sizeof(uint8_t *));
    if (!tokens) {
        errno = ENOMEM;
        return APN_ERROR;
    }
    ctx->tokens = tokens;

    if (!(binary_token = apn_token_hex_to_binary(token))) {
        return APN_ERROR;
    }

    ctx->tokens[ctx->tokens_count] = binary_token;
    ctx->tokens_count++;
    return APN_SUCCESS;
}

void apn_remove_all_tokens(apn_ctx_ref ctx) {
    assert(ctx);
    apn_tokens_array_free(ctx->tokens, ctx->tokens_count);
    ctx->tokens = NULL;
    ctx->tokens_count = 0;
}

apn_connection_mode apn_mode(const apn_ctx_ref ctx) {
    assert(ctx);
    return ctx->mode;
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

apn_return apn_send(const apn_ctx_ref ctx, const apn_payload_ref payload, char **invalid_token) {
    apn_binary_message * binary_message = NULL;
    uint8_t **tokens = NULL;
    char apple_error[6];
    uint16_t apple_errcode = 0;
    int bytes_read = 0;
    int bytes_written = 0;
    uint32_t tokens_count = 0;
    uint32_t invalid_message_id = 0;
    fd_set write_set, read_set;
    int select_returned = 0;
    uint32_t i = 0;
    struct timeval timeout = {10, 0};
    uint8_t apple_returned_error = 0;

    assert(ctx);
    assert(payload);

    if (!ctx->ssl || ctx->feedback) {
        errno = APN_ERR_NOT_CONNECTED;
        return APN_ERROR;
    }

    if (payload->tokens_count > 0 && payload->tokens != NULL) {
        tokens = payload->tokens;
        tokens_count = payload->tokens_count;
    } else if (ctx->tokens_count > 0 && ctx->tokens != NULL) {
        tokens = ctx->tokens;
        tokens_count = ctx->tokens_count;
    }

    if (tokens_count == 0) {
        errno = APN_ERR_TOKEN_IS_NOT_SET;
        return APN_ERROR;
    }

    binary_message = __apn_create_binary_message(payload);
    if(!binary_message) {
        return APN_ERROR;
    }

    while (1) {
        if (i == tokens_count) {
            break;
        }
                
        __apn_binary_message_set_id(binary_message, i);
        __apn_binary_message_set_token(binary_message, tokens[i]);

        FD_ZERO(&write_set);
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &write_set);
        FD_SET(ctx->sock, &read_set);

        select_returned = select(ctx->sock + 1, &read_set, &write_set, NULL, &timeout);
        if (select_returned <= 0) {
            if (errno == EINTR) {
                continue;
            }
            __apn_binary_message_free(binary_message);
            errno = APN_ERR_SELECT;
            return APN_ERROR;
        }
               
        if (FD_ISSET(ctx->sock, &read_set)) {
            bytes_read = __ssl_read(ctx, apple_error, sizeof(apple_error));
            if (bytes_read <= 0) {
                return APN_ERROR;
            }
            apple_returned_error = 1;
        }
                
        if (FD_ISSET(ctx->sock, &write_set)) {
            bytes_written = __ssl_write(ctx, binary_message->message, binary_message->message_size);
            if (bytes_written <= 0) {
                __apn_binary_message_free(binary_message);
                return APN_ERROR;
            }
            i++;
        }
    }

    __apn_binary_message_free(binary_message);
    timeout.tv_sec = 1;
    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &read_set);
        select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
        if (select_returned < 0) {
            if (errno == EINTR) {
                continue;
            }
            errno = APN_ERR_SELECT;
            return APN_ERROR;
        }

        if (select_returned == 0) {
            break;
        }

        if (FD_ISSET(ctx->sock, &read_set)) {
            bytes_read = __ssl_read(ctx, apple_error, sizeof(apple_error));
            if (bytes_read > 0) {
                apple_returned_error = 1;
            } else {
                return APN_ERROR;
            }
            break;
        }
    }
    
    if(apple_returned_error) {
        __apn_parse_apns_error(apple_error, &apple_errcode, &invalid_message_id);
        if (apple_errcode == APN_ERR_TOKEN_INVALID && invalid_token) {
            *invalid_token = apn_token_binary_to_hex(tokens[invalid_message_id]);
        }
        errno = apple_errcode;
        return APN_ERROR;
    }
    
    return APN_SUCCESS;
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

apn_return apn_feedback(const apn_ctx_ref ctx, char ***tokens_array, uint32_t *tokens_array_count) {
    char buffer[38]; /* Buffer to read data */
    char *buffer_ref = buffer; /* Pointer to buffer */
    fd_set read_set;
    struct timeval timeout = {3, 0};
    uint16_t token_length = 0;
    uint8_t binary_token[APN_TOKEN_BINARY_SIZE];
    int bytes_read = 0; /* Number of bytes read */
    char **tokens = NULL; /* Array of HEX tokens */
    uint32_t tokens_count = 0; /* Tokens count */
    char *token_hex = NULL; /* Token as HEX string */
    int select_returned = 0;

    assert(ctx);
    assert(tokens_array);
    assert(tokens_array_count);

    if (!ctx->ssl || ctx->feedback) {
        errno = APN_ERR_NOT_CONNECTED;
        return APN_ERROR;
    }

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &read_set);

        select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
        if (select_returned < 0) {
            if (errno == EINTR) {
                continue;
            }
            errno = APN_ERR_SELECT;
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
                    apn_feedback_tokens_array_free(tokens, tokens_count);
                    return APN_ERROR;
                }
                tokens = (char **) apn_realloc(tokens, (tokens_count + 1) * sizeof(char *));
                if (!tokens) {
                    apn_feedback_tokens_array_free(tokens, tokens_count);
                    errno = ENOMEM;
                    return APN_ERROR;
                }
                tokens[tokens_count] = token_hex;
                tokens_count++;
            }
            break;
        }
    }

    *tokens_array = tokens;
    *tokens_array_count = tokens_count;

    return APN_SUCCESS;
}

uint32_t apn_version() {
    return APN_VERSION_NUM;
}

const char *apn_version_string() {
    return APN_VERSION_STRING;
}

void apn_feedback_tokens_array_free(char **tokens_array, uint32_t tokens_array_count) {
    uint32_t i = 0;
    if (tokens_array != NULL && tokens_array_count > 0) {
        for (i = 0; i < tokens_array_count; i++) {
            char *token = *(tokens_array + i);
            free(token);
        }
        free(tokens_array);
    }
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
        case APN_ERR_TOKEN_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1, "no device tokens given");
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
        case APN_ERR_COULD_NOT_RESOLVE_HOST:
            apn_snprintf(error, sizeof(error) - 1, "could not reslove host");
            break;
        case APN_ERR_COULD_NOT_CREATE_SOCKET:
            apn_snprintf(error, sizeof(error) - 1, "could not create socket");
            break;
        case APN_ERR_SELECT:
            apn_snprintf(error, sizeof(error) - 1, "system call select() returned error");
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
            apn_snprintf(error, sizeof(error) - 1, "alert message text or key used to get a localized alert-message string or content-available flag must be set");
            break;
        default:
            __apn_strerror_r(errnum, error, sizeof(error) - 1);
            break;
    }
    return apn_strndup(error, sizeof(error));
}

static int __apn_password_cd(char *buf, int size, int rwflag, void *password) {
    (void) rwflag;
    if (password == NULL) {
        return 0;
    }
#ifdef _WIN32
    strncpy_s(buf, size, (char *) password, size);
#else
    strncpy(buf, (char *) password, size);
#endif
    buf[size - 1] = '\0';

    return (int) strlen(buf);
}

static apn_binary_message_ref __apn_binary_message_init(uint32_t message_size) {
    apn_binary_message_ref binary_message = malloc(sizeof(apn_binary_message));
    if(!binary_message) {
        errno = ENOMEM;
        return NULL;
    }
    binary_message->message = malloc(message_size);
    if (!binary_message->message) {
        errno = ENOMEM;
        free(binary_message);
        return NULL;
    };
    binary_message->message_size = message_size;
    binary_message->id_position = NULL;
    binary_message->token_position = NULL;
    return binary_message;
}

static void __apn_binary_message_free(apn_binary_message_ref binary_message) {
    if(binary_message) {
        if(binary_message->message) {
            free(binary_message->message);
        }
        free(binary_message);
    }
}

static void __apn_binary_message_set_id(apn_binary_message_ref binary_message, uint32_t id) {
    uint32_t id_n = htonl(id);
    if(binary_message && binary_message->id_position) {
        memcpy(binary_message->id_position, &id_n, sizeof(uint32_t));
    }
}

static void __apn_binary_message_set_token(apn_binary_message_ref binary_message, uint8_t *token) {
    if(binary_message && binary_message->token_position) {
        memcpy(binary_message->token_position, token, APN_TOKEN_BINARY_SIZE);
    }
}

static apn_binary_message_ref __apn_create_binary_message(const apn_payload_ref payload) {
    char *json = NULL;
    size_t json_size = 0;
    uint8_t *frame = NULL;
    uint8_t *frame_ref = NULL;
    size_t frame_size = 0;
    uint32_t id_n = 0; // ID (network ordered)
    uint32_t expiry_n = htonl((uint32_t) payload->expiry); // expiry time (network ordered)
    uint8_t item_id = 1; // Item ID
    uint16_t item_data_size_n = 0; // Item data size (network ordered)
    uint8_t *message_ref = NULL;
    uint32_t frame_size_n; // Frame size (network ordered)
    apn_binary_message_ref binary_message;
    
    json = apn_create_json_document_from_payload(payload);
    if (!json) {
        return NULL;
    }
    
    json_size = strlen(json);
    if (json_size > APN_PAYLOAD_MAX_SIZE) {
        errno = APN_ERR_INVALID_PAYLOAD_SIZE;
        free(json);
        return NULL;
    }
        
    frame_size = ((sizeof(uint8_t) + sizeof(uint16_t)) * 5)
            + APN_TOKEN_BINARY_SIZE
            + json_size
            + sizeof(uint32_t)
            + sizeof(uint32_t)
            + sizeof(uint8_t);
    
    frame_size_n = htonl(frame_size);
    frame = malloc(frame_size);
    if (!frame) {
        errno = ENOMEM;
        return NULL;
    }
    frame_ref = frame;
    
    binary_message = __apn_binary_message_init((uint32_t) (frame_size + sizeof(uint32_t) + sizeof(uint8_t)));
    if(!binary_message) {
        return NULL;
    }
    message_ref = binary_message->message;
        
    /* Token */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(APN_TOKEN_BINARY_SIZE);
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    frame_ref += APN_TOKEN_BINARY_SIZE;

    /* Payload */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(json_size);
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, json, json_size);
    frame_ref += json_size;
    
    free(json);

    /* Message ID */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof(uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, &id_n, sizeof(uint32_t));
    frame_ref += sizeof(uint32_t);

    /* Expires */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof(uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, &expiry_n, sizeof(uint32_t));
    frame_ref += sizeof(uint32_t);

    /* Priority */
    *frame_ref++ = item_id;
    item_data_size_n = htons(sizeof(uint8_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    *frame_ref = (uint8_t) payload->priority;

    /* Binary message */
    *message_ref++ = 2;
    memcpy(message_ref, &frame_size_n, sizeof(uint32_t));
    message_ref += sizeof(uint32_t);
    memcpy(message_ref, frame, frame_size);
    
    binary_message->token_position = message_ref + (sizeof(uint8_t) + sizeof(uint16_t));
    binary_message->id_position = binary_message->token_position + (APN_TOKEN_BINARY_SIZE + ((sizeof(uint8_t) + sizeof(uint16_t)) * 2) + json_size);

    free(frame);
    return binary_message;
}

static apn_return __apn_connect(const apn_ctx_ref ctx, struct __apn_apple_server server) {
    struct hostent *hostent = NULL;
    struct sockaddr_in socket_address;
    SOCKET sock;
    int sock_flags = 0;
    SSL_CTX *ssl_ctx = NULL;
    char *password = NULL;

    if (!ctx->certificate_file) {
        errno = APN_ERR_CERTIFICATE_IS_NOT_SET;
        return APN_ERROR;
    }
    if (!ctx->private_key_file) {
        errno = APN_ERR_PRIVATE_KEY_IS_NOT_SET;
        return APN_ERROR;
    }

    if (ctx->sock == -1) {
        hostent = gethostbyname(server.host);
        if (!hostent) {
            errno = APN_ERR_COULD_NOT_RESOLVE_HOST;
            return APN_ERROR;
        }

        memset(&socket_address, 0, sizeof(socket_address));
        socket_address.sin_addr = *(struct in_addr *) hostent->h_addr_list[0];
        socket_address.sin_family = AF_INET;
        socket_address.sin_port = htons(server.port);

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            errno = APN_ERR_COULD_NOT_CREATE_SOCKET;
            return APN_ERROR;
        }

        if (connect(sock, (struct sockaddr *) &socket_address, sizeof(socket_address)) < 0) {
            errno = APN_ERR_COULD_NOT_INITIALIZE_CONNECTION;
            return APN_ERROR;
        }

        ctx->sock = sock;
        ssl_ctx = SSL_CTX_new(TLSv1_client_method());

        if (!SSL_CTX_use_certificate_file(ssl_ctx, ctx->certificate_file, SSL_FILETYPE_PEM)) {
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }

        SSL_CTX_set_default_passwd_cb(ssl_ctx, __apn_password_cd);

        if (ctx->private_key_pass) {
            password = apn_strndup(ctx->private_key_pass, strlen(ctx->private_key_pass));
            if (password == NULL) {
                errno = ENOMEM;
                SSL_CTX_free(ssl_ctx);
                return APN_ERROR;
            }
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, password);
        } else {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, NULL);
        }

        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->private_key_file, SSL_FILETYPE_PEM)) {
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            SSL_CTX_free(ssl_ctx);
            if (password) {
                free(password);
            }
            return APN_ERROR;
        }

        if (password) {
            free(password);
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }

        ctx->ssl = SSL_new(ssl_ctx);
        SSL_CTX_free(ssl_ctx);

        if (!ctx->ssl) {
            errno = APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION;
            return APN_ERROR;
        }

        if (-1 == SSL_set_fd(ctx->ssl, ctx->sock) ||
                SSL_connect(ctx->ssl) < 1) {
            errno = APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION;
            return APN_ERROR;
        }

#ifndef _WIN32
        sock_flags = fcntl(ctx->sock, F_GETFL, 0);
        fcntl(ctx->sock, F_SETFL, sock_flags | O_NONBLOCK);
#else
        sock_flags = 1;
        ioctlsocket(ctx->sock, FIONBIO, (u_long *) &sock_flags);
#endif
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
                    apn_close(ctx);
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
    for (; ;) {
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
                apn_close(ctx);
                errno = APN_ERR_CONNECTION_CLOSED;
                return -1;
            default:
                errno = APN_ERR_CONNECTION_TIMEDOUT;
                return -1;
        }
    }
    return read;
}

static void __apn_parse_apns_error(char *apns_error, uint16_t *errcode, uint32_t *id) {
    uint8_t cmd = 0;
    uint8_t apple_error_code = 0;
    uint32_t notification_id = 0;
    memcpy(&cmd, apns_error, sizeof(uint8_t));
    apns_error += sizeof(cmd);
    if (cmd == 8) {
        memcpy(&apple_error_code, apns_error, sizeof(uint8_t));
        apns_error += sizeof(apple_error_code);
        switch (apple_error_code) {
            case APN_APNS_ERR_PROCESSING_ERROR:
                *errcode = APN_ERR_PROCESSING_ERROR;
                break;
            case APN_APNS_ERR_INVALID_PAYLOAD_SIZE:
                *errcode = APN_ERR_INVALID_PAYLOAD_SIZE;
                break;
            case APN_APNS_ERR_SERVICE_SHUTDOWN:
                *errcode = APN_ERR_SERVICE_SHUTDOWN;
                break;
            case APN_APNS_ERR_INVALID_TOKEN:
                *errcode = APN_ERR_TOKEN_INVALID;
                memcpy(&notification_id, apns_error, sizeof(uint32_t));
                *id = ntohl(notification_id);
                break;
            default:
                *errcode = APN_ERR_UNKNOWN;
                break;
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
