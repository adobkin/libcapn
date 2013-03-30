/* 
 * Copyright (c) 2013, Anton Dobkin
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

#include "jansson.h"

#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 

#include "apn.h"

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

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#define DIAGNOSTIC_MAKE_STRING(x) #x
#define DIAGNOSTIC_JOIN_STRING(x, y) DIAGNOSTIC_MAKE_STRING(x ## y)
#define DIAGNOSTIC_DO_PRAGMA(p) _Pragma (#p)

#if defined(__clang__)
    #define DIAGNOSTIC_PRAGMA(x) DIAGNOSTIC_DO_PRAGMA(clang diagnostic x)
    #define DIAGNOSTIC_OFF(x) \
	       DIAGNOSTIC_PRAGMA(push) \
	       DIAGNOSTIC_PRAGMA(ignored DIAGNOSTIC_JOIN_STRING(-W, x))
    #define DIAGNOSTIC_ON(x) \
	    DIAGNOSTIC_PRAGMA(pop)
#elif defined(__GNUC__)
    #define GNUC_NUM_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)
    #define DIAGNOSTIC_PRAGMA(x) DIAGNOSTIC_DO_PRAGMA(GCC diagnostic x)
    #if GNUC_NUM_VERSION >= 402
	    #if GNUC_NUM_VERSION >= 406
	        #define DIAGNOSTIC_OFF(x) \
		        DIAGNOSTIC_PRAGMA(push) \
		        DIAGNOSTIC_PRAGMA(ignored DIAGNOSTIC_JOIN_STRING(-W, x))
	        #define DIAGNOSTIC_ON(x) \
		        DIAGNOSTIC_PRAGMA(pop)
	    #else
	        #define DIAGNOSTIC_OFF(x) \
		        DIAGNOSTIC_PRAGMA(ignored DIAGNOSTIC_JOIN_STRING(-W, x))
	        #define DIAGNOSTIC_ON(x) \
		        DIAGNOSTIC_PRAGMA(warning DIAGNOSTIC_JOIN_STRING(-W, x))
	    #endif
    #endif
#endif

#if !defined(DIAGNOSTIC_OFF) && !defined(DIAGNOSTIC_ON)
    #define DIAGNOSTIC_OFF(x)
    #define DIAGNOSTIC_ON(x)
#endif


#include "apn_strings.h"
#include "version.h"

#define APN_TOKEN_BINARY_SIZE 32

#define APN_PAYLOAD_SIZE  256

#define APN_MESSAGE_SIZE (APN_PAYLOAD_SIZE + APN_TOKEN_BINARY_SIZE + sizeof(uint8_t) +  (sizeof(uint16_t) * 2))

#define APN_RETURN_SUCCESS return APN_SUCCESS

#define APN_RETURN_ERROR return APN_ERROR

#define APN_SET_ERROR(__err, __err_code, __err_msg) \
   do {\
      if(__err){ \
        __err->code = __err_code; \
        apn_strcpy(__err->message, __err_msg, APN_ERROR_MESSAGE_MAX_SIZE);\
      }\
   } while(0);


static char *__apn_errors[APN_ERR_COUNT] = {
    "no memory", // APN_ERR_NOMEM
    "connection context is not initialized", // APN_ERR_CTX_NOT_INITIALIZED
    "no opened connection to Apple Push Notification Service",
    "no opened connection to Apple Feedback Service",
    "invalid argument", // APN_ERR_INVALID_ARGUMENT
    "certificate is not set", // APN_ERR_CERTIFICATE_IS_NOT_SET
    "private key is not set", // APN_ERR_PRIVATE_KEY_IS_NOT_SET
    "notification payload is not set", // APN_ERR_PAYLOAD_IS_NOT_SET
    "no one device token is not set", // APN_ERR_TOKEN_IS_NOT_SET
    "too many device tokens",
    "ssl: unable to use specified SSL certificate", // APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE
    "ssl: unable to use specified private key", // APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY     
    "could not reslove host", // APN_ERR_COULD_NOT_RESOLVE_HOST
    "could not create socket", // APN_ERR_COULD_NOT_CREATE_SOCKET
    "could not initialize connection", // APN_ERR_COULD_NOT_INITIALIZE_CONNECTION
    "ssl: could not initialize ssl connection", // APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION
    "ssl: SSL_write failed", // APN_ERR_SSL_WRITE_FAILED
    "invalid notification payload size", // APN_ERR_INVALID_PAYLOAD_SIZE
    "payload notification contex is not initialized", // APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED
    "incorrect number to display as the badge on application icon", // APN_ERR_PAYLOAD_BADGE_INVALID_VALUE
    "too many custom properties, no more than 5", //APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES
    "specified custom property key is already used", // APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED
    "could not create json document", // APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT
    "alert message text is not set", // APN_ERR_PAYLOAD_ALERT_IS_NOT_SET
    "non-UTF8 symbols detected in a string",
    "unknown error" // APN_ERR_UNKNOWN
};

struct __apn_appl_server {
    char *host;
    int port;
};

struct __apn_appl_server __apn_appl_servers[4] = {
    {"gateway.sandbox.push.apple.com", 2195},
    {"gateway.push.apple.com", 2195},
    {"feedback.sandbox.push.apple.com", 2196},
    {"feedback.push.apple.com", 2196}
};

static char * __token_hex_to_binary_copy(char *, uint16_t);

static uint8_t __apn_payload_alert_init(apn_payload_alert_ref *alert, apn_error_ref error);
static void __apn_payload_custom_property_free(apn_payload_custom_property_ref *property);
static uint8_t __apn_payload_custom_key_is_already_used(apn_payload_ctx_ref payload_ctx, const char *property_key);
static uint8_t __apn_payload_custom_property_init(apn_payload_ctx_ref payload_ctx, const char *property_key,
        apn_error_ref error);
static char * __apn_create_json_document_from_payload(apn_payload_ctx_ref payload_ctx, apn_error_ref error);

static uint8_t __apn_ssl_connect(const apn_ctx_ref, apn_error_ref);
static uint8_t __apn_connect(const apn_ctx_ref, struct __apn_appl_server, apn_error_ref);
static uint8_t __apn_send(const apn_ctx_ref, const char *, size_t, apn_error_ref);
static void __apn_ssl_free(SSL **);

static char * __token_hex_to_binary_copy(char *token, uint16_t token_length) {
    uint16_t i = 0;
    uint16_t j = 0;
    char *binary_token = malloc(APN_TOKEN_BINARY_SIZE + 1);
    int binary = 0;

    if (!binary_token) {
        return NULL;
    }

    for (i = 0, j = 0; i < token_length; i += 2, j++) {
        char tmp[3] = {token[i], token[i + 1], '\0'};
#ifdef WIN32
        sscanf_s(tmp, "%x", &binary);
#else
        sscanf(tmp, "%x", &binary);
#endif
        binary_token[j] = binary;
    }

    binary_token[j + 1] = '\0';
    return binary_token;
}

static uint8_t __apn_payload_alert_init(apn_payload_alert_ref *alert, apn_error_ref error) {
    apn_payload_alert_ref _alert = NULL;

    *alert = NULL;

    _alert = malloc(sizeof (apn_payload_alert));
    if (!_alert) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    _alert->action_loc_key = NULL;
    _alert->body = NULL;
    _alert->launch_image = NULL;
    _alert->loc_args = NULL;
    _alert->loc_key = NULL;
    _alert->__loc_args_count = 0;

    *alert = _alert;

    APN_RETURN_SUCCESS;
}

static void __apn_payload_custom_property_free(apn_payload_custom_property_ref *property) {
    apn_payload_custom_property_ref _property = NULL;
    uint8_t array_size = 0;
    uint8_t i = 0;

    if (property && *property) {
        _property = *property;
        if (_property->key) {
            free(_property->key);
        }
        switch (_property->value_type) {
            case APN_CUSTOM_PROPERTY_TYPE_STRING:
            {
                if (_property->value.string_value.value) {
                    free(_property->value.string_value.value);
                }
            }
                break;
            case APN_CUSTOM_PROPERTY_TYPE_ARRAY:
            {
                array_size = _property->value.array_value.array_size;
                if (_property->value.array_value.array && array_size > 0) {
                    for (i = 0; i < array_size; i++) {
                        free(*(_property->value.array_value.array + i));
                    }
                    free(_property->value.array_value.array);
                }
            }
                break;
            default:
                break;

        }
        free(_property);
    }
}

static uint8_t __apn_payload_custom_key_is_already_used(apn_payload_ctx_ref payload_ctx, const char *property_key) {
    apn_payload_custom_property_ref property = NULL;
    uint8_t i = 0;

    if (payload_ctx->__custom_properties_count == 0 || payload_ctx->custom_properties == NULL) {
        return 0;
    }
    for (i = 0; i < payload_ctx->__custom_properties_count; i++) {
        property = *(payload_ctx->custom_properties + 0);
        if (strcmp(property->key, property_key) == 0) {
            return 1;
        }
    }

    return 0;
}

static uint8_t __apn_payload_custom_property_init(apn_payload_ctx_ref payload_ctx, const char *property_key,
        apn_error_ref error) {

    apn_payload_custom_property_ref *properties = NULL;
    char *key = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (payload_ctx->__custom_properties_count >= 5) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES, __apn_errors[APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES]);
        APN_RETURN_ERROR;
    }

    if (!property_key || strlen(property_key) == 0) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "key of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (!apn_string_is_utf8(property_key)) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "key of custom property contains non-utf8 symbols");
        APN_RETURN_ERROR;
    }

    key = apn_strndup(property_key, strlen(property_key));
    if (__apn_payload_custom_key_is_already_used(payload_ctx, key)) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED, __apn_errors[APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED]);
        free(key);
        APN_RETURN_ERROR;
    }
    free(key);

    if (payload_ctx->__custom_properties_count == 0) {
        payload_ctx->custom_properties = (apn_payload_custom_property_ref *) malloc(sizeof (apn_payload_custom_property_ref *));
        if (!payload_ctx->custom_properties) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    } else {
        properties = (apn_payload_custom_property_ref *) realloc(payload_ctx->custom_properties, (payload_ctx->__custom_properties_count + 1) * sizeof (apn_payload_custom_property_ref));
        if (!properties) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
        payload_ctx->custom_properties = properties;
    }

    APN_RETURN_SUCCESS;
}

static char * __apn_create_json_document_from_payload(apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    json_t *root = NULL;
    json_t *aps = NULL;
    json_t *alert = NULL;
    json_t *args = NULL;
    json_t *array = NULL;
    char *json_document = NULL;
    uint16_t i = 0;
    uint8_t array_i = 0;

    root = json_object();
    if (!root) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT, __apn_errors[APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT]);
        return NULL;
    }

    aps = json_object();
    if (!aps) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT, __apn_errors[APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT]);
        return NULL;
    }

    if (!payload_ctx->alert || !payload_ctx->alert->body) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_ALERT_IS_NOT_SET, __apn_errors[APN_ERR_PAYLOAD_ALERT_IS_NOT_SET]);
        return NULL;
    }
    
    if (!payload_ctx->alert->action_loc_key && !payload_ctx->alert->launch_image &&
            !payload_ctx->alert->loc_args && !payload_ctx->alert->loc_key) {

        json_object_set_new(aps, "alert", json_string(payload_ctx->alert->body));
    } else {
        alert = json_object();
        json_object_set_new(alert, "body", json_string(payload_ctx->alert->body));

        if (payload_ctx->alert->launch_image) {
            json_object_set_new(alert, "launch-image", json_string(payload_ctx->alert->launch_image));
        }

        if (payload_ctx->alert->action_loc_key) {
            json_object_set_new(alert, "action-loc-key", json_string(payload_ctx->alert->action_loc_key));
        }

        if (payload_ctx->alert->loc_key) {
            json_object_set_new(alert, "loc-key", json_string(payload_ctx->alert->loc_key));
        }

        if (payload_ctx->alert->__loc_args_count > 0 && payload_ctx->alert->loc_args) {
            args = json_array();
            for (i = 0; i < payload_ctx->alert->__loc_args_count; i++) {
                json_array_append(args, json_string(*(payload_ctx->alert->loc_args + i)));
            }
            json_object_set_new(alert, "loc-args", args);
        }

        json_object_set_new(aps, "alert", alert);
    }

    if (payload_ctx->badge > -1) {
        json_object_set_new(aps, "badge", json_integer(payload_ctx->badge));
    }

    if (payload_ctx->sound) {
        json_object_set_new(aps, "sound", json_string(payload_ctx->sound));
    }

    json_object_set_new(root, "aps", aps);

    if (payload_ctx->custom_properties && payload_ctx->__custom_properties_count) {
        for (i = 0; i < payload_ctx->__custom_properties_count; i++) {
            apn_payload_custom_property_ref property = *(payload_ctx->custom_properties + i);
            switch (property->value_type) {
                case APN_CUSTOM_PROPERTY_TYPE_BOOL:
                    json_object_set_new(root, property->key, ((property->value.bool_value == 0) ? json_false() : json_true()));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NUMERIC:
                    json_object_set_new(root, property->key, json_integer((json_int_t) property->value.numeric_value));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NULL:
                    json_object_set_new(root, property->key, json_null());
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_STRING:
                    json_object_set_new(root, property->key, json_string(property->value.string_value.value));
                case APN_CUSTOM_PROPERTY_TYPE_DOUBLE:
                    json_object_set_new(root, property->key, json_real(property->value.double_value));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_ARRAY:
                {
                    for (array_i = 0; array_i < property->value.array_value.array_size; array_i++) {
                        json_array_append(array, json_string(*(property->value.array_value.array + array_i)));
                    }
                    json_object_set_new(root, property->key, array);
                }
                    break;
            }
        }
    }

    json_document = json_dumps(root, JSON_ENSURE_ASCII);
    json_decref(root);
    return json_document;
}

void apn_close(apn_ctx_ref ctx) {
    if (ctx->sock > 0) {
        CLOSE_SOCKET(ctx->sock);
        ctx->sock = -1;
    }
    WSACleanup();
    __apn_ssl_free(&ctx->ssl);
}

static uint8_t __apn_connect(const apn_ctx_ref ctx, struct __apn_appl_server server, apn_error_ref error) {
    struct hostent * hostent = NULL;
    struct sockaddr_in socket_address;
    int sock = -1;
#ifdef WIN32
    WSADATA wsa_data;
#endif

    if (ctx->sock == -1) {
#ifdef WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            APN_SET_ERROR(error, -100, "WSAStartup failed");
            APN_RETURN_ERROR;
        }
#endif

        hostent = gethostbyname(server.host);

        if (!hostent) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_RESOLVE_HOST, __apn_errors[APN_ERR_COULD_NOT_RESOLVE_HOST]);
            WSACleanup();
            APN_RETURN_ERROR;
        }

        memset(&socket_address, 0, sizeof (socket_address));
        socket_address.sin_addr = *(struct in_addr*) hostent->h_addr_list[0];
        socket_address.sin_family = AF_INET;
        socket_address.sin_port = htons(server.port);

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sock < 0) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_CREATE_SOCKET, __apn_errors[APN_ERR_COULD_NOT_CREATE_SOCKET]);
            WSACleanup();
            APN_RETURN_ERROR;
        }

        if (connect(sock, (struct sockaddr *) &socket_address, sizeof (socket_address)) < 0) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_CONNECTION, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_CONNECTION]);
            WSACleanup();
            APN_RETURN_ERROR;
        }

        ctx->sock = sock;


        if (__apn_ssl_connect(ctx, error) == APN_ERROR) {
            APN_RETURN_ERROR;
        }
    }

    APN_RETURN_SUCCESS;
}

#if defined(__APPLE__) && defined(__MACH__)

/* Apple deprecated SSL functions on Mac OS X >= 10.7.
 * Disable deprecated warnings
 */
DIAGNOSTIC_OFF(deprecated-declarations)
#endif

static uint8_t __apn_ssl_connect(const apn_ctx_ref ctx, apn_error_ref error) {
    SSL_CTX *ssl_ctx = NULL;
    SSL *_ssl = NULL;

    if (ctx->ssl == NULL) {
        SSL_library_init();
        SSL_load_error_strings();

        ssl_ctx = SSL_CTX_new(SSLv23_client_method());

        if (!SSL_CTX_use_certificate_file(ssl_ctx, ctx->certificate_file, SSL_FILETYPE_PEM)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE]);
            SSL_CTX_free(ssl_ctx);
            APN_RETURN_ERROR;
        }

        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->private_key_file, SSL_FILETYPE_PEM)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY]);
            SSL_CTX_free(ssl_ctx);
            APN_RETURN_ERROR;
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY]);
            SSL_CTX_free(ssl_ctx);
            APN_RETURN_ERROR;
        }

        _ssl = SSL_new(ssl_ctx);
        SSL_CTX_free(ssl_ctx);

        if (!_ssl) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            APN_RETURN_ERROR;
        }

        if (SSL_set_fd(_ssl, ctx->sock) == -1) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            SSL_free(_ssl);
            APN_RETURN_ERROR;
        }

        if (SSL_connect(_ssl) < 1) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            SSL_free(_ssl);
            APN_RETURN_ERROR;
        }
        ctx->ssl = _ssl;
    }
    APN_RETURN_SUCCESS;
}

static void __apn_ssl_free(SSL **ssl) {
    if (!ssl || !*ssl) {
        return;
    }
    SSL_shutdown(*ssl);
    SSL_free(*ssl);
    *ssl = NULL;
}

static uint8_t __apn_send(const apn_ctx_ref ctx, const char *message, size_t message_len, apn_error_ref error) {
    if (SSL_write(ctx->ssl, message, message_len) < 0) {
        APN_SET_ERROR(error, APN_ERR_SSL_WRITE_FAILED, __apn_errors[APN_ERR_SSL_WRITE_FAILED]);
        return APN_ERROR;
    }
    return APN_SUCCESS;
}

uint32_t apn_feedback(const apn_ctx_ref ctx, const char ***tokens, apn_error_ref error) {
    uint8_t buffer[38];
    int read = 0;
    uint8_t contnuie_loop = 1;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, __apn_errors[APN_ERR_INVALID_ARGUMENT]);
        APN_RETURN_ERROR;
    }
    if (!ctx->ssl || !ctx->feedback) {
        APN_SET_ERROR(error, APN_ERR_NOT_CONNECTED_FEEDBACK, __apn_errors[APN_ERR_NOT_CONNECTED_FEEDBACK]);
        APN_RETURN_ERROR;
    }
    if (!ctx->certificate_file) {
        APN_SET_ERROR(error, APN_ERR_CERTIFICATE_IS_NOT_SET, __apn_errors[APN_ERR_CERTIFICATE_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }
    if (!ctx->private_key_file) {
        APN_SET_ERROR(error, APN_ERR_PRIVATE_KEY_IS_NOT_SET, __apn_errors[APN_ERR_PRIVATE_KEY_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    do {
        read = SSL_read(ctx->ssl, buffer, 38);
        if (read > 0) {
            break;
        }

        switch (SSL_get_error(ctx->ssl, read)) {
            case SSL_ERROR_NONE:
            case SSL_ERROR_ZERO_RETURN: /* no more data */
                contnuie_loop = 0; /* get out of loop */
                printf("No more data \n");
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                printf("Pending data \n");
                break;
        }

    } while (contnuie_loop);

    APN_RETURN_SUCCESS;
}

#if defined(__APPLE__) && defined(__MACH__)
DIAGNOSTIC_ON(deprecated - declarations)
#endif

uint8_t apn_send(const apn_ctx_ref ctx, apn_payload_ctx_ref payload, apn_error_ref error) {
    char *json_payload = NULL;
    char binary_message[APN_MESSAGE_SIZE];
    char *binary_message_ref = NULL;
    char *token = NULL;
    char *binary_token = NULL;

    size_t payload_size = 0;
    uint32_t i = 0;
    uint16_t token_length = 0;
    uint16_t payload_length = 0;
    size_t message_length = 0;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, __apn_errors[APN_ERR_INVALID_ARGUMENT]);
        APN_RETURN_ERROR;
    }

    if (!ctx->ssl || ctx->feedback) {
        APN_SET_ERROR(error, APN_ERR_NOT_CONNECTED, __apn_errors[APN_ERR_NOT_CONNECTED]);
        APN_RETURN_ERROR;
    }

    if (!ctx->certificate_file) {
        APN_SET_ERROR(error, APN_ERR_CERTIFICATE_IS_NOT_SET, __apn_errors[APN_ERR_CERTIFICATE_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }
    if (!ctx->private_key_file) {
        APN_SET_ERROR(error, APN_ERR_PRIVATE_KEY_IS_NOT_SET, __apn_errors[APN_ERR_PRIVATE_KEY_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    if (ctx->__tokens_count == 0) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_IS_NOT_SET, __apn_errors[APN_ERR_TOKEN_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    if (!payload) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_IS_NOT_SET, __apn_errors[APN_ERR_PAYLOAD_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    json_payload = __apn_create_json_document_from_payload(payload, error);

    if (!json_payload) {
        APN_RETURN_ERROR;
    }

    payload_size = strlen(json_payload);

    if (payload_size > APN_PAYLOAD_SIZE) {
        APN_SET_ERROR(error, APN_ERR_INVALID_PAYLOAD_SIZE, __apn_errors[APN_ERR_INVALID_PAYLOAD_SIZE]);
        free(json_payload);
        APN_RETURN_ERROR;
    }

    for (i = 0; i < ctx->__tokens_count; i++) {
        binary_message_ref = binary_message;
        token_length = htons(APN_TOKEN_BINARY_SIZE);
        payload_length = htons(payload_size);

        token = ctx->tokens[i];
        binary_token = __token_hex_to_binary_copy(token, strlen(token));

        if (!binary_token) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }

        *binary_message_ref++ = 0;

        memcpy(binary_message_ref, &token_length, sizeof (token_length));
        binary_message_ref += sizeof (token_length);

        memcpy(binary_message_ref, binary_token, APN_TOKEN_BINARY_SIZE);
        binary_message_ref += APN_TOKEN_BINARY_SIZE;

        memcpy(binary_message_ref, &payload_length, sizeof (payload_length));
        binary_message_ref += sizeof (payload_length);

        memcpy(binary_message_ref, json_payload, payload_size);
        binary_message_ref += payload_size;

        message_length = (binary_message_ref - binary_message);

        if (__apn_send(ctx, binary_message, message_length, error) != APN_SUCCESS) {
            free(json_payload);
            APN_RETURN_ERROR;
        }
    }

    free(json_payload);
    APN_RETURN_SUCCESS;
}

uint8_t apn_init(apn_ctx_ref *ctx, apn_error_ref error) {
    apn_ctx_ref _ctx = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, __apn_errors[APN_ERR_INVALID_ARGUMENT]);
        APN_RETURN_ERROR;
    }

    *ctx = NULL;
    _ctx = malloc(sizeof (apn_ctx));

    if (!_ctx) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    _ctx->sock = -1;
    _ctx->ssl = NULL;
    _ctx->__tokens_count = 0;
    _ctx->certificate_file = NULL;
    _ctx->private_key_file = NULL;
    _ctx->tokens = NULL;
    _ctx->feedback = 0;
    *ctx = _ctx;
    APN_RETURN_SUCCESS;
}

apn_ctx_ref apn_copy(const apn_ctx_ref ctx, apn_error_ref error) {
    apn_ctx_ref _ctx = NULL;
    uint16_t i = 0;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (apn_init(&_ctx, error)) {
        return NULL;
    }

    if (ctx->certificate_file) {
        _ctx->certificate_file = apn_strndup(ctx->certificate_file, strlen(ctx->certificate_file));
    }
    if (_ctx->private_key_file) {
        _ctx->private_key_file = apn_strndup(ctx->private_key_file, strlen(ctx->private_key_file));
    }

    if (ctx->__tokens_count > 0 && ctx->tokens) {
        _ctx->tokens = (char **) malloc((ctx->__tokens_count) * sizeof (char *));
        if (!_ctx->tokens) {
            apn_free(&_ctx, NULL);
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }

        for (i = 0; i < ctx->__tokens_count; i++) {
            _ctx->tokens[i] = apn_strndup(_ctx->tokens[i], strlen(_ctx->tokens[i]));
            _ctx->__tokens_count++;
        }
    }
    return _ctx;
}

uint8_t apn_free(apn_ctx_ref *ctx, apn_error_ref error) {
    apn_ctx_ref _ctx = NULL;
    uint16_t i = 0;

    if (!ctx || !(*ctx)) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    _ctx = *ctx;

    if (_ctx->certificate_file) {
        free(_ctx->certificate_file);
    }

    if (_ctx->private_key_file) {
        free(_ctx->private_key_file);
    }

    if (_ctx->tokens && _ctx->__tokens_count > 0) {
        for (i = 0; i < _ctx->__tokens_count; i++) {
            char *token = *(_ctx->tokens + i);
            free(token);
        }
        free(_ctx->tokens);
    }
    free(_ctx);
    *ctx = NULL;
    APN_RETURN_SUCCESS;
}

uint8_t apn_connect(const apn_ctx_ref ctx, uint8_t sandbox, apn_error_ref error) {
    struct __apn_appl_server server;
    if (sandbox) {
        server = __apn_appl_servers[0];
    } else {
        server = __apn_appl_servers[1];
    }

    return __apn_connect(ctx, server, error);
}

uint8_t apn_connect_feedback(const apn_ctx_ref ctx, uint8_t sandbox, apn_error_ref error) {
    struct __apn_appl_server server;
    if (sandbox) {
        server = __apn_appl_servers[2];
    } else {
        server = __apn_appl_servers[3];
    }

    ctx->feedback = 1;
    return __apn_connect(ctx, server, error);
}

uint8_t apn_set_certificate(apn_ctx_ref ctx, const char *cert, apn_error_ref error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (ctx->certificate_file) {
        free(ctx->certificate_file);
    }
    if (cert) {
        ctx->certificate_file = apn_strndup(cert, strlen(cert));
    }

    APN_RETURN_SUCCESS;
}

uint8_t apn_set_private_key(apn_ctx_ref ctx, const char *key, apn_error_ref error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (ctx->private_key_file) {
        free(ctx->private_key_file);
    }
    if (key) {
        ctx->private_key_file = apn_strndup(key, strlen(key));
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_add_token(apn_ctx_ref ctx, const char *token, apn_error_ref error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (ctx->__tokens_count >= UINT32_MAX) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_TOO_MANY, __apn_errors[APN_ERR_TOKEN_TOO_MANY]);
        APN_RETURN_ERROR;
    }

    if (!token) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "invalid value of token. Expected string, passed NULL");
        APN_RETURN_ERROR;
    }

    if (ctx->__tokens_count == 0) {
        ctx->tokens = malloc(sizeof (char *));
        if (!ctx->tokens) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    } else {
        char **tokens = (char **) realloc(ctx->tokens, (ctx->__tokens_count + 1) * sizeof (char *));
        if (!tokens) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
        ctx->tokens = tokens;
    }
    ctx->tokens[ctx->__tokens_count] = apn_strndup(token, strlen(token));
    ctx->__tokens_count++;

    APN_RETURN_SUCCESS;
}

const char *apn_certificate(const apn_ctx_ref ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }
    if (ctx->certificate_file) {
        ret_value = ctx->certificate_file;
    }
    return ret_value;
}

const char *apn_private_key(const apn_ctx_ref ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (ctx->private_key_file) {
        ret_value = ctx->private_key_file;
    }
    return ret_value;
}

uint32_t apn_tokens(const apn_ctx_ref ctx, char ***tokens, apn_error_ref error) {
    *tokens = NULL;
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return 0;
    }
    if (ctx->tokens && ctx->__tokens_count) {
        *tokens = ctx->tokens;
        return ctx->__tokens_count;
    }

    return 0;
}

apn_payload_ctx_ref apn_payload_copy(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    apn_payload_ctx_ref _payload = NULL;
    uint16_t i = 0;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (apn_payload_init(&_payload, error)) {
        return NULL;
    }

    _payload->badge = payload_ctx->badge;

    if (payload_ctx->sound) {
        _payload->sound = apn_strndup(payload_ctx->sound, strlen(payload_ctx->sound));
    }

    if (payload_ctx->alert) {
        if (payload_ctx->alert->action_loc_key) {
            _payload->alert->action_loc_key = apn_strndup(payload_ctx->alert->action_loc_key, strlen(payload_ctx->alert->action_loc_key));
        }
        if (payload_ctx->alert->body) {
            _payload->alert->body = apn_strndup(payload_ctx->alert->body, strlen(payload_ctx->alert->body));
        }
        if (payload_ctx->alert->launch_image) {
            _payload->alert->launch_image = apn_strndup(payload_ctx->alert->launch_image, strlen(payload_ctx->alert->launch_image));
        }
        if (payload_ctx->alert->loc_key) {
            _payload->alert->loc_key = apn_strndup(payload_ctx->alert->loc_key, strlen(payload_ctx->alert->loc_key));
        }
        if (payload_ctx->alert->__loc_args_count > 0 && payload_ctx->alert->loc_args) {
            _payload->alert->loc_args = (char **) malloc((payload_ctx->alert->__loc_args_count) * sizeof (char *));
            if (!_payload->alert->loc_args) {
                apn_payload_free(&_payload, NULL);
                APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }

            for (i = 0; i < payload_ctx->alert->__loc_args_count; i++) {
                _payload->alert->loc_args[i] = apn_strndup(payload_ctx->alert->loc_args[i], strlen(payload_ctx->alert->loc_args[i]));
                _payload->alert->__loc_args_count++;
            }
        }
    }

    if (payload_ctx->__custom_properties_count > 0 && payload_ctx->custom_properties) {
        uint8_t i = 0;

        _payload->custom_properties = (apn_payload_custom_property_ref *) malloc(payload_ctx->__custom_properties_count * sizeof (apn_payload_custom_property_ref));
        if (!_payload->custom_properties) {
            apn_payload_free(&_payload, NULL);
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
        _payload->__custom_properties_count = 0;
        for (i = 0; i < payload_ctx->__custom_properties_count; i++) {
            apn_payload_custom_property_ref property = (apn_payload_custom_property_ref) malloc(sizeof (apn_payload_custom_property));
            if (!property) {
                apn_payload_free(&_payload, NULL);
                APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }

            property->value_type = (*(payload_ctx->custom_properties + i))->value_type;
            property->key = apn_strndup((*(payload_ctx->custom_properties + i))->key, strlen((*(payload_ctx->custom_properties + i))->key));

            switch (property->value_type) {
                case APN_CUSTOM_PROPERTY_TYPE_BOOL:
                    property->value.bool_value = (*(payload_ctx->custom_properties + i))->value.bool_value;
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NUMERIC:
                    property->value.numeric_value = (*(payload_ctx->custom_properties + i))->value.numeric_value;
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_DOUBLE:
                    property->value.double_value = (*(payload_ctx->custom_properties + i))->value.double_value;
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NULL:
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_STRING:
                {
                    property->value.string_value.value = apn_strndup((*(payload_ctx->custom_properties + i))->value.string_value.value, strlen((*(payload_ctx->custom_properties + i))->value.string_value.value));
                    property->value.string_value.length = (*(payload_ctx->custom_properties + i))->value.string_value.length;
                }
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_ARRAY:
                {
                    uint8_t j = 0;
                    property->value.array_value.array = (char **) malloc((*(payload_ctx->custom_properties + i))->value.array_value.array_size * sizeof (char *));
                    if (!property->value.array_value.array) {
                        apn_payload_free(&_payload, NULL);
                        __apn_payload_custom_property_free(&property);
                        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
                        return NULL;
                    }
                    property->value.array_value.array_size = 0;
                    for (j = 0; j < (*(payload_ctx->custom_properties + i))->value.array_value.array_size; j++) {
                        char *array_item = apn_strndup((*(payload_ctx->custom_properties + i))->value.array_value.array[j], strlen((*(payload_ctx->custom_properties + i))->value.array_value.array[j]));
                        property->value.array_value.array[j] = array_item;
                        property->value.array_value.array_size++;
                    }
                }
                    break;
            }
            _payload->custom_properties[_payload->__custom_properties_count] = property;
            _payload->__custom_properties_count++;
        }
    }
    return _payload;
}

uint8_t apn_payload_init(apn_payload_ctx_ref *payload_ctx, apn_error_ref error) {
    apn_payload_ctx_ref _payload = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, __apn_errors[APN_ERR_INVALID_ARGUMENT]);
        APN_RETURN_ERROR;
    }
    *payload_ctx = NULL;
    _payload = malloc(sizeof (apn_payload_ctx));
    if (!_payload) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if (__apn_payload_alert_init(&_payload->alert, error)) {
        free(_payload);
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    _payload->badge = -1;
    _payload->sound = NULL;
    _payload->__custom_properties_count = 0;
    _payload->custom_properties = NULL;

    *payload_ctx = _payload;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_free(apn_payload_ctx_ref *payload_ctx, apn_error_ref error) {
    apn_payload_ctx_ref _payload_ctx = NULL;
    if (!payload_ctx || !(*payload_ctx)) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    _payload_ctx = *payload_ctx;

    if (_payload_ctx->alert) {
        if (_payload_ctx->alert->action_loc_key) {
            free(_payload_ctx->alert->action_loc_key);
        }
        if (_payload_ctx->alert->body) {
            free(_payload_ctx->alert->body);
        }
        if (_payload_ctx->alert->launch_image) {
            free(_payload_ctx->alert->launch_image);
        }
        if (_payload_ctx->alert->loc_key) {
            free(_payload_ctx->alert->loc_key);
        }

        if (_payload_ctx->alert->loc_args && _payload_ctx->alert->__loc_args_count > 0) {
            uint16_t i = 0;
            for (i = 0; i < _payload_ctx->alert->__loc_args_count; i++) {
                char *arg = *(_payload_ctx->alert->loc_args + i);
                free(arg);
            }
            free(_payload_ctx->alert->loc_args);
        }
        free(_payload_ctx->alert);
    }

    if (_payload_ctx->sound) {
        free(_payload_ctx->sound);
    }

    if (_payload_ctx->custom_properties && _payload_ctx->__custom_properties_count > 0) {
        uint8_t i = 0;
        for (i = 0; i < _payload_ctx->__custom_properties_count; i++) {
            __apn_payload_custom_property_free(_payload_ctx->custom_properties + i);
        }
        free(_payload_ctx->custom_properties);
    }

    free(_payload_ctx);
    *payload_ctx = NULL;
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_badge(apn_payload_ctx_ref payload_ctx, uint16_t badge, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (badge < 0 || badge > UINT16_MAX) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_BADGE_INVALID_VALUE, __apn_errors[APN_ERR_PAYLOAD_BADGE_INVALID_VALUE]);
        APN_RETURN_ERROR;
    }

    payload_ctx->badge = badge;
    APN_RETURN_SUCCESS;
}

uint16_t apn_payload_badge(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return -1;
    }
    return payload_ctx->badge;
}

uint8_t apn_payload_set_sound(apn_payload_ctx_ref payload_ctx, const char *sound, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->sound) {
        free(payload_ctx->sound);
        payload_ctx->sound = NULL;
    }
    if (sound) {
        payload_ctx->sound = apn_strndup(sound, strlen(sound));
    }
    APN_RETURN_SUCCESS;
}

const char *apn_payload_sound(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->sound) {
        ret_value = payload_ctx->sound;
    }
    return ret_value;
}

uint8_t apn_payload_set_body(apn_payload_ctx_ref payload_ctx, const char *body, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->body) {
        free(payload_ctx->alert->body);
        payload_ctx->alert->body = NULL;
    }
    if (body) {
        if (!apn_string_is_utf8(body)) {
            APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "body contains non-utf8 symbols");
            APN_RETURN_ERROR;
        }
        payload_ctx->alert->body = apn_strndup(body, strlen(body));
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_localized_action_key(apn_payload_ctx_ref payload_ctx, const char *key, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->action_loc_key) {
        free(payload_ctx->alert->action_loc_key);
        payload_ctx->alert->action_loc_key = NULL;
    }
    if (key) {
        payload_ctx->alert->action_loc_key = apn_strndup(key, strlen(key));
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_launch_image(apn_payload_ctx_ref payload_ctx, const char *image, apn_error_ref error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->action_loc_key) {
        free(payload_ctx->alert->action_loc_key);
        payload_ctx->alert->action_loc_key = NULL;
    }
    if (image) {
        payload_ctx->alert->launch_image = apn_strndup(image, strlen(image));
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_localized_key(apn_payload_ctx_ref payload_ctx, const char *key, char **args, uint16_t args_count, apn_error_ref error) {
    char *arg = NULL;
    uint16_t i = 0;
    uint16_t args_i = 0;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->loc_key) {
        free(payload_ctx->alert->loc_key);
        payload_ctx->alert->loc_key = NULL;

        if (payload_ctx->alert->loc_args && payload_ctx->alert->__loc_args_count) {
            for (i = 0; i < payload_ctx->alert->__loc_args_count; i++) {
                arg = *(payload_ctx->alert->loc_args + i);
                free(arg);
            }
            free(payload_ctx->alert->loc_args);
            payload_ctx->alert->loc_args = NULL;
        }
    }

    if (key) {
        payload_ctx->alert->loc_key = apn_strndup(key, strlen(key));

        if (args && args_count > 0) {
            payload_ctx->alert->loc_args = (char **) malloc((args_count) * sizeof (char *));
            if (!payload_ctx->alert->loc_args) {
                APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
                APN_RETURN_ERROR;
            }

            for (args_i = 0; args_i < args_count; args_i++) {
                payload_ctx->alert->loc_args[args_i] = apn_strndup(args[args_i], strlen(args[args_i]));
                payload_ctx->alert->__loc_args_count++;
            }
        }
    }
    APN_RETURN_SUCCESS;
}

const char *apn_payload_launch_image(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->launch_image) {
        ret_value = payload_ctx->alert->launch_image;
    }
    return ret_value;
}

const char *apn_payload_localized_action_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->action_loc_key) {
        ret_value = payload_ctx->alert->action_loc_key;
    }
    return ret_value;
}

const char *apn_payload_body(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->body) {
        ret_value = payload_ctx->alert->body;
    }
    return ret_value;
}

const char *apn_payload_localized_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->loc_key) {
        ret_value = payload_ctx->alert->loc_key;
    }
    return ret_value;
}

uint16_t apn_payload_localized_key_args(const apn_payload_ctx_ref payload_ctx, char ***args, apn_error_ref error) {
    *args = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return 0;
    }
    if (payload_ctx->alert->loc_args && payload_ctx->alert->__loc_args_count) {
        *args = payload_ctx->alert->loc_args;
        return payload_ctx->alert->__loc_args_count;
    }
    return 0;
}

uint8_t apn_payload_add_custom_property_integer(apn_payload_ctx_ref payload_ctx, const char *property_key,
        int64_t property_value,
        apn_error_ref error) {

    apn_payload_custom_property_ref property = NULL;

    if (!property_value) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->key = apn_strndup(property_key, strlen(property_key));
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NUMERIC;
    property->value.numeric_value = property_value;
    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_double(apn_payload_ctx_ref payload_ctx, const char *property_key,
        double property_value,
        apn_error_ref error) {

    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_DOUBLE;
    property->key = apn_strndup(property_key, strlen(property_key));
    property->value.double_value = property_value;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_bool(apn_payload_ctx_ref payload_ctx, const char *property_key,
        unsigned char property_value,
        apn_error_ref error) {

    apn_payload_custom_property_ref property = NULL;

    if (!property_value) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_BOOL;
    property->key = apn_strndup(property_key, strlen(property_key));
    property->value.bool_value = (property_value == 0) ? 0 : 1;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_null(apn_payload_ctx_ref payload_ctx, const char *property_key, apn_error_ref error) {
    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NULL;
    property->key = apn_strndup(property_key, strlen(property_key));
    property->value.string_value.value = NULL;
    property->value.string_value.length = 0;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_string(apn_payload_ctx_ref payload_ctx, const char *property_key,
        const char *property_value,
        apn_error_ref error) {

    apn_payload_custom_property_ref property = NULL;

    if (!property_value) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    if (!apn_string_is_utf8(property_value)) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "value contains non-utf8 symbols");
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));
    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_STRING;
    property->key = apn_strndup(property_key, strlen(property_key));

    property->value.string_value.value = apn_strndup(property_value, strlen(property_value));
    property->value.string_value.length = strlen(property_value);

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_array(apn_payload_ctx_ref payload_ctx, const char *property_key,
        const char **array, uint8_t array_size,
        apn_error_ref error) {

    char **_array = NULL;
    apn_payload_custom_property_ref property = NULL;
    uint8_t i = 0;
    uint8_t _array_size = 0;

    if (!array) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));
    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_ARRAY;
    property->key = apn_strndup(property_key, strlen(property_key));

    if (array_size) {
        _array = (char **) malloc(sizeof (char *) * array_size);
        if (!_array) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }

        _array_size = (array_size > 6) ? 6 : array_size;
        for (i = 0; i < _array_size; i++) {
            _array[i] = apn_strndup(array[i], strlen(array[i]));
        }
        property->value.array_value.array = _array;
        property->value.array_value.array_size = _array_size;
    }

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint apn_version() {
    return APN_VERSION_NUM;
}

const char * apn_version_string() {
    return APN_VERSION_STRING;
}
