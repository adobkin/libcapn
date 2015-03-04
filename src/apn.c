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

#include "jansson.h"

#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include <errno.h>

#include <fcntl.h>

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

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <openssl/err.h>

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
#define APN_PAYLOAD_MAX_SIZE  256
#define APN_RETURN_SUCCESS return APN_SUCCESS
#define APN_RETURN_ERROR return APN_ERROR

#define APN_SET_ERROR(__err, __err_code, __err_msg) \
        __apn_error_set(__err, __err_code, __err_msg);

static uint8_t __ssl_lib_initialized = 0;

enum __apn_apns_errors {
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

static char *__apn_errors[APN_ERR_COUNT] = {
    "out of memory", // APN_ERR_NOMEM
    "connection context is not initialized. Expected poninter to initialize apn_ctx structure, passed NULL", // APN_ERR_CTX_NOT_INITIALIZED
    "no opened connection to Apple Push Notification Service",
    "no opened connection to Apple Feedback Service",
    "connection was closed", // APN_ERR_CONNECTION_CLOSED
    "invalid argument", // APN_ERR_INVALID_ARGUMENT
    "certificate is not set", // APN_ERR_CERTIFICATE_IS_NOT_SET
    "private key is not set", // APN_ERR_PRIVATE_KEY_IS_NOT_SET
    "notification payload is not set", // APN_ERR_PAYLOAD_IS_NOT_SET
    "no device tokens given", // APN_ERR_TOKEN_IS_NOT_SET
    "invalid device token", // APN_ERR_TOKEN_INVALID
    "too many device tokens",
    "unable to use specified SSL certificate", // APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE
    "unable to use specified private key", // APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY     
    "could not reslove host", // APN_ERR_COULD_NOT_RESOLVE_HOST
    "could not create socket", // APN_ERR_COULD_NOT_CREATE_SOCKET
    "system call select() returned error", // APN_ERR_SELECT_ERROR
    "could not initialize connection", // APN_ERR_COULD_NOT_INITIALIZE_CONNECTION
    "could not initialize ssl connection", // APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION
    "SSL_write failed", // APN_ERR_SSL_WRITE_FAILED
    "SSL_read failed", // APN_ERR_SSL_READ_FAILED
    "invalid notification payload size", // APN_ERR_INVALID_PAYLOAD_SIZE
    "payload notification contex is not initialized, Expected poninter to initialize apn_payload_ctx, passed NULL", // APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED
    "incorrect number to display as the badge on application icon", // APN_ERR_PAYLOAD_BADGE_INVALID_VALUE
    "too many custom properties, no more than 5", //APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES
    "specified custom property key is already used", // APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED
    "could not create json document", // APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT
    "alert message text and key used to get a localized alert-message string are not set", // APN_ERR_PAYLOAD_ALERT_IS_NOT_SET
    "non-UTF8 symbols detected in a string",
    "processing error", // APN_ERR_PROCESSING_ERROR
    "server closed the connection", // APN_ERR_SERVICE_SHUTDOWN
    "unknown error" // APN_ERR_UNKNOWN
};

struct __apn_appl_server {
    char *host;
    int port;
};

static struct __apn_appl_server __apn_appl_servers[4] = {
    {"gateway.sandbox.push.apple.com", 2195},
    {"gateway.push.apple.com", 2195},
    {"feedback.sandbox.push.apple.com", 2196},
    {"feedback.push.apple.com", 2196}
};

static void * __apn_realloc(void *, size_t);
static uint8_t * __token_hex_to_binary(const char *);
static char * __token_binary_to_hex(const uint8_t *);
static uint8_t __apn_payload_alert_init(apn_payload_alert_ref *, apn_error_ref *);
static void __apn_payload_custom_property_free(apn_payload_custom_property_ref *);
static uint8_t __apn_payload_custom_key_is_already_used(apn_payload_ctx_ref, const char *);
static uint8_t __apn_payload_custom_property_init(apn_payload_ctx_ref, const char *, apn_error_ref *);
static char * __apn_create_json_document_from_payload(apn_payload_ctx_ref, apn_error_ref *);
static uint8_t __apn_connect(const apn_ctx_ref, struct __apn_appl_server, apn_error_ref *);
static int __ssl_read(const apn_ctx_ref, char *, size_t, apn_error_ref *);
static size_t __ssl_write(const apn_ctx_ref, const uint8_t *, size_t, apn_error_ref *);
static void __apn_tokens_array_free(uint8_t **, uint32_t);
static uint8_t** __apn_tokens_array_copy(uint8_t **, uint32_t, apn_error_ref *);
static void __apn_error_set(apn_error_ref *, uint32_t, const char *);
static uint8_t __apn_is_error(const apn_error_ref);
static uint8_t __apn_check_hex_token(const char *);
static size_t __apn_create_binary_message(uint8_t *, const char * const, uint32_t, uint32_t, apn_notification_priority, uint8_t **, apn_error_ref *);

static void *__apn_realloc(void *ptr, size_t size) {
    void *new_ptr = NULL;
    if (ptr != NULL) {
        if (size == 0) {
            free(ptr);
            return NULL;
        } else {
            new_ptr = realloc(ptr, size);
            if (new_ptr == NULL) {
                free(ptr);
            }
            return new_ptr;
        }
    }
    return malloc(size);
}

static void __apn_tokens_array_free(uint8_t **tokens, uint32_t count) {
    uint8_t *token = NULL;
    int64_t i = 0;
    if (tokens && count > 0) {
        for (i = 0; i < count; i++) {
            token = tokens[i];
            free(token);
        }
        free(tokens);
    }
}

static uint8_t ** __apn_tokens_array_copy(uint8_t **tokens, uint32_t count, apn_error_ref *error) {
    uint8_t **new_tokens = NULL;
    int64_t i = 0;
    if (count > 0 && tokens) {
        new_tokens = (uint8_t **) malloc(count);
        if (!new_tokens) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
        for (i = 0; i < count; i++) {
            new_tokens[i] = (uint8_t *)malloc(APN_TOKEN_BINARY_SIZE);
            if (!new_tokens[i]) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }
            memcpy(new_tokens[i], tokens[i], APN_TOKEN_BINARY_SIZE);
        }
    }
    return new_tokens;
}

static uint8_t * __token_hex_to_binary(const char *token) {
    uint16_t i = 0;
    uint16_t j = 0;
    uint8_t *binary_token = NULL;
    int binary = 0;

    binary_token = malloc(APN_TOKEN_BINARY_SIZE);
    if (!binary_token) {
        return NULL;
    }
    memset(binary_token, 0, APN_TOKEN_BINARY_SIZE);

    for (i = 0, j = 0; i < APN_TOKEN_BINARY_SIZE * 2; i += 2, j++) {
        char tmp[3] = {token[i], token[i + 1], '\0'};
#ifdef _WIN32
        sscanf_s(tmp, "%x", &binary);
#else
        sscanf(tmp, "%x", &binary);
#endif
        binary_token[j] = binary;
    }
    return binary_token;
}

static char * __token_binary_to_hex(const uint8_t *binary_token) {
    uint16_t i = 0;
    size_t token_size = (APN_TOKEN_BINARY_SIZE * 2) + 1;
    char *token = malloc(token_size);
    char *p = token;

    if (!token) {
        return NULL;
    }

    for (i = 0; i < APN_TOKEN_BINARY_SIZE; i++) {
#ifdef _WIN32
        _snprintf_s(p, token_size, 3, "%2.2hhX", (unsigned char) binary_token[i]);
#else
        snprintf(p, 3, "%2.2hhX", (unsigned char) binary_token[i]);
#endif
        p += 2;
    }
    return token;
}

static uint8_t __apn_check_hex_token(const char *token) {
    char *p = (char *) token;

    while (*p != '\0') {
        if (!isxdigit(*p)) {
            return 0;
        }
        p++;
    }
    return 1;
}

static void __apn_error_set(apn_error_ref *error, uint32_t code, const char *message) {
    apn_error_ref _error = NULL;

    if (error) {
        _error = malloc(sizeof (apn_error));
        if (!_error) {
            return;
        }
        _error->code = code;
        _error->message = apn_strndup(message, strlen(message));
        _error->invalid_token = NULL;
        *error = _error;
    }
}

static uint8_t __apn_is_error(const apn_error_ref error) {
    if (error != NULL && error->code > 0) {
        return 1;
    }
    return 0;
}

static uint8_t __apn_payload_alert_init(apn_payload_alert_ref *alert, apn_error_ref *error) {
    apn_payload_alert_ref _alert = NULL;

    *alert = NULL;

    _alert = malloc(sizeof (apn_payload_alert));
    if (!_alert) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
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
        free(_property->key);

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
        apn_error_ref *error) {

    apn_payload_custom_property_ref *properties = NULL;
    char *key = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (payload_ctx->__custom_properties_count >= 5) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES]);
        APN_RETURN_ERROR;
    }

    if (!property_key || strlen(property_key) == 0) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "key of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (!apn_string_is_utf8(property_key)) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "key of custom property contains non-utf8 symbols");
        APN_RETURN_ERROR;
    }

    if ((key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_key_is_already_used(payload_ctx, key)) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED]);
        free(key);
        APN_RETURN_ERROR;
    }
    free(key);

    if (payload_ctx->__custom_properties_count == 0) {
        payload_ctx->custom_properties = (apn_payload_custom_property_ref *) malloc(sizeof (apn_payload_custom_property_ref *));
        if (!payload_ctx->custom_properties) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    } else {
        properties = (apn_payload_custom_property_ref *) __apn_realloc(payload_ctx->custom_properties, (payload_ctx->__custom_properties_count + 1) * sizeof (apn_payload_custom_property_ref));
        if (!properties) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
        payload_ctx->custom_properties = properties;
    }

    APN_RETURN_SUCCESS;
}

static size_t __apn_create_binary_message(uint8_t *token, const char * const payload, uint32_t id, uint32_t expiry, apn_notification_priority priority, uint8_t ** message, apn_error_ref *error) {
    uint8_t * frame = NULL;
    uint8_t * frame_ref = NULL;
    size_t frame_size = 0;
    size_t payload_size = 0;

    uint32_t id_n = htonl(id); // ID (network ordered) 
    uint32_t expiry_n = htonl(expiry); // expiry time (network ordered)

    uint8_t item_id = 1; // Item ID
    uint16_t item_data_size_n = 0; // Item data size (network ordered)

    size_t binary_message_size = 0;
    uint8_t *binary_message = NULL;
    uint8_t *binary_message_ref = NULL;
    uint32_t frame_size_n; // Frame size (network ordered)

    payload_size = strlen(payload);
    frame_size = ((sizeof (uint8_t) + sizeof (uint16_t)) * 5)
            + APN_TOKEN_BINARY_SIZE
            + payload_size
            + sizeof (uint32_t)
            + sizeof (uint32_t)
            + sizeof (uint8_t);

    frame_size_n = htonl(frame_size);

    frame = (uint8_t *) malloc(frame_size);
    if (!frame) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        *message = NULL;
        return 0;
    }
    frame_ref = frame;

    binary_message_size = frame_size + sizeof (uint32_t) + sizeof (uint8_t);
    binary_message = (uint8_t *) malloc(binary_message_size);
    if (!binary_message) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        *message = NULL;
        free(frame);
        return 0;
    }
    binary_message_ref = binary_message;

    /* Token */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(APN_TOKEN_BINARY_SIZE);
    memcpy(frame_ref, &item_data_size_n, sizeof (uint16_t));
    frame_ref += sizeof (uint16_t);
    memcpy(frame_ref, token, APN_TOKEN_BINARY_SIZE);
    frame_ref += APN_TOKEN_BINARY_SIZE;

    /* Payload */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(payload_size);
    memcpy(frame_ref, &item_data_size_n, sizeof (uint16_t));
    frame_ref += sizeof (uint16_t);
    memcpy(frame_ref, payload, payload_size);
    frame_ref += payload_size;

    /* Message ID */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof (uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof (uint16_t));
    frame_ref += sizeof (uint16_t);
    memcpy(frame_ref, &id_n, sizeof (uint32_t));
    frame_ref += sizeof (uint32_t);

    /* Expires */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof (uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof (uint16_t));
    frame_ref += sizeof (uint16_t);
    memcpy(frame_ref, &expiry_n, sizeof (uint32_t));
    frame_ref += sizeof (uint32_t);

    /* Priority */
    *frame_ref++ = item_id;
    item_data_size_n = htons(sizeof (uint8_t));
    memcpy(frame_ref, &item_data_size_n, sizeof (uint16_t));
    frame_ref += sizeof (uint16_t);
    *frame_ref++ = (uint8_t) priority;

    /* Binary message */
    *binary_message_ref++ = 2;

    memcpy(binary_message_ref, &frame_size_n, sizeof (uint32_t));
    binary_message_ref += sizeof (uint32_t);
    memcpy(binary_message_ref, frame, frame_size);

    free(frame);

    *message = binary_message;
    return binary_message_size;
}

static char * __apn_create_json_document_from_payload(apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
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
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT]);
        return NULL;
    }

    aps = json_object();
    if (!aps) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT]);
        return NULL;
    }

    if (!payload_ctx->alert || (!payload_ctx->alert->loc_key && !payload_ctx->alert->body && !payload_ctx->content_available)) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_ALERT_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_ALERT_IS_NOT_SET]);
        return NULL;
    }

    if (!payload_ctx->alert->action_loc_key && !payload_ctx->alert->launch_image &&
            !payload_ctx->alert->loc_args && !payload_ctx->alert->loc_key) {

        json_object_set_new(aps, "alert", json_string(payload_ctx->alert->body));
    } else {
        alert = json_object();

        if (payload_ctx->alert->body) {
            json_object_set_new(alert, "body", json_string(payload_ctx->alert->body));
        }

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

    if (payload_ctx->content_available == 1) {
        json_object_set_new(aps, "content-available", json_integer(payload_ctx->content_available));
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
                    break;
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

    json_document = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return json_document;
}

static int __apn_password_cd(char *buf, int size, int rwflag, void *password) {
    if (password == NULL) {
        return 0;
    }
#ifdef _WIN32
    strncpy_s(buf, size, (char *) password, size);
#else
    strncpy(buf, (char *) password, size);
#endif
    buf[size - 1] = '\0';

    return strlen(buf);
}

#if defined(__APPLE__) && defined(__MACH__)
/* Apple deprecated SSL functions on Mac OS X >= 10.7.
 * Disable deprecated warnings
 */
DIAGNOSTIC_OFF(deprecated-declarations)
#endif

static uint8_t __apn_connect(const apn_ctx_ref ctx, struct __apn_appl_server server, apn_error_ref *error) {
    struct hostent * hostent = NULL;
    struct sockaddr_in socket_address;
    SOCKET sock = -1; /* File descriptor for socket connection */
    int sock_flags = 0; /* Socket flags */
    SSL_CTX *ssl_ctx = NULL; /* Pointer to the SSL context */
    char *password = NULL;

#ifdef _WIN32
    WSADATA wsa_data;
#endif

    if (ctx->sock == -1) {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            APN_SET_ERROR(error, -100, "WSAStartup failed");
            APN_RETURN_ERROR;
        }
#endif

        hostent = gethostbyname(server.host);

        if (!hostent) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_RESOLVE_HOST | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_RESOLVE_HOST]);
            APN_RETURN_ERROR;
        }

        memset(&socket_address, 0, sizeof (socket_address));
        socket_address.sin_addr = *(struct in_addr*) hostent->h_addr_list[0];
        socket_address.sin_family = AF_INET;
        socket_address.sin_port = htons(server.port);

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sock < 0) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_CREATE_SOCKET | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_CREATE_SOCKET]);
            APN_RETURN_ERROR;
        }

        if (connect(sock, (struct sockaddr *) &socket_address, sizeof (socket_address)) < 0) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_CONNECTION | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_CONNECTION]);
            APN_RETURN_ERROR;
        }

        ctx->sock = sock;
        ssl_ctx = SSL_CTX_new(TLSv1_client_method());

        if (!SSL_CTX_use_certificate_file(ssl_ctx, ctx->certificate_file, SSL_FILETYPE_PEM)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE]);
            SSL_CTX_free(ssl_ctx);
            APN_RETURN_ERROR;
        }

        SSL_CTX_set_default_passwd_cb(ssl_ctx, __apn_password_cd);

        if (ctx->private_key_pass) {
            password = apn_strndup(ctx->private_key_pass, strlen(ctx->private_key_pass));
            if (password == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                APN_RETURN_ERROR;
            }
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, password);
        } else {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, NULL);
        }

        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->private_key_file, SSL_FILETYPE_PEM)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY]);
            SSL_CTX_free(ssl_ctx);
            if (password) {
                free(password);
            }
            APN_RETURN_ERROR;
        }

        if (password) {
            free(password);
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            APN_SET_ERROR(error, APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY]);
            SSL_CTX_free(ssl_ctx);
            APN_RETURN_ERROR;
        }

        ctx->ssl = SSL_new(ssl_ctx);
        SSL_CTX_free(ssl_ctx);

        if (!ctx->ssl) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            APN_RETURN_ERROR;
        }

        if (SSL_set_fd(ctx->ssl, ctx->sock) == -1) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            SSL_free(ctx->ssl);
            APN_RETURN_ERROR;
        }

        if (SSL_connect(ctx->ssl) < 1) {
            APN_SET_ERROR(error, APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION]);
            SSL_free(ctx->ssl);
            APN_RETURN_ERROR;
        }

#ifndef _WIN32
        sock_flags = fcntl(ctx->sock, F_GETFL, 0);
        fcntl(ctx->sock, F_SETFL, sock_flags | O_NONBLOCK);
#else
        sock_flags = 1;
        ioctlsocket(ctx->sock, FIONBIO, (u_long *) & sock_flags);
#endif
    }

    APN_RETURN_SUCCESS;
}

void apn_close(apn_ctx_ref ctx) {
    if (ctx) {
        if (ctx->ssl) {
            SSL_shutdown(ctx->ssl);
            SSL_free(ctx->ssl);
            ctx->ssl = NULL;
        }

        if (ctx->sock != -1) {
            CLOSE_SOCKET(ctx->sock);
            ctx->sock = -1;
        }

#ifdef _WIN32
        WSACleanup();
#endif
    }
}

static void __apn_parse_apns_error(char *apns_error, uint32_t *id, apn_error_ref *error) {
    uint8_t cmd = 0;
    uint8_t error_code = 0;
    uint32_t notification_id = 0;

    memcpy(&cmd, apns_error, sizeof (uint8_t));
    apns_error += sizeof (cmd);

    if (cmd == 8) {
        memcpy(&error_code, apns_error, sizeof (uint8_t));
        apns_error += sizeof (error_code);

        switch (error_code) {
            case APN_APNS_ERR_PROCESSING_ERROR:
                APN_SET_ERROR(error, APN_ERR_PROCESSING_ERROR | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_PROCESSING_ERROR]);
                break;
            case APN_APNS_ERR_INVALID_PAYLOAD_SIZE:
                APN_SET_ERROR(error, APN_ERR_INVALID_PAYLOAD_SIZE | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_INVALID_PAYLOAD_SIZE]);
                break;
            case APN_APNS_ERR_SERVICE_SHUTDOWN:
                APN_SET_ERROR(error, APN_ERR_SERVICE_SHUTDOWN | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_SERVICE_SHUTDOWN]);
                break;
            case APN_APNS_ERR_INVALID_TOKEN:
                APN_SET_ERROR(error, APN_ERR_TOKEN_INVALID | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_INVALID]);
                break;
            default: break;
        }

        if (id) {
            memcpy(&notification_id, apns_error, sizeof (uint32_t));
            *id = notification_id;
        }
    }
}

static size_t __ssl_write(const apn_ctx_ref ctx, const uint8_t *message, size_t length, apn_error_ref *error) {
    int bytes_written = 0;
    int bytes_written_total = 0;

    while (length > 0) {
        bytes_written = SSL_write(ctx->ssl, message, length);

        if (bytes_written <= 0) {
            switch (SSL_get_error(ctx->ssl, bytes_written)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
#ifdef _WIN32
                    Sleep(1000);
#else
                    sleep(1);
#endif 
                    continue;
                case SSL_ERROR_SYSCALL:
                    switch (errno) {
                        case EINTR:
                            continue;
                        case EPIPE:
                            APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "network unreachable (SSL_ERROR_SYSCALL, errno => EPIPE)");
                            return -1;
                        case ETIMEDOUT:
                            APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "connection timeout (SSL_ERROR_SYSCALL, errno => ETIMEDOUT)");
                            return -1;
                        default:
                            APN_SET_ERROR(error, APN_ERR_SSL_WRITE_FAILED | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SSL_WRITE_FAILED]);
                            return -1;
                    }
                case SSL_ERROR_ZERO_RETURN:
                    APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "server closed connection (SSL_ERROR_ZERO_RETURN)");
                    return -1;
                default:
                    APN_SET_ERROR(error, APN_ERR_SSL_WRITE_FAILED | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SSL_WRITE_FAILED]);
                    return -1;
            }
        }

        message += bytes_written;
        bytes_written_total += bytes_written;
        length -= bytes_written;
    }

    return bytes_written_total;
}

static int __ssl_read(const apn_ctx_ref ctx, char *buff, size_t buff_length, apn_error_ref *error) {
    int read = -1;
    for (;;) {
        read = SSL_read(ctx->ssl, buff, buff_length);
        if (read > 0) {
            break;
        }
        switch (SSL_get_error(ctx->ssl, read)) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
#ifdef _WIN32
                Sleep(1000);
#else
                sleep(1);
#endif   
                continue;
            case SSL_ERROR_SYSCALL:
                switch (errno) {
                    case EINTR:
                        continue;
                    case EPIPE:
                        APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "network unreachable (SSL_ERROR_SYSCALL, errno => EPIPE)");
                        return -1;
                    case ETIMEDOUT:
                        APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "connection timeout (SSL_ERROR_SYSCALL, errno => ETIMEDOUT)");
                        return -1;
                    default:
                        APN_SET_ERROR(error, APN_ERR_SSL_READ_FAILED | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SSL_READ_FAILED]);
                        return -1;
                }

            case SSL_ERROR_ZERO_RETURN:
                //APN_SET_ERROR(error, APN_ERR_CONNECTION_CLOSED | APN_ERR_CLASS_INTERNAL, "server closed connection (SSL_ERROR_ZERO_RETURN)");
                return 0;
            default:
                APN_SET_ERROR(error, APN_ERR_SSL_READ_FAILED | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SSL_READ_FAILED]);
                return -1;
        }
    }

    return read;
}

uint8_t apn_feedback(const apn_ctx_ref ctx, char ***tokens_array, uint32_t *tokens_array_count, apn_error_ref *error) {
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

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (!ctx->ssl || !ctx->feedback) {
        APN_SET_ERROR(error, APN_ERR_NOT_CONNECTED_FEEDBACK | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_NOT_CONNECTED_FEEDBACK]);
        APN_RETURN_ERROR;
    }

    if (!ctx->certificate_file) {
        APN_SET_ERROR(error, APN_ERR_CERTIFICATE_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CERTIFICATE_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    if (!ctx->private_key_file) {
        APN_SET_ERROR(error, APN_ERR_PRIVATE_KEY_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PRIVATE_KEY_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &read_set);

        select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);
        if (select_returned < 0) {
            if (errno == EINTR) {
                continue;
            }
            APN_SET_ERROR(error, APN_ERR_SELECT | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SELECT]);
            APN_RETURN_ERROR;
        }

        if (select_returned == 0) {
            /* select() timed out */
            break;
        }

        if (FD_ISSET(ctx->sock, &read_set)) {
            bytes_read = __ssl_read(ctx, buffer, sizeof (buffer), error);

            if (bytes_read < 0) {
                APN_RETURN_ERROR;
            }

            if (bytes_read > 0) {
                buffer_ref += sizeof (uint32_t);
                memcpy(&token_length, buffer_ref, sizeof (token_length));
                buffer_ref += sizeof (token_length);
                token_length = ntohs(token_length);

                memcpy(&binary_token, buffer_ref, sizeof (binary_token));

                token_hex = __token_binary_to_hex(binary_token);
                if (token_hex == NULL) {
                    APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                    APN_RETURN_ERROR;
                }

                tokens = (char **) __apn_realloc(tokens, (tokens_count + 1) * sizeof (char *));
                if (!tokens) {
                    APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                    APN_RETURN_ERROR;
                }
                tokens[tokens_count] = token_hex;
                tokens_count++;
            }
            break;
        }
    }

    if (tokens_array != NULL && tokens_count > 0) {
        *tokens_array = tokens;
    }

    if (tokens_array_count != NULL) {
        *tokens_array_count = tokens_count;
    }

    APN_RETURN_SUCCESS;
}

uint8_t apn_send(const apn_ctx_ref ctx, apn_payload_ctx_ref payload, apn_error_ref *error) {
    char *json = NULL;
    size_t json_size = 0; /* Payload size */

    size_t message_size = 0;
    uint8_t *message = NULL;

    uint8_t **tokens = NULL;
    uint8_t *token = NULL;
    char apple_error[6];
    int bytes_read = 0; /* Number of bytes read */
    int bytes_written = 0; /* Number of bytes written */
    uint8_t has_error = 0;
    uint32_t tokens_count = 0;
    uint32_t invalid_id = 0;
    fd_set write_set, read_set;
    int select_returned = 0;
    uint32_t i = 0;
    struct timeval timeout = {10, 0};

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (!ctx->ssl || ctx->feedback) {
        APN_SET_ERROR(error, APN_ERR_NOT_CONNECTED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_NOT_CONNECTED]);
        APN_RETURN_ERROR;
    }

    if (!ctx->certificate_file) {
        APN_SET_ERROR(error, APN_ERR_CERTIFICATE_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CERTIFICATE_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }
    if (!ctx->private_key_file) {
        APN_SET_ERROR(error, APN_ERR_PRIVATE_KEY_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PRIVATE_KEY_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    if (!payload) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    if (payload->__tokens_count > 0 && payload->tokens != NULL) {
        tokens = payload->tokens;
        tokens_count = payload->__tokens_count;
    } else if (ctx->__tokens_count > 0 && ctx->tokens != NULL) {
        tokens = ctx->tokens;
        tokens_count = ctx->__tokens_count;
    }

    if (tokens_count == 0) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_IS_NOT_SET | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_IS_NOT_SET]);
        APN_RETURN_ERROR;
    }

    json = __apn_create_json_document_from_payload(payload, error);

    if (!json) {
        APN_RETURN_ERROR;
    }

    json_size = strlen(json);

    if (json_size > APN_PAYLOAD_MAX_SIZE) {
        APN_SET_ERROR(error, APN_ERR_INVALID_PAYLOAD_SIZE | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_INVALID_PAYLOAD_SIZE]);
        free(json);
        APN_RETURN_ERROR;
    }

    while (1) {
        if (i == tokens_count) {
            break;
        }
        token = tokens[i];
        message_size = __apn_create_binary_message(token, json, i, payload->expiry, payload->priority, &message, error);
        if (message_size == 0) {
            free(json);
            APN_RETURN_ERROR;
        }

        FD_ZERO(&write_set);
        FD_ZERO(&read_set);
        FD_SET(ctx->sock, &write_set);
        FD_SET(ctx->sock, &read_set);

        select_returned = select(ctx->sock + 1, &read_set, &write_set, NULL, &timeout);

        if (select_returned <= 0) {
            if (errno == EINTR) {
                continue;
            }
            APN_SET_ERROR(error, APN_ERR_SELECT | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SELECT]);
            APN_RETURN_ERROR;
        }

        if (FD_ISSET(ctx->sock, &read_set)) {
            bytes_read = __ssl_read(ctx, apple_error, sizeof (apple_error), error);
            if (bytes_read < 0) {
                if (message) {
                    free(message);
                }
                free(json);
                APN_RETURN_ERROR;
            }
            free(message);
            has_error = 1;
            break;
        }

        if (FD_ISSET(ctx->sock, &write_set)) {
            bytes_written = __ssl_write(ctx, message, message_size, error);
            free(message);
            if (bytes_written <= 0) {
                free(json);
                APN_RETURN_ERROR;
            }
            i++;
        }
    }

    free(json);

    if (!has_error) {
        timeout.tv_sec = 1;
        for (;;) {
            FD_ZERO(&read_set);
            FD_SET(ctx->sock, &read_set);

            select_returned = select(ctx->sock + 1, &read_set, NULL, NULL, &timeout);

            if (select_returned < 0) {
                if (errno == EINTR) {
                    continue;
                }

                APN_SET_ERROR(error, APN_ERR_SELECT | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_SELECT]);
                APN_RETURN_ERROR;
            }

            if (select_returned == 0) {
                /* select() timed out */
                break;
            }

            if (FD_ISSET(ctx->sock, &read_set)) {
                bytes_read = __ssl_read(ctx, apple_error, sizeof (apple_error), error);
                if (bytes_read > 0) {
                    has_error = 1;
                } else {
                    APN_RETURN_ERROR;
                }
                break;
            }
        }
    }

    if (has_error) {
        __apn_parse_apns_error(apple_error, &invalid_id, error);
        if (apn_error_code(*error) == APN_ERR_TOKEN_INVALID) {
            (*error)->invalid_token = __token_binary_to_hex(tokens[invalid_id]);
        }
        APN_RETURN_ERROR;
    }

    APN_RETURN_SUCCESS;
}

uint8_t apn_init(apn_ctx_ref *ctx, const char *cert, const char *private_key, const char *private_key_pass, apn_error_ref *error) {
    apn_ctx_ref _ctx = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "invalid argument ctx. Expected pointer to pointer to apn_ctx struct, passed NULL");
        APN_RETURN_ERROR;
    }

    *ctx = NULL;
    _ctx = malloc(sizeof (apn_ctx));

    if (!_ctx) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    _ctx->sock = -1;
    _ctx->ssl = NULL;
    _ctx->__tokens_count = 0;
    _ctx->certificate_file = NULL;
    _ctx->private_key_file = NULL;
    _ctx->tokens = NULL;
    _ctx->feedback = 0;
    _ctx->private_key_pass = NULL;
    _ctx->mode = APN_MODE_PRODUCTION;

    if (cert && strlen(cert) > 0) {
        if (apn_set_certificate(_ctx, cert, error) != APN_SUCCESS) {
            apn_free(&_ctx);
            APN_RETURN_ERROR;
        }
    }

    if (private_key && strlen(private_key) > 0) {
        if (private_key_pass && strlen(private_key_pass) > 0) {
            if (apn_set_private_key(_ctx, private_key, private_key_pass, error) != APN_SUCCESS) {
                apn_free(&_ctx);
                APN_RETURN_ERROR;
            }
        } else {
            if (apn_set_private_key(_ctx, private_key, NULL, error) != APN_SUCCESS) {
                apn_free(&_ctx);
                APN_RETURN_ERROR;
            }
        }
    }

    if (!__ssl_lib_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        __ssl_lib_initialized = 1;
    }

    *ctx = _ctx;
    APN_RETURN_SUCCESS;
}

#if defined(__APPLE__) && defined(__MACH__)
DIAGNOSTIC_ON(deprecated-declarations)
#endif

apn_ctx_ref apn_copy(const apn_ctx_ref ctx, apn_error_ref *error) {
    apn_ctx_ref _ctx = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (apn_init(&_ctx, NULL, NULL, NULL, error)) {
        return NULL;
    }

    if (ctx->certificate_file) {
        if ((_ctx->certificate_file = apn_strndup(ctx->certificate_file, strlen(ctx->certificate_file))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
    }

    if (ctx->private_key_file) {
        if ((_ctx->private_key_file = apn_strndup(ctx->private_key_file, strlen(ctx->private_key_file))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
    }

    if (ctx->private_key_pass) {
        if ((_ctx->private_key_pass = apn_strndup(ctx->private_key_pass, strlen(ctx->private_key_pass))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
    }

    _ctx->tokens = __apn_tokens_array_copy(ctx->tokens, ctx->__tokens_count, error);
    if (_ctx->tokens == NULL && __apn_is_error((*error))) {
        apn_free(&_ctx);
        return NULL;
    }
    _ctx->__tokens_count = ctx->__tokens_count;

    _ctx->feedback = ctx->feedback;
    _ctx->mode = ctx->mode;

    return _ctx;
}

void apn_free(apn_ctx_ref *ctx) {
    apn_ctx_ref _ctx = NULL;

    if (!ctx || !(*ctx)) {
        return;
    }

    _ctx = *ctx;

    if (_ctx) {
        apn_close(_ctx);
    }

    if (_ctx->certificate_file) {
        free(_ctx->certificate_file);
    }

    if (_ctx->private_key_file) {
        free(_ctx->private_key_file);
    }

    if (_ctx->private_key_pass) {
        free(_ctx->private_key_pass);
    }

    __apn_tokens_array_free(_ctx->tokens, _ctx->__tokens_count);

    free(_ctx);
    *ctx = NULL;
}

uint8_t apn_connect(const apn_ctx_ref ctx, apn_error_ref *error) {
    struct __apn_appl_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_appl_servers[0];
    } else {
        server = __apn_appl_servers[1];
    }

    return __apn_connect(ctx, server, error);
}

uint8_t apn_feedback_connect(const apn_ctx_ref ctx, apn_error_ref *error) {
    struct __apn_appl_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_appl_servers[2];
    } else {
        server = __apn_appl_servers[3];
    }

    ctx->feedback = 1;
    return __apn_connect(ctx, server, error);
}

uint8_t apn_set_certificate(apn_ctx_ref ctx, const char *cert, apn_error_ref *error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (ctx->certificate_file) {
        apn_strfree(&ctx->certificate_file);
    }
    if (cert && strlen(cert) > 0) {
        if ((ctx->certificate_file = apn_strndup(cert, strlen(cert))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }

    APN_RETURN_SUCCESS;
}

uint8_t apn_set_private_key(apn_ctx_ref ctx, const char *key, const char *pass, apn_error_ref *error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (ctx->private_key_file) {
        apn_strfree(&ctx->private_key_file);
    }
    if (key && strlen(key) > 0) {
        if ((ctx->private_key_file = apn_strndup(key, strlen(key))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    if (ctx->private_key_pass) {
        apn_strfree(&ctx->private_key_pass);
    }
    if (pass && strlen(pass) > 0) {
        if ((ctx->private_key_pass = apn_strndup(pass, strlen(pass))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_set_mode(apn_ctx_ref ctx, uint8_t mode, apn_error_ref *error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (mode == APN_MODE_SANDBOX) {
        ctx->mode = APN_MODE_SANDBOX;
    } else {
        ctx->mode = APN_MODE_PRODUCTION;
    }

    APN_RETURN_SUCCESS;
}

uint8_t apn_add_token(apn_ctx_ref ctx, const char *token, apn_error_ref *error) {
    uint8_t *binary_token = NULL;
    uint8_t **tokens = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (ctx->__tokens_count >= UINT32_MAX) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_TOO_MANY | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_TOO_MANY]);
        APN_RETURN_ERROR;
    }

    if (!token || strlen(token) == 0) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "invalid value of token. Expected string, passed NULL");
        APN_RETURN_ERROR;
    }

    if (!__apn_check_hex_token(token)) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_INVALID | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_INVALID]);
        APN_RETURN_ERROR;
    }

    tokens = (uint8_t **)__apn_realloc(ctx->tokens, (ctx->__tokens_count + 1) * sizeof(uint8_t *));
    if (!tokens) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }
    ctx->tokens = tokens;

    if (!(binary_token = __token_hex_to_binary(token))) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    ctx->tokens[ctx->__tokens_count] = binary_token;
    ctx->__tokens_count++;

    APN_RETURN_SUCCESS;
}

const char *apn_certificate(const apn_ctx_ref ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }
    if (ctx->certificate_file) {
        ret_value = ctx->certificate_file;
    }
    return ret_value;
}

const char *apn_private_key(const apn_ctx_ref ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (ctx->private_key_file) {
        ret_value = ctx->private_key_file;
    }
    return ret_value;
}

const char *apn_private_key_pass(const apn_ctx_ref ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (ctx->private_key_pass) {
        ret_value = ctx->private_key_pass;
    }
    return ret_value;
}

int8_t apn_mode(apn_ctx_ref ctx, apn_error_ref *error) {
    if (!ctx) {
        APN_SET_ERROR(error, APN_ERR_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_CTX_NOT_INITIALIZED]);
        return -1;
    }

    return ctx->mode;
}

int64_t apn_payload_expiry(apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return -1;
    }

    return payload_ctx->expiry;
}

apn_payload_ctx_ref apn_payload_copy(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    apn_payload_ctx_ref _payload = NULL;
    uint16_t i = 0;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (apn_payload_init(&_payload, error)) {
        return NULL;
    }

    _payload->badge = payload_ctx->badge;

    if (payload_ctx->sound) {
        _payload->sound = apn_strndup(payload_ctx->sound, strlen(payload_ctx->sound));
        if (_payload->sound == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
    }

    if (payload_ctx->alert) {
        if (payload_ctx->alert->action_loc_key) {
            if ((_payload->alert->action_loc_key = apn_strndup(payload_ctx->alert->action_loc_key, strlen(payload_ctx->alert->action_loc_key))) == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }
        }
        if (payload_ctx->alert->body) {
            if ((_payload->alert->body = apn_strndup(payload_ctx->alert->body, strlen(payload_ctx->alert->body))) == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }
        }
        if (payload_ctx->alert->launch_image) {

            if ((_payload->alert->launch_image = apn_strndup(payload_ctx->alert->launch_image, strlen(payload_ctx->alert->launch_image))) == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }
        }
        if (payload_ctx->alert->loc_key) {
            if ((_payload->alert->loc_key = apn_strndup(payload_ctx->alert->loc_key, strlen(payload_ctx->alert->loc_key))) == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }
        }
        if (payload_ctx->alert->__loc_args_count > 0 && payload_ctx->alert->loc_args) {
            _payload->alert->loc_args = (char **) malloc((payload_ctx->alert->__loc_args_count) * sizeof (char *));
            if (!_payload->alert->loc_args) {
                apn_payload_free(&_payload);
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }

            for (i = 0; i < payload_ctx->alert->__loc_args_count; i++) {
                _payload->alert->loc_args[i] = apn_strndup(payload_ctx->alert->loc_args[i], strlen(payload_ctx->alert->loc_args[i]));

                if (_payload->alert->loc_args[i] == NULL) {
                    APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                    return NULL;
                }

                _payload->alert->__loc_args_count++;
            }
        }
    }

    _payload->expiry = payload_ctx->expiry;
    _payload->priority = payload_ctx->priority;

    _payload->tokens = __apn_tokens_array_copy(payload_ctx->tokens, payload_ctx->__tokens_count, error);
    if (_payload->tokens == NULL && __apn_is_error((*error))) {
        apn_payload_free(&_payload);
        return NULL;
    }
    _payload->__tokens_count = payload_ctx->__tokens_count;

    if (payload_ctx->__custom_properties_count > 0 && payload_ctx->custom_properties) {
        uint8_t i = 0;

        _payload->custom_properties = (apn_payload_custom_property_ref *) malloc(payload_ctx->__custom_properties_count * sizeof (apn_payload_custom_property_ref));
        if (!_payload->custom_properties) {
            apn_payload_free(&_payload);
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            return NULL;
        }
        _payload->__custom_properties_count = 0;
        for (i = 0; i < payload_ctx->__custom_properties_count; i++) {
            apn_payload_custom_property_ref property = (apn_payload_custom_property_ref) malloc(sizeof (apn_payload_custom_property));
            if (!property) {
                apn_payload_free(&_payload);
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }

            property->value_type = (*(payload_ctx->custom_properties + i))->value_type;
            property->key = apn_strndup((*(payload_ctx->custom_properties + i))->key, strlen((*(payload_ctx->custom_properties + i))->key));

            if (property->key == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                return NULL;
            }

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
                    if (property->value.string_value.value == NULL) {
                        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                        return NULL;
                    }
                    property->value.string_value.length = (*(payload_ctx->custom_properties + i))->value.string_value.length;
                }
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_ARRAY:
                {
                    uint8_t j = 0;
                    property->value.array_value.array = (char **) malloc((*(payload_ctx->custom_properties + i))->value.array_value.array_size * sizeof (char *));
                    if (!property->value.array_value.array) {
                        apn_payload_free(&_payload);
                        __apn_payload_custom_property_free(&property);
                        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                        return NULL;
                    }
                    property->value.array_value.array_size = 0;
                    for (j = 0; j < (*(payload_ctx->custom_properties + i))->value.array_value.array_size; j++) {
                        char *array_item = apn_strndup((*(payload_ctx->custom_properties + i))->value.array_value.array[j], strlen((*(payload_ctx->custom_properties + i))->value.array_value.array[j]));

                        if (array_item == NULL) {
                            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                            return NULL;
                        }

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

uint8_t apn_payload_init(apn_payload_ctx_ref *payload_ctx, apn_error_ref *error) {
    apn_payload_ctx_ref _payload = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "invalid payload_ctx. Expected pointer to tointer to apn_payload_ctx structure, passed NULL");
        APN_RETURN_ERROR;
    }
    *payload_ctx = NULL;
    _payload = malloc(sizeof (apn_payload_ctx));
    if (!_payload) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if (__apn_payload_alert_init(&_payload->alert, error)) {
        free(_payload);
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    _payload->badge = -1;
    _payload->sound = NULL;
    _payload->__custom_properties_count = 0;
    _payload->custom_properties = NULL;
    _payload->__tokens_count = 0;
    _payload->tokens = NULL;
    _payload->expiry = 0;
    _payload->content_available = 0;
    _payload->priority = APN_NOTIFICATION_PRIORITY_DEFAULT;

    *payload_ctx = _payload;

    APN_RETURN_SUCCESS;
}

void apn_payload_free(apn_payload_ctx_ref *payload_ctx) {
    apn_payload_ctx_ref _payload_ctx = NULL;
    if (!payload_ctx || !(*payload_ctx)) {
        return;
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

    __apn_tokens_array_free(_payload_ctx->tokens, _payload_ctx->__tokens_count);

    free(_payload_ctx);
    *payload_ctx = NULL;
}

/* Setters */

uint8_t apn_payload_set_priority(apn_payload_ctx_ref payload_ctx, apn_notification_priority priority, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    payload_ctx->priority = priority;
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_expiry(apn_payload_ctx_ref payload_ctx, uint32_t expiry, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    payload_ctx->expiry = expiry;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_token(apn_payload_ctx_ref payload_ctx, const char *token, apn_error_ref *error) {
    uint8_t *binary_token = NULL;
    uint8_t **tokens = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }

    if (payload_ctx->__tokens_count >= UINT32_MAX) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_TOO_MANY | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_TOO_MANY]);
        APN_RETURN_ERROR;
    }

    if (!token) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "invalid value of token. Expected string, passed NULL");
        APN_RETURN_ERROR;
    }

    if (!__apn_check_hex_token(token)) {
        APN_SET_ERROR(error, APN_ERR_TOKEN_INVALID | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_TOKEN_INVALID]);
        APN_RETURN_ERROR;
    }

    tokens = (uint8_t **) __apn_realloc(payload_ctx->tokens, (payload_ctx->__tokens_count + 1) * sizeof(uint8_t *));
    if (!tokens) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }
    payload_ctx->tokens = tokens;

    if (!(binary_token = __token_hex_to_binary(token))) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    payload_ctx->tokens[payload_ctx->__tokens_count] = binary_token;
    payload_ctx->__tokens_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_badge(apn_payload_ctx_ref payload_ctx, int32_t badge, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (badge < 0 || badge > UINT16_MAX) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_BADGE_INVALID_VALUE | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_BADGE_INVALID_VALUE]);
        APN_RETURN_ERROR;
    }

    payload_ctx->badge = badge;
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_sound(apn_payload_ctx_ref payload_ctx, const char *sound, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->sound) {
        apn_strfree(&payload_ctx->sound);
    }
    if (sound && strlen(sound)) {
        if ((payload_ctx->sound = apn_strndup(sound, strlen(sound))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_content_available(apn_payload_ctx_ref payload_ctx, uint8_t content_available, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    payload_ctx->content_available = (content_available == 1) ? 1 : 0;
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_body(apn_payload_ctx_ref payload_ctx, const char *body, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->body) {
        apn_strfree(&payload_ctx->alert->body);
    }
    if (body && strlen(body) > 0) {
        if (!apn_string_is_utf8(body)) {
            APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "body contains non-utf8 symbols");
            APN_RETURN_ERROR;
        }

        if ((payload_ctx->alert->body = apn_strndup(body, strlen(body))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_localized_action_key(apn_payload_ctx_ref payload_ctx, const char *key, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->action_loc_key) {
        apn_strfree(&payload_ctx->alert->action_loc_key);
    }
    if (key && strlen(key) > 0) {
        if ((payload_ctx->alert->action_loc_key = apn_strndup(key, strlen(key))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_launch_image(apn_payload_ctx_ref payload_ctx, const char *image, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->action_loc_key) {
        apn_strfree(&payload_ctx->alert->action_loc_key);
    }
    if (image && strlen(image)) {
        if ((payload_ctx->alert->launch_image = apn_strndup(image, strlen(image))) == NULL) {
            APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_set_localized_key(apn_payload_ctx_ref payload_ctx, const char *key, char **args, uint16_t args_count, apn_error_ref *error) {
    char *arg = NULL;
    uint16_t i = 0;
    uint16_t args_i = 0;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        APN_RETURN_ERROR;
    }
    if (payload_ctx->alert->loc_key) {
        apn_strfree(&payload_ctx->alert->loc_key);

        if (payload_ctx->alert->loc_args && payload_ctx->alert->__loc_args_count) {
            for (i = 0; i < payload_ctx->alert->__loc_args_count; i++) {
                arg = *(payload_ctx->alert->loc_args + i);
                free(arg);
            }
            free(payload_ctx->alert->loc_args);
            payload_ctx->alert->loc_args = NULL;
        }
    }

    if (key && strlen(key) > 0) {
        payload_ctx->alert->loc_key = apn_strndup(key, strlen(key));

        if (args && args_count > 0) {
            payload_ctx->alert->loc_args = (char **) malloc((args_count) * sizeof (char *));

            if (!payload_ctx->alert->loc_args) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                APN_RETURN_ERROR;
            }

            for (args_i = 0; args_i < args_count; args_i++) {
                if ((payload_ctx->alert->loc_args[args_i] = apn_strndup(args[args_i], strlen(args[args_i]))) == NULL) {
                    APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                    APN_RETURN_ERROR;
                }

                payload_ctx->alert->__loc_args_count++;
            }
        }
    }
    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_integer(apn_payload_ctx_ref payload_ctx, const char *property_key,
        int64_t property_value,
        apn_error_ref *error) {

    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NUMERIC;
    property->value.numeric_value = property_value;
    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_double(apn_payload_ctx_ref payload_ctx, const char *property_key,
        double property_value,
        apn_error_ref *error) {

    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_DOUBLE;

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value.double_value = property_value;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_bool(apn_payload_ctx_ref payload_ctx, const char *property_key,
        unsigned char property_value,
        apn_error_ref *error) {

    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_BOOL;

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value.bool_value = (property_value == 0) ? 0 : 1;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_null(apn_payload_ctx_ref payload_ctx, const char *property_key, apn_error_ref *error) {
    apn_payload_custom_property_ref property = NULL;

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));

    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NULL;

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value.string_value.value = NULL;
    property->value.string_value.length = 0;

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_string(apn_payload_ctx_ref payload_ctx, const char *property_key,
        const char *property_value,
        apn_error_ref *error) {

    apn_payload_custom_property_ref property = NULL;

    if (!property_value) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (!apn_string_is_utf8(property_value)) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "value contains non-utf8 symbols");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));
    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_STRING;

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if ((property->value.string_value.value = apn_strndup(property_value, strlen(property_value))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value.string_value.length = strlen(property_value);

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

uint8_t apn_payload_add_custom_property_array(apn_payload_ctx_ref payload_ctx, const char *property_key,
        const char **array, uint8_t array_size,
        apn_error_ref *error) {

    char **_array = NULL;
    apn_payload_custom_property_ref property = NULL;
    uint8_t i = 0;
    uint8_t _array_size = 0;

    if (!array) {
        APN_SET_ERROR(error, APN_ERR_INVALID_ARGUMENT | APN_ERR_CLASS_USER, "value of custom property is NULL");
        APN_RETURN_ERROR;
    }

    if (__apn_payload_custom_property_init(payload_ctx, property_key, error)) {
        APN_RETURN_ERROR;
    }

    property = malloc(sizeof (apn_payload_custom_property));
    if (!property) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_ARRAY;

    if ((property->key = apn_strndup(property_key, strlen(property_key))) == NULL) {
        APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
        APN_RETURN_ERROR;
    }

    if (array_size) {
        _array = (char **) malloc(sizeof (char *) * array_size);
        if (!_array) {
            APN_SET_ERROR(error, APN_ERR_NOMEM, __apn_errors[APN_ERR_NOMEM]);
            APN_RETURN_ERROR;
        }

        _array_size = (array_size > 6) ? 6 : array_size;
        for (i = 0; i < _array_size; i++) {
            if ((_array[i] = apn_strndup(_array[i], strlen(_array[i]))) == NULL) {
                APN_SET_ERROR(error, APN_ERR_NOMEM | APN_ERR_CLASS_INTERNAL, __apn_errors[APN_ERR_NOMEM]);
                APN_RETURN_ERROR;
            }
        }
        property->value.array_value.array = _array;
        property->value.array_value.array_size = _array_size;
    }

    payload_ctx->custom_properties[payload_ctx->__custom_properties_count] = property;
    payload_ctx->__custom_properties_count++;

    APN_RETURN_SUCCESS;
}

/** Getters */

int8_t apn_payload_content_available(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return -1;
    }
    return payload_ctx->content_available;
}

int32_t apn_payload_badge(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return -1;
    }
    return payload_ctx->badge;
}

const char *apn_payload_sound(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->sound) {
        ret_value = payload_ctx->sound;
    }
    return ret_value;
}

const char *apn_payload_launch_image(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->launch_image) {
        ret_value = payload_ctx->alert->launch_image;
    }
    return ret_value;
}

const char *apn_payload_localized_action_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->action_loc_key) {
        ret_value = payload_ctx->alert->action_loc_key;
    }
    return ret_value;
}

const char *apn_payload_body(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->body) {
        ret_value = payload_ctx->alert->body;
    }
    return ret_value;
}

const char *apn_payload_localized_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) {
    char *ret_value = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return NULL;
    }

    if (payload_ctx->alert->loc_key) {
        ret_value = payload_ctx->alert->loc_key;
    }
    return ret_value;
}

uint16_t apn_payload_localized_key_args(const apn_payload_ctx_ref payload_ctx, char ***args, apn_error_ref *error) {
    *args = NULL;

    if (!payload_ctx) {
        APN_SET_ERROR(error, APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED | APN_ERR_CLASS_USER, __apn_errors[APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED]);
        return 0;
    }
    if (payload_ctx->alert->loc_args && payload_ctx->alert->__loc_args_count) {
        *args = payload_ctx->alert->loc_args;
        return payload_ctx->alert->__loc_args_count;
    }
    return 0;
}

uint32_t apn_version() {
    return APN_VERSION_NUM;
}

const char * apn_version_string() {
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

void apn_error_free(apn_error_ref *error) {
    apn_error_ref _error = NULL;
    if (error) {
        _error = *error;
        if (!_error) {
            return;
        }
        if (_error->message) {
            free(_error->message);
        }
        if (_error->invalid_token) {
            free(_error->invalid_token);
        }
        free(_error);
        *error = NULL;
    }
}

const char *apn_error_message(const apn_error_ref error) {
    if (!error) {
        return NULL;
    }
    return error->message;
}

const char *apn_error_invalid_token(const apn_error_ref error) {
    if (!error) {
        return NULL;
    }
    return error->invalid_token;
}

int32_t apn_error_code(const apn_error_ref error) {
    if (!error) {
        return 0;
    }
    return error->code;
}
