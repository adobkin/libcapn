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

#ifndef __APN_H__
#define __APN_H__

#include "platform.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif
    
#define APN_SUCCESS 0
#define APN_ERROR 1
    
enum __apn_mode {
    APN_MODE_PRODUCTION = 0,
    APN_MODE_SANDBOX = 1
};

/**
 * Maximum size of error message
 * @ingroup errors
 */
#define APN_ERROR_MESSAGE_MAX_SIZE 128
  
/**
 * @ingroup errors
 */
enum __apn_errors_class {
    APN_ERR_CLASS_USER = 0x20000000,
    APN_ERR_CLASS_INTERNAL = 0x40000000
};

/**
 * @ingroup errors
 */
#define APN_ERR_IS_INTERNAL(__errcode) (__errcode & APN_ERR_CLASS_INTERNAL)

/**
 * @ingroup errors
 */
#define APN_ERR_IS_USER(__errcode) (__errcode & APN_ERR_CLASS_USER)

/**
 * @ingroup errors
 */
#define APN_ERR_CODE_WITHOUT_CLASS(__errcode) (__errcode & ~(APN_ERR_CLASS_USER | APN_ERR_CLASS_INTERNAL))

/**
 * Error codes
 * 
 * @ingroup errors
 */
enum __apn_errors {
    /** No free memory */
    APN_ERR_NOMEM,
    
    /** Connection contex is not initialized */
    APN_ERR_CTX_NOT_INITIALIZED,
    
    /** No opened connection to Apple Push Notification Service */
    APN_ERR_NOT_CONNECTED,
    
    /** No opened connection to Apple Push Feedback Service */
    APN_ERR_NOT_CONNECTED_FEEDBACK,
    
    APN_ERR_INVALID_ARGUMENT,  
    
    /** Path to SSL certificate file which is used to set up a secure connection is not set */
    APN_ERR_CERTIFICATE_IS_NOT_SET,
    
    /** Path to private key file which is used to set up a secure connection is not set */
    APN_ERR_PRIVATE_KEY_IS_NOT_SET,
    
    /** Notification payload is not set */
    APN_ERR_PAYLOAD_IS_NOT_SET,
    
    /** Device token is not set */
    APN_ERR_TOKEN_IS_NOT_SET,
    
    /** Invalid device token */
    APN_ERR_TOKEN_INVALID,
    
    /** Added too many device tokens */
    APN_ERR_TOKEN_TOO_MANY,
    
    /** Unable to use specified SSL certificate to set up a secure connection */
    APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE, 
    
    /** Unable to use specified private key to set up a secure connection */
    APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY, 
        
    /** Unable to resolve host */
    APN_ERR_COULD_NOT_RESOLVE_HOST,
    
    /** Unable to create TCP socket */
    APN_ERR_COULD_NOT_CREATE_SOCKET,
    
    /** Could not initialize connection */
    APN_ERR_COULD_NOT_INITIALIZE_CONNECTION,
    
    /** Could not initialize SSL connection */
    APN_ERR_COULD_NOT_INITIALIZE_SSL_CONNECTION,

    /** SSL_write failed */
    APN_ERR_SSL_WRITE_FAILED,
    
    /** SSL_read failed */
    APN_ERR_SSL_READ_FAILED,
    
    /** Invalid size of notification payload */
    APN_ERR_INVALID_PAYLOAD_SIZE,
    
    /** Payload notification contex is not initialized */
    APN_ERR_PAYLOAD_CTX_NOT_INITIALIZED,
    
    /** Incorrect number to display as the badge on application icon */
    APN_ERR_PAYLOAD_BADGE_INVALID_VALUE,
    
    /** Too many custom properties. Max: 5 */
    APN_ERR_PAYLOAD_TOO_MANY_CUSTOM_PROPERTIES,
    
    /** Specified custom property key is already used */
    APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED,
    
    /** Could not create json document */
    APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT,
    
    /** Alert message text is not set */
    APN_ERR_PAYLOAD_ALERT_IS_NOT_SET,
        
    /** Non-UTF8 symbols detected in a string */
    APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS,
    
    /** Processing error */
    APN_ERR_PROCESSING_ERROR,
    
    /** Unknown error */
    APN_ERR_UNKNOWN,    
    
    /** Don't use */
    APN_ERR_COUNT 
};

/**
 * @ingroup errors
 */
typedef enum __apn_errors apn_errors;

/**
 * Uses to pass error information to the caller
 * 
 * @ingroup errors
 */
struct __apn_error {
    /** 
     * Error code 
     * @sa apn_errors
     */
    
    uint16_t code;
    
    /** 
     * Error message or NULL if the message 
     * is not available 
     */
    char *message;
    
    /**
     * Invalid device token in HEX format.
     * Field has value only when code == APN_ERR_TOKEN_INVALID, otherwise NULL
     */
    char *invalid_token;
};

/**
 * @ingroup errors
 */
typedef struct __apn_error* apn_error_ref;
/**
 * @ingroup errors
 */
typedef struct __apn_error apn_error;

struct __apn_binary_token {
    char *token;
    uint16_t length;
};

typedef struct __apn_binary_token apn_binary_token;

typedef struct __apn_binary_token *apn_binary_token_ref;

/**
 * @ingroup payload
 * Types of custom property of notification payload
 */
enum __apn_payload_custom_property_types {
    APN_CUSTOM_PROPERTY_TYPE_BOOL,
    APN_CUSTOM_PROPERTY_TYPE_NUMERIC,
    APN_CUSTOM_PROPERTY_TYPE_ARRAY,
    APN_CUSTOM_PROPERTY_TYPE_STRING,
    APN_CUSTOM_PROPERTY_TYPE_DOUBLE,
    APN_CUSTOM_PROPERTY_TYPE_NULL
};

/**
 * @ingroup payload
 */
union __apn_payload_custom_value {
    int64_t numeric_value;					
    double double_value;
    struct {
        char *value;
        size_t length;
    } string_value;
    unsigned char bool_value;
    struct {
        char **array;
        uint8_t array_size;
    } array_value;
};

/** 
 * Custom property
 * 
 * Uses to store custom notification property
 * 
 * @ingroup payload
 */
struct __apn_payload_custom_property {
    /** Property name */
    char *key;
    
    /** Property value */
    union __apn_payload_custom_value value;
    
    /** Property value type */
    enum __apn_payload_custom_property_types value_type;
};

/**
 * @ingroup payload
 */
typedef struct __apn_payload_custom_property  apn_payload_custom_property;
/**
 * @ingroup payload
 */
typedef struct __apn_payload_custom_property * apn_payload_custom_property_ref;

 
/** 
 * Payload alert
 * 
 * Uses to store payload alert
 * 
 * @ingroup payload
 */
struct __apn_payload_alert {
    /** Text of the alert message */
    char *body;
    
    char *action_loc_key;
    char *loc_key;
    char **loc_args;
    uint16_t __loc_args_count;
    
    /** Filename of an image file in the application bundle */
    char *launch_image;
};

/**
 * @ingroup payload
 */
typedef struct __apn_payload_alert * apn_payload_alert_ref;
/**
 * @ingroup payload
 */
typedef struct __apn_payload_alert  apn_payload_alert;

/** 
 * Notification Payload
 * 
 * Uses to store notification payload
 * 
 * @ingroup payload
 */
struct __apn_payload {
    /** Alert */
    struct __apn_payload_alert *alert;
    
    /** Name of a sound file in the application bundle */
    char *sound;

    /** 
     * Target devices tokens
     *   
     * The device token is an opaque identifier of a device that Apple Push Notification Service 
     * gives to the device when it first connects with it. Device token is used to identify
     * a target device which should receive the notification
     */
    apn_binary_token_ref *tokens;

    uint32_t expiry;

    /**
     * Device tokens count
     */
    uint32_t __tokens_count;
    
    /** Number to display as a badge on application icon */
    int32_t badge;
    
    /** Custom payload properties*/
    struct __apn_payload_custom_property **custom_properties;
    
    /** Custom properties number */
    uint8_t __custom_properties_count;
};

/**
 * @ingroup payload
 */
typedef struct __apn_payload * apn_payload_ctx_ref;
/**
 * @ingroup payload
 */
typedef struct __apn_payload  apn_payload_ctx;

/** 
 * Connection context
 * 
 * Uses to store connection data for Apple Push Notification/Feedback Service
 * 
 * @ingroup apn
 * @ingroup feedback
 */
struct __apn_ctx {
    SOCKET sock;
    
    /**
     * Pointer to `SSL` structure. Is used to hold data 
     * for a TLS/SSL connection
     */
    SSL *ssl;
    
    /**
     * Device tokens count
     */
    uint32_t __tokens_count;
    
    /** 
     * Path to an SSL certificate file
     * 
     * The SSL certificate used establish a secure connection
     */
    char *certificate_file;
    
    /** 
     * Path to private key file
     * 
     * The private key used to establish secure connection
     */
    char *private_key_file;
    
    /** 
     * Target devices tokens
     *   
     * The device token is an opaque identifier of a device that Apple Push Notification Service 
     * gives to the device when it first connects with it. Device token is used to identify
     * a target device which should receive the notification
     */
    apn_binary_token_ref *tokens;
    
    char *private_key_pass;
    
    uint8_t feedback;
    
    uint8_t mode;
    
};

/**
 * @ingroup apn
 * @ingroup feedback
 */
typedef struct __apn_ctx * apn_ctx_ref;

/**
 * @ingroup apn
 * @ingroup feedback
 */
typedef struct __apn_ctx  apn_ctx;


/**
 * Returns a 3-byte hexadecimal representation of the 
 * library version
 *
 * E.g. 0x010000 for version 1.0.0, 0x010100 for version 1.1.0 
 * This is useful in numeric comparisions:
 * 
 * @ingroup version
 *
 * @code {.c}
 * if(apn_version() <= 0x010100) {
 *      ...  
 * }
 * @endcode
 * 
 * @sa ::APN_VERSION_NUM
 * @sa ::APN_VERSION_STRING
 * @sa apn_version_string()
 *
 * @return hexadecimal 
 */
__apn_export__ uint apn_version();

/**
 * Returns a string representation of the 
 * version library
 *
 * E.g. "1.0.0", "1.1.0" 
 * 
 * @sa ::APN_VERSION_NUM
 * @sa ::APN_VERSION_STRING
 * @sa apn_version()
 * @ingroup version
 *
 * @return string 
 */
__apn_export__ const char * apn_version_string();

/**
 * Creates a new connection context which is needed to hold the data for a connection to
 * Apple Push Notification/Feedback Service
 *
 * This function allocates memory for a connection context which should be freed - call ::apn_free() function
 * for it
 *
 * @warning 
 * 
 * @sa apn_free()
 * @sa apn_set_private_key()
 * @sa apn_set_certificate()
 * 
 * @ingroup feedback
 * @ingroup apn
 * 
 * @param[in, out] ctx - Double pointer to `::apn_ctx` structure. Used to return new connection context. Cannot be NULL
 * @param[in] cert - path to an SSL certificate which will be used to establish secure connection. Can be NULL
 * @param[in] private_key - path to private key which used to establish secure connection. Can be NULL
 * @param[in] private_key_pass - Private key passphrase. Can be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_init(apn_ctx_ref *ctx, const char *cert, const char *private_key, const char *private_key_pass, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for a connection context
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @param[in, out] ctx - Pointer to pointer to `::apn_ctx` structure
 * 
 */
__apn_export__ void apn_free(apn_ctx_ref *ctx);

/**
 * Opens Apple Push Notification Service connection
 * 
 * @sa apn_close() 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to apn_error structure to return error information to the caller.
 * Pass NULL as the apn_error pointer, if information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_connect(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Closes Apple Push Notification/Feedback Service connection
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @param[in] ctx - Pointer to an initialized `apn_ctx` structure
 */
__apn_export__ void apn_close(apn_ctx_ref ctx);

/**
 * Creates a deep copy of `::apn_ctx` structure
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return point to new `::apn_ctx` structure on success, or NULL on failure with error information stored in `error`
 */
__apn_export__ apn_ctx_ref apn_copy(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Sets connection mode
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
 * @ingroup apn
 * @ingroup feedback
 * @since 1.0.0.beta3
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] mode -  Mode, must be ::APN_MODE_SANDBOX, or ::APN_MODE_PRODUCTION. 
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_set_mode(apn_ctx_ref ctx, uint8_t mode, apn_error_ref *error);

/**
 * Sets path to an SSL certificate which will be used to establish secure connection
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] cert - Path to a SSL certificate file. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to apn_error structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_set_certificate(apn_ctx_ref ctx, const char *cert, apn_error_ref *error);

/**
 * Sets a path to a private key which will be used to establish secure connection
 * 
 * @ingroup apn
 * @ingroup feedback
 * @attention In version 1.0.0 added a new argument `pass`
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] key - Path to a private key file. Must be a valid NULL-terminated string
 * @param[in] pass - Private key passphrase. Can be NULL
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error``
 */
__apn_export__ uint8_t apn_set_private_key(apn_ctx_ref ctx, const char *key, const char *pass, apn_error_ref *error);


/**
 * Adds a new target device token
 * 
 * Device token are used for identification of targets
 * which will receive the notification.
 * 
 * @ingroup apn
 * @sa apn_payload_add_tokn()
 *
 * @warning If device tokens are added both to apn_ctx and to payload_ctx, tokens from payload_ctx will 
 * be used when sending push notification 
 *
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] token - Device token. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_add_token(apn_ctx_ref ctx, const char *token, apn_error_ref *error);   


/**
 * Returns the connection mode
 * 
 * @ingroup apn
 * @ingroup feedback
 * @since 1.0.0.beta3
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the apn_error pointer, if error information should not be returned to the caller
 * 
 * @return -1 on error with error information stored to `error`, or mode 
 */
__apn_export__ int8_t apn_mode(apn_ctx_ref ctx, apn_error_ref *error);

/**
 * Returns a path to an SSL certificate used to establish secure connection
 *  
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the apn_error pointer, if error information should not be returned to the caller
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with error information stored 
 * in `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_certificate(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a path to private key which used to establish secure connection
 *  
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_private_key(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a private key passphrase
 *  
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @ingroup apn
 * @ingroup feedback
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_private_key_pass(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;


/**
 * Sends push notification
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] payload_ctx - Pointer to `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return  ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error`
 */
__apn_export__ uint8_t apn_send(const apn_ctx_ref ctx, apn_payload_ctx_ref payload_ctx, apn_error_ref *error);

/**
 * Opens Apple Push Feedback Service connection
 * 
 * @sa apn_close()
 * @ingroup feedback
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_feedback_connect(const apn_ctx_ref ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;


/**
 * Returns array of device tokens which no longer exists
 * 
 * @ingroup feedback
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] tokens_array - Pointer to a device tokens array. . The array  
 * should be freed - call ::apn_feedback_tokens_array_free() function for it
 * @param[in, out] tokens_array_count - Count tokens in `tokens_array`
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller 
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error`
 */
 __apn_export__ uint8_t apn_feedback(const apn_ctx_ref ctx, char ***tokens_array, uint32_t *tokens_array_count, apn_error_ref *error);

 /**
  * Frees memory allocated for a tokens array, which returned ::apn_feedback()
  * 
  * @ingroup feedback
  * 
  * This function allocates memory for a connection context which 
  * 
  * @param[in] tokens_array - Pointer to a device tokens array
  * @param[in] tokens_array_count - Count tokens in `tokens_array`
  */
 __apn_export__ void apn_feedback_tokens_array_free(char **tokens_array, uint32_t tokens_array_count);
 
 /**
 * Creates a new notification payload context
 *
 * This function allocates memory for payload context which should be freed - call ::apn_payload_free() function
 * for it 
 *
 * @ingroup payload
 * @sa apn_payload_free()
 * 
 * @param[in, out] payload_ctx - Double pointer to `::apn_payload_ctx` structure. Uses to return new connection context. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with stored error information stored to `error`
 */
__apn_export__ uint8_t apn_payload_init(apn_payload_ctx_ref *payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for notification payload context
 * 
 * @ingroup payload
 * 
 * @param[in, out] payload_ctx - Double pointer to `::apn_payload_ctx` structure
 * 
 */
__apn_export__ void apn_payload_free(apn_payload_ctx_ref *payload_ctx);

/**
 * Creates a deep copy of `::apn_payload_ctx` structure
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to new `::apn_payload_ctx` structure on success, or NULL on failure with error information stored to `error`
 */
__apn_export__ apn_payload_ctx_ref apn_payload_copy(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Adds a new target device token to payload
 * 
 * Device token are used for identification of targets
 * which will receive the notification.
 * 
 * @since 1.0.0.beta2 
 * @ingroup payload
 * @sa apn_add_token()
 * @warning If device tokens are added both to apn_ctx and to payload_ctx, tokens from payload_ctx will 
 * be used when sending push notification 
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] token - Device token. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_payload_add_token(apn_payload_ctx_ref payload_ctx, const char *token, apn_error_ref *error);  

/**
 * Sets expiration time of notification 
 *  
 * Expiration time is a fixed UNIX epoch date expressed in seconds (UTC) that identifies when the notification 
 * is no longer valid and can be discarded. You can specify zero or a value less than zero 
 * to request that APNs not store the notification at all.
 * Default value is 0.
 * 
 * @ingroup payload
 * @since 1.0.0
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] expiry - Time in seconds
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 *
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error``
 */
__apn_export__ uint8_t apn_payload_set_expiry(apn_payload_ctx_ref payload_ctx, uint32_t expiry, apn_error_ref *error);

/**
 * Sets a number to display as a badge on the application icon
 * 
 * If this property is not set, previously set value is not changed. To remove the badge, 
 * set the value to 0
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] badge - A number to display as the badge
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_badge(apn_payload_ctx_ref payload_ctx, int32_t badge, apn_error_ref *error);

/**
 * Sets a name of a sound file in the application bundle
 * 
 * This sound file is played as an alert. If the sound file doesn’t exist 
 * or default is specified as the value, the default alert sound is played
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] sound - Name of a sound file. Must be a valid UTF-8 encoded Unicode string
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_sound(apn_payload_ctx_ref payload_ctx, const char *sound, apn_error_ref *error);

/**
 * Sets a text of the alert message
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] body - Text. Must be a valid UTF-8 encoded Unicode string
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_body(apn_payload_ctx_ref payload_ctx, const char *body, apn_error_ref *error);

/**
 * Sets a key used to get a localized string to use for the right button’s 
 * caption instead of "View"
 * 
 * If the value is null, the system displays an alert with a single OK button that simply 
 * dismisses the alert when tapped 
 * 
 * @ingroup payload
 * 
 * @sa <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a> for more information
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] key - Key for localized string
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_localized_action_key(apn_payload_ctx_ref payload_ctx, const char *key, apn_error_ref *error);

/**
 * Sets a filename of an image file in the application bundle
 * 
 * Filename may include or not include the extension. The image is used as the launch image when users tap 
 * the action button or move the action slider. If this property is not specified, the system either 
 * uses the previous one, uses the image identified by the UILaunchImageFile key in the application’s 
 * Info.plist file, or falls back to Default.png
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] image - A filename of an image file
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_launch_image(apn_payload_ctx_ref payload_ctx, const char *image, apn_error_ref *error);

/**
 * Sets a key used to get a localized alert-message string and an array of strings
 * to appear in place of the format specifiers in `key`
 * 
 * The `key` string can be formatted with %@ and %n$@ specifiers to take the variables specified in `args`
 * 
 * @see <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a> for more information
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] key - Key of localized string
 * @param[in] args - Array of string values to appear in place of the format specifiers in `key`
 * @param[in] args_count - Count elements in `args` array
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_set_localized_key(apn_payload_ctx_ref payload_ctx, const char *key, char **args, uint16_t args_count, apn_error_ref *error);

/**
 * Returns expiration time of notification
 * 
 * Expiration time is a fixed UNIX epoch date expressed in seconds (UTC) that identifies when the notification 
 * is no longer valid and can be discarded.
 * 
 * @since 1.0.0
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 *
 * @return Unix timestamp
 */
__apn_export__ uint32_t apn_payload_expiry(apn_payload_ctx_ref payload_ctx, apn_error_ref *error);

/**
 * Returns an array of strings to appear in place of the format specifiers in localized alert-message string
 * 
 * @sa apn_payload_localized_key()
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param args - Pointer to array. Return NULL on failure with stored error information stored to `error`
 * The return value must not be modified or freed
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Number of elements in `args`
 */
__apn_export__ uint16_t apn_payload_localized_key_args(const apn_payload_ctx_ref payload_ctx, char ***args, apn_error_ref *error);

/**
 * Returns a number to display as the badge of the application icon
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Number to display as the badge
 */
__apn_export__ int32_t apn_payload_badge(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a name of a sound file in the application bundle which played as an alert
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with 
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_payload_sound(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a filename of an image file in the application bundle used as a launch image
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with 
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_payload_launch_image(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a key used to get a localized string for the right button’s 
 * caption instead of "View"
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with stored 
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed  
 */
__apn_export__ const char *apn_payload_localized_action_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a key used to get a localized alert-message string
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with 
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_payload_localized_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Returns a text of an alert message
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with stored 
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_payload_body(const apn_payload_ctx_ref payload_ctx, apn_error_ref *error) __apn_attribute_warn_unused_result__;

/**
 * Adds a custom property with a boolean value to notification payload
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] key - Property name
 * @param[in] value - Property value
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_add_custom_property_bool(apn_payload_ctx_ref payload_ctx, const char *key, 
        uint8_t value, 
        apn_error_ref *error);

/**
 * Adds a custom property with a double value to notification payload
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_add_custom_property_double(apn_payload_ctx_ref payload_ctx, const char *name, 
        double value, 
        apn_error_ref *error);

/**
 * Adds a custom property with an integer value to notification payload
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_add_custom_property_integer(apn_payload_ctx_ref payload_ctx, const char *name, 
        int64_t value, 
        apn_error_ref *error);

/**
 * Adds a custom property with a null value to notification payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_add_custom_property_null(apn_payload_ctx_ref payload_ctx, const char *name, apn_error_ref *error);


/**
 * Adds a custom property with a string value to notification payload
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error` 
 */
__apn_export__ uint8_t apn_payload_add_custom_property_string(apn_payload_ctx_ref payload_ctx, const char *name, 
        const char *value,
        apn_error_ref *error);

/**
 * Adds a custom property with an array value to notification payload
 * 
 * @ingroup payload
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in] name - Propery name
 * @param[in] array - Array
 * @param[in] array_size - Count elements in `array`
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error`
 */
__apn_export__ uint8_t apn_payload_add_custom_property_array(apn_payload_ctx_ref payload_ctx, const char *name, 
        const char **array, uint8_t array_size,
        apn_error_ref *error);

/**
 * Frees memory allocated for an error
 * 
 * @ingroup errors
 * @since 1.0.0 beta3
 * 
 * @param[in] error - Pointer to pointer to `::apn_error` structure
 */
__apn_export__ void apn_error_free(apn_error_ref *error);

/**
 * Returns error message
 * 
 * @ingroup errors
 * @since 1.0.0 beta3
 * 
 * @param[in] error - Pointer to `::apn_error` structure
 * @return Pointer to NULL-terminated string, or NULL. 
 * The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_error_message(const apn_error_ref error);

/**
 * Returns error code
 * 
 * @ingroup errors
 * @since 1.0.0 beta3
 * 
 * @param[in] error - Pointer to `::apn_error` structure
 * @return -1 if `error' not initialized, or error code
 */
__apn_export__ int32_t apn_error_code(const apn_error_ref error);

/**
 * Returns invalid device token in hex format
 * 
 * If error code == ::APN_ERR_TOKEN_INVALID, an invalid token is set:
 * 
 * @code{.c}
 * if(APN_ERR_CODE_WITHOUT_CLASS(apn_error_code(error)) == APN_ERR_TOKEN_INVALID) {
 *     printf("Invalid token: %s\n", apn_error_invalid_token(error));
 * }
 * @endcode
 * 
 * @ingroup errors
 * @since 1.0.0 beta3
 * 
 * @param[in] error - Pointer to `::apn_error` structure
 * @return Pointer to NULL-terminated string, or NULL. 
 * The retuned value is read-only and must not be modified or freed 
 */
__apn_export__  const char *apn_error_invalid_token(const apn_error_ref error);

#ifdef __cplusplus
}
#endif

#endif
