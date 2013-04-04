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

/**
 * @example example.c 
 * Send Push Notification
 */
 
/** 
 * @defgroup errors Error Handling
 * Error Handling
 * @{
 * 
 * @details libcapn uses an ::apn_error structure to pass error information to the caller. 
 * 
 * If the call succeeded, the contents of error are generally left unspecified.  The normal use 
 * of apn_error is to allocate it on the stack, and pass the pointer to a function.
 * 
 * 
 * Example code:
 * 
 * @code{.c}
 * int main() {
 *     apn_error error;
 *     apn_ctx_ref ctx = NULL;
 * 
 *     ...
 * 
 *     if(apn_init(&ctx, &error) == APN_ERROR){
 *       printf("%s: %d\n", error.message, error.code);
 *       return 1;
 *     }
 * 
 *     ...
 * }
 * @endcode
 */

/**
 * Maximum size of error message
 */
#define APN_ERROR_MESSAGE_MAX_SIZE 128
    
/**
 * Error codes
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
    
    /** Unknown error */
    APN_ERR_UNKNOWN,    
    
    /** Don't use */
    APN_ERR_COUNT 
};

typedef enum __apn_errors apn_errors;

/**
 * Uses to pass error information to the caller
 */
struct __apn_error {
    /** 
     * Error code 
     * @sa apn_errors
     */
    
    apn_errors code;
    
    /** 
     * Error message or an empty string if the message 
     * is not available 
     */
    char message[APN_ERROR_MESSAGE_MAX_SIZE];
};

typedef struct __apn_error* apn_error_ref;
typedef struct __apn_error apn_error;

/**
 * @}
 */

/**
 * @defgroup apn Apple Push Notification Service
 * Apple Push Notification Service
 * 
 * @details Apple Push Notification service (APNs for short) transports and routes a notification from a given provider to a given 
 * device. A notification is a short message consisting of two major pieces of data: the device token and the \ref payload "payload". 
 * 
 * The device token is analogous to a phone number; it contains information that enables APNs to locate the device on 
 * which the client application is installed. APNs also uses it to authenticate the routing of a notification. 
 * 
 * @attention The Apple is not guarantee delivery, you should not depend on the remote-notifications facility 
 * for delivering critical data to an application via the payload. And never include sensitive data in the payload. 
 * 
 * The payload specifies how the user of an application on a device is to 
 * be alerted.
 * 
 * To establish secure connection from APNs uses SSL certificate and private key. The SSL certificate required for these connections 
 * is provisioned through the iOS Provisioning Portal. 
 * 
 * @note To establish a TLS session with APNs, an Entrust Secure CA root certificate must be installed on the 
 * provider’s server. If on your systems the certificate is not available, you can download this certificate 
 * from the Entrust SSL Certificates  <a href="http://www.entrust.net">website</a>.
 * 
 * @attention You should also retain connections with APNs across multiple notifications. 
 * APNs may consider connections that are rapidly and repeatedly established and torn down as a 
 * denial-of-service attack. Upon error, APNs closes the connection on which the error occurred.
 * 
 * @sa <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW9">Apple Push Notification Service</a> for more information
 * @{
 * 
 * @defgroup payload Notification Payload
 * Notification Payload
 * 
 * @details Each push notification carries with it a payload. The payload specifies how users are to be alerted to the 
 * data waiting to be downloaded to the client application. 
 * 
 * @attention The maximum size allowed for a notification payload 
 * is 256 bytes.
 * 
 * The payload contains one or more properties that specify the following actions:
 * - An alert message to display to the user
 * - A number to badge the application icon with
 * - A sound to play
 * - A custom properties
 * 
 * @attention The alert messsage is required.
 * 
 * You can specify custom payload values. You should not include customer information as custom payload data. Instead, 
 * use it for such purposes as setting context (for the user interface) or internal metrics.
 * 
 * 
 * @sa <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW1">The Notification Payload</a> for more information
 *  
 * @{
 */

/**
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
 */
struct __apn_payload_custom_property {
    /** Property name */
    char *key;
    
    /** Property value */
    union __apn_payload_custom_value value;
    
    /** Property value type */
    enum __apn_payload_custom_property_types value_type;
};

typedef struct __apn_payload_custom_property  apn_payload_custom_property;
typedef struct __apn_payload_custom_property * apn_payload_custom_property_ref;


/** 
 * Payload alert
 * 
 * Uses to store payload alert
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

typedef struct __apn_payload_alert * apn_payload_alert_ref;
typedef struct __apn_payload_alert  apn_payload_alert;

/** 
 * Notification Payload
 * 
 * Uses to store notification payload
 */
struct __apn_payload {
    /** Alert */
    struct __apn_payload_alert *alert;
    
    /** Name of a sound file in the application bundle */
    char *sound;
    
    /** Number to display as a badge on application icon */
    uint16_t badge;
    
    /** Custom payload properties*/
    struct __apn_payload_custom_property **custom_properties;
    
    /** Custom properties number */
    uint8_t __custom_properties_count;
};

typedef struct __apn_payload * apn_payload_ctx_ref;
typedef struct __apn_payload  apn_payload_ctx;

/**
 * @}
 */


/** 
 * Connection context
 * 
 * Uses to store connection data for Apple Push Notification/Feedback Service
 */
struct __apn_ctx {
    int sock;
    
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
    char **tokens;
    
    uint8_t feedback;
};

typedef struct __apn_ctx * apn_ctx_ref;
typedef struct __apn_ctx  apn_ctx;

/**
 * @} 
 */

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
 * This function allocates memory for a connection context which should be freed - call apn_free() function
 * for it
 *
 * @sa apn_free()
 * @ingroup apn
 * 
 * @param[in, out] ctx - Double pointer to `::apn_ctx` structure. Used to return new connection context. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_init(apn_ctx_ref *ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for a connection context
 * 
 * @ingroup apn
 * 
 * @param[in, out] ctx - Double pointer to `::apn_ctx` structure
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_free(apn_ctx_ref *ctx, apn_error_ref error);

/**
 * Opens Apple Push Notification Service connection
 * 
 * @sa apn_close() 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] sandbox - 1 to use "sandbox" server, 0 - not to use
 * @param[in, out] error - Pointer to apn_error structure to return error information to the caller.
 * Pass NULL as the apn_error pointer, if information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_connect(const apn_ctx_ref ctx, uint8_t sandbox, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Opens Apple Push Feedback Service connection
 * 
 * @sa apn_close()
 * @ingroup feedback
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] sandbox - 1 to use "sandbox" server, 0 - not to use
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_connect_feedback(const apn_ctx_ref ctx, uint8_t sandbox, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ apn_ctx_ref apn_copy(const apn_ctx_ref ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Sets path to an SSL certificate which will be used to establish secure connection
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] cert - Path to a SSL certificate file. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to apn_error structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_set_certificate(apn_ctx_ref ctx, const char *cert, apn_error_ref error);

/**
 * Sets a path to a private key which will be used to establish secure connection
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] key - Path to a private key file. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error``
 */
__apn_export__ uint8_t apn_set_private_key(apn_ctx_ref ctx, const char *key, apn_error_ref error);

/**
 * Adds a new target device token
 * 
 * Device token are used for identification of targets
 * which will receive the notification.
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] token - Device token. Must be a valid NULL-terminated string
 * @param[in, out] error - Pointer to `apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored in `error`
 */
__apn_export__ uint8_t apn_add_token(apn_ctx_ref ctx, const char *token, apn_error_ref error);   

/**
 * Returns a path to an SSL certificate used to establish secure connection
 *  
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the apn_error pointer, if error information should not be returned to the caller
 * 
 * @ingroup apn
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with error information stored 
 * in `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_certificate(const apn_ctx_ref ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Returns a path to private key which used to establish secure connection
 *  
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller.
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @ingroup apn
 * 
 * @return Pointer to NULL-terminated string on success, or NULL on failure with
 * error information stored to `error`. The retuned value is read-only and must not be modified or freed 
 */
__apn_export__ const char *apn_private_key(const apn_ctx_ref ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Returns an array of device tokens which should receive the notification
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in, out] tokens - Pointer to a device tokens array. Return NULL on failure with error information stored to `error`.
 * The return value must not be modified or freed
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Tokens count in `tokens` array
 */
__apn_export__ uint32_t apn_tokens(const apn_ctx_ref ctx, char ***tokens, apn_error_ref error) __apn_attribute_warn_unused_result__;    

/**
 * Sends push notification
 * 
 * @ingroup apn
 * 
 * @param[in] ctx - Pointer to an initialized `::apn_ctx` structure. Cannot be NULL
 * @param[in] payload_ctx - Pointer to `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return  ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error`
 */
__apn_export__ uint8_t apn_send(const apn_ctx_ref ctx, apn_payload_ctx_ref payload_ctx, apn_error_ref error);

 __apn_export__ uint32_t apn_feedback(const apn_ctx_ref ctx, const char ***tokens, apn_error_ref error);

 /**
 * Creates a new notification payload context
 *
 * This function allocates memory for connection context which should be freed - call ::apn_payload_free() function
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
__apn_export__ uint8_t apn_payload_init(apn_payload_ctx_ref *payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for notification payload context
 * 
 * @ingroup payload
 * 
 * @param[in, out] payload_ctx - Double pointer to `::apn_payload_ctx` structure
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return ::APN_SUCCESS on success, or ::APN_ERROR on failure with error information stored to `error`
 */
__apn_export__ uint8_t apn_payload_free(apn_payload_ctx_ref *payload_ctx, apn_error_ref error);

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
__apn_export__ apn_payload_ctx_ref apn_payload_copy(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ uint8_t apn_payload_set_badge(apn_payload_ctx_ref payload_ctx, uint16_t badge, apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_set_sound(apn_payload_ctx_ref payload_ctx, const char *sound, apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_set_body(apn_payload_ctx_ref payload_ctx, const char *body, apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_set_localized_action_key(apn_payload_ctx_ref payload_ctx, const char *key, apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_set_launch_image(apn_payload_ctx_ref payload_ctx, const char *image, apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_set_localized_key(apn_payload_ctx_ref payload_ctx, const char *key, char **args, uint16_t args_count, apn_error_ref error);

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
__apn_export__ uint16_t apn_payload_localized_key_args(const apn_payload_ctx_ref payload_ctx, char ***args, apn_error_ref error);

/**
 * Returns a number to display as the badge of the application icon
 * 
 * @ingroup payload
 * 
 * @param[in] payload_ctx - Pointer to an initialized `::apn_payload_ctx` structure. Cannot be NULL
 * @param[in, out] error - Pointer to `::apn_error` structure to return error information to the caller. 
 * Pass NULL as the `::apn_error` pointer, if error information should not be returned to the caller
 * 
 * @return Number
 */
__apn_export__ uint16_t apn_payload_badge(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ const char *apn_payload_sound(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ const char *apn_payload_launch_image(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ const char *apn_payload_localized_action_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ const char *apn_payload_localized_key(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
__apn_export__ const char *apn_payload_body(const apn_payload_ctx_ref payload_ctx, apn_error_ref error) __apn_attribute_warn_unused_result__;

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
        apn_error_ref error);

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
        apn_error_ref error);

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
        apn_error_ref error);

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
__apn_export__ uint8_t apn_payload_add_custom_property_null(apn_payload_ctx_ref payload_ctx, const char *name, apn_error_ref error);


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
        apn_error_ref error);

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
        apn_error_ref error);

#ifdef __cplusplus
}
#endif

#endif
