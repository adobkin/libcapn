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

#ifndef __APN_PAYLOAD_H__
#define __APN_PAYLOAD_H__

#include "apn_platform.h"
#include "apn_array.h"

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Notification priority
 */
typedef enum __apn_notification_priority_t {
    /* The push message is sent at a time that conserves power on the device receiving it */
    APN_NOTIFICATION_PRIORITY_DEFAULT = 5,
    /* The push message is sent immediately */
    APN_NOTIFICATION_PRIORITY_HIGH = 10
} apn_notification_priority_t;

typedef union __apn_payload_custom_value_t apn_payload_custom_value_t;
typedef struct __apn_payload_custom_property_t apn_payload_custom_property_t;
typedef struct __apn_payload_alert_t apn_payload_alert_t;
typedef struct __apn_payload_t apn_payload_t;

/**
 * Creates a new notification payload context.
 *
 * This function allocates memory for payload which should be freed - call ::apn_payload_free() function
 * for it.
 *
 * @sa apn_payload_free()
 *
 * @return
 *      - Pointer to new `payload` structure on success
 *      - NULL on failure with error information stored to `errno`
 */
__apn_export__ apn_payload_t *apn_payload_init()
        __apn_attribute_warn_unused_result__;

/**
 * Frees memory allocated for `payload`
 *
 * @param[in, out] payload - Double pointer to `payload` structure
 */
__apn_export__ void apn_payload_free(apn_payload_t *payload);

/**
 * Sets expiration time of notification.
 *
 * Expiration time is a fixed UNIX epoch date expressed in seconds (UTC) that identifies when the notification
 * is no longer valid and can be discarded. You can specify zero or a value less than zero
 * to request that APNs not store the notification at all. Default value is 0.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] expiry - Time in seconds
*/
__apn_export__ void apn_payload_set_expiry(apn_payload_t * const payload, time_t expiry)
        __apn_attribute_nonnull__((1));

/**
 * Sets a number to display as a badge on the application icon.
 *
 * If this property is not set, previously set value is not changed. To remove the badge,
 * set the value to 0.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] badge - A number to display as the badge
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_badge(apn_payload_t * const payload, int32_t badge)
        __apn_attribute_nonnull__((1));

/**
 * Sets a name of a sound file in the application bundle.
 *
 * If the sound file doesn’t exist or default is specified as the value,
 * the default alert sound is played.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] sound - Name of a sound file. Must be a valid UTF-8 encoded Unicode string
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_sound(apn_payload_t * const payload, const char *const sound)
        __apn_attribute_nonnull__((1));

/**
 * Sets a content availability flag.
 *
 * Set this flag to value of 1 to indicate that new content is available, it lets the remote notification act as a “silent”
 * notification. When a silent notification arrives, iOS wakes up your app in the background so that you can get new data from your server
 * or do background information processing. Users aren’t told about the new or changed information that results from a silent notification.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] content_available - flag
 *
 */
__apn_export__ void apn_payload_set_content_available(apn_payload_t *const payload, uint8_t content_available)
        __apn_attribute_nonnull__((1));

/**
 * Sets a notification priority.
 *
 * Provide one of the following values:
 *      - ::APN_NOTIFICATION_PRIORITY_HIGH - The push message is sent immediately
 *      - ::APN_NOTIFICATION_PRIORITY_DEFAULT - The push message is sent at a time that conserves power on the device receiving it
 *
 * If payload contains only content available flag you must use ::APN_NOTIFICATION_PRIORITY_DEFAULT, otherwise
 * it is an error to use.
 * Default priority is ::APN_NOTIFICATION_PRIORITY_DEFAULT
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] priority - Notification's priority
 */
__apn_export__ void apn_payload_set_priority(apn_payload_t *const payload, apn_notification_priority_t priority)
        __apn_attribute_nonnull__((1));

/**
 * Sets a text of the alert message.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] body - Text. Must be a valid UTF-8 encoded Unicode string
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_body(apn_payload_t *const payload, const char *const body)
        __apn_attribute_nonnull__((1));

/**
 * Sets a key used to get a localized string to use for the right button’s
 * caption instead of "View".
 *
 * If the value is null, the system displays an alert with a single OK button that simply
 * dismisses the alert when tapped.
 *
 * @sa <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a> for more information
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] key - Key for localized string
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_localized_action_key(apn_payload_t *const payload, const char *const key)
        __apn_attribute_nonnull__((1));

/**
 * Sets a name of an image file in the application bundle.
 *
 * Filename may include or not include the extension. The image is used as the launch image when users tap
 * the action button or move the action slider. If this property is not specified, the system either
 * uses the previous one, uses the image identified by the UILaunchImageFile key in the application’s
 * Info.plist file, or falls back to Default.png
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] image - A filename of an image file
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_launch_image(apn_payload_t *const payload, const char *const image)
        __apn_attribute_nonnull__((1));

/**
 * Sets a key used to get a localized alert-message string and an array of strings
 * to appear in place of the format specifiers in `key`.
 *
 * The `key` string can be formatted with %@ and %n$@ specifiers to take the variables specified in `args`.
 *
 * @see <a href="http://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a> for more information
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] key - Key of localized string
 * @param[in] args - Array of string values to appear in place of the format specifiers in `key`
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_localized_key(apn_payload_t *const payload, const char *const key, apn_array_t * const args)
        __apn_attribute_nonnull__((1));

/**
 * Sets a category name of notification.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] category - Category name
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_set_category(apn_payload_t *const payload, const char *const category)
        __apn_attribute_nonnull__((1));

/**
 * Adds a custom property with an integer value to notification payload
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_integer(apn_payload_t *const payload, const char *const key, int64_t value)
        __apn_attribute_nonnull__((1, 2));

/**
 * Adds a custom property with a boolean value to notification payload.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL.
 * @param[in] key - Property name
 * @param[in] value - Property value
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_bool(apn_payload_t *const payload, const char *const key, uint8_t value)
        __apn_attribute_nonnull__((1, 2));

/**
 * Adds a custom property with a double value to notification payload.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_double(apn_payload_t *const payload, const char *const key, double value)
        __apn_attribute_nonnull__((1, 2));

/**
 * Adds a custom property with a null value to notification payload.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] name - Property name
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_null(apn_payload_t *const payload, const char *const key)
        __apn_attribute_nonnull__((1, 2));

/**
 * Adds a custom property with a string value to notification payload.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] name - Property name
 * @param[in] value - Property value
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_string(apn_payload_t * const payload, const char *const key, const char *value)
        __apn_attribute_nonnull__((1, 2, 3));

/**
 * Adds a custom property with an array value to notification payload.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 * @param[in] key - Property name
 * @param[in] array - Array
 * @param[in] array_size - Count elements in `array`
 *
 * @return
 *      - ::APN_SUCCESS on success
 *      - ::APN_ERROR on failure with error information stored to `errno`
 */
__apn_export__ apn_return apn_payload_add_custom_property_array(apn_payload_t * const payload, const char *const key, const char **array, uint8_t array_size)
        __apn_attribute_nonnull__((1, 2, 3));

/**
 * Returns a content available flag.
 *
 * @param[in] payload - Pointer to an initialized `apn_payload` structure. Cannot be NULL
 *
 * @return 1 if flag is set, 0 if not set
 */
__apn_export__ uint8_t apn_payload_content_available(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a category of notification.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or NULL if category is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_category(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns expiration time of notification.
 *
 * Expiration time is a fixed UNIX epoch date expressed in seconds (UTC) that identifies when the notification
 * is no longer valid and can be discarded.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Unix timestamp
 */
__apn_export__ time_t apn_payload_expiry(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ apn_array_t *apn_payload_localized_key_args(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a number to display as the badge of the application icon.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Number to display as the badge or -1 if badge not set
 */
__apn_export__ int32_t apn_payload_badge(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a name of a sound file in the application bundle which played as an alert.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or NULL if sound is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_sound(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a filename of an image file in the application bundle used as a launch image.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or NULL if filename is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_launch_image(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a key used to get a localized string for the right button’s
 * caption instead of "View".
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or NULL if key is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_localized_action_key(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a key used to get a localized alert-message string.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or NULL if key is not set
 *
 * The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_localized_key(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a text of an alert message.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return Pointer to NULL-terminated string or null if alert text is not set
 *
 *  The returned value is read-only and must not be modified or freed
 */
__apn_export__ const char *apn_payload_body(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

/**
 * Returns a notification's priority.
 *
 * @param[in] payload - Pointer to an initialized `payload` structure. Cannot be NULL
 *
 * @return ::APN_NOTIFICATION_PRIORITY_DEFAULT or ::APN_NOTIFICATION_PRIORITY_HIGH
 */
__apn_export__ apn_notification_priority_t apn_payload_priority(const apn_payload_t * const payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;


#ifdef __cplusplus
}
#endif

#endif
