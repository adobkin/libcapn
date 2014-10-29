/*
 * Copyright (c) 2013, 2104 Anton Dobkin
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

#include <stddef.h>
#include <time.h>
#include "apn_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum __apn_notification_priority {
    /* The push message is sent at a time that conserves power on the device receiving it */
    APN_NOTIFICATION_PRIORITY_DEFAULT = 5,
    /* The push message is sent immediately */
    APN_NOTIFICATION_PRIORITY_HIGH = 10
} apn_notification_priority;


typedef enum __apn_payload_custom_property_type {
    APN_CUSTOM_PROPERTY_TYPE_BOOL,
    APN_CUSTOM_PROPERTY_TYPE_NUMERIC,
    APN_CUSTOM_PROPERTY_TYPE_ARRAY,
    APN_CUSTOM_PROPERTY_TYPE_STRING,
    APN_CUSTOM_PROPERTY_TYPE_DOUBLE,
    APN_CUSTOM_PROPERTY_TYPE_NULL
} apn_payload_custom_property_type;

typedef union {
    int64_t numeric_value;
    double double_value;
    struct {
        char *value;
        size_t length;
    } string_value;
    uint8_t bool_value;
    struct {
        char **array;
        uint8_t array_size;
    } array_value;
} apn_payload_custom_value;

typedef struct __apn_payload_custom_property {
    char *name;
    apn_payload_custom_value value;
    apn_payload_custom_property_type value_type;
} apn_payload_custom_property;

typedef struct __apn_payload_alert {
    uint16_t loc_args_count;
    char *body;
    char *action_loc_key;
    char *loc_key;
    char **loc_args;
    char *launch_image;
} apn_payload_alert;

typedef struct __apn_payload {
    uint32_t custom_properties_count;
    uint8_t content_available;
    apn_notification_priority priority;
    uint32_t tokens_count;
    uint32_t custom_properties_allocated;
    int32_t badge;
    time_t expiry;
    apn_payload_alert *alert;
    char *sound;
    char *category;
    uint8_t **tokens;
    apn_payload_custom_property **custom_properties;
} apn_payload;

typedef apn_payload_custom_property *apn_payload_custom_property_ref;
typedef apn_payload_alert *apn_payload_alert_ref;
typedef apn_payload *apn_payload_ref;

__apn_export__ apn_payload_ref apn_payload_init()
		__apn_attribute_warn_unused_result__;

__apn_export__ void apn_payload_free(apn_payload_ref *payload)
		__apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_add_token(apn_payload_ref payload, const char * const token)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ void apn_payload_remove_all_tokens(apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_payload_set_expiry(apn_payload_ref payload, time_t expiry)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_set_badge(apn_payload_ref payload, int32_t badge)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_set_sound(apn_payload_ref payload, const char * const sound)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ void apn_payload_set_content_available(apn_payload_ref payload, uint8_t content_available)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_payload_set_priority(apn_payload_ref payload, apn_notification_priority priority)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_set_body(apn_payload_ref payload, const char * const body)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_set_localized_action_key(apn_payload_ref payload, const char * const key)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_set_launch_image(apn_payload_ref payload, const char * const image)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_set_localized_key(apn_payload_ref payload, const char * const key, char **args, uint16_t args_count)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_set_category(apn_payload_ref payload, const char * const category)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_payload_add_custom_property_integer(apn_payload_ref payload, const char * const key, int64_t value)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_add_custom_property_bool(apn_payload_ref payload, const char * const key, uint8_t value)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_add_custom_property_double(apn_payload_ref payload, const char * const key, double value)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_add_custom_property_null(apn_payload_ref payload, const char * const key)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ apn_return apn_payload_add_custom_property_string(apn_payload_ref payload, const char * const key, const char *value)
        __apn_attribute_nonnull__((1, 2, 3));

__apn_export__ apn_return apn_payload_add_custom_property_array(apn_payload_ref payload, const char * const key, const char **array, uint8_t array_size)
        __apn_attribute_nonnull__((1, 2, 3));

__apn_export__ uint8_t apn_payload_content_available(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

__apn_export__ const char * apn_payload_category(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

__apn_export__ time_t apn_payload_expiry(apn_payload_ref payload_ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ uint16_t apn_payload_localized_key_args(const apn_payload_ref payload, char ***args)
        __apn_attribute_nonnull__((1, 2));

__apn_export__ int32_t apn_payload_badge(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

__apn_export__ const char *apn_payload_sound(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_payload_launch_image(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_payload_localized_action_key(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_payload_localized_key(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ const char *apn_payload_body(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

__apn_export__ apn_notification_priority apn_payload_priority(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

char *apn_create_json_document_from_payload(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

#ifdef __cplusplus
}
#endif

#endif
