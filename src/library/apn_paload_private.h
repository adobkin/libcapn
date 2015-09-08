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

#ifndef __APN_PAYLOAD_PRIVATE_H__
#define __APN_PAYLOAD_PRIVATE_H__

#include "apn_payload.h"
#include "apn_array.h"

#define APN_PAYLOAD_MAX_SIZE  2048

/**
 * Types of custom property of notification payload
 */
typedef enum __apn_payload_custom_property_type_t {
    APN_CUSTOM_PROPERTY_TYPE_BOOL,
    APN_CUSTOM_PROPERTY_TYPE_NUMERIC,
    APN_CUSTOM_PROPERTY_TYPE_ARRAY,
    APN_CUSTOM_PROPERTY_TYPE_STRING,
    APN_CUSTOM_PROPERTY_TYPE_DOUBLE,
    APN_CUSTOM_PROPERTY_TYPE_NULL
} apn_payload_custom_property_type_t;

union __apn_payload_custom_value_t {
    int64_t numeric_value;
    double double_value;
    struct {
            char *value;
            size_t length;
    } string_value;
    uint8_t bool_value;
    struct {
            char **array;
            uint32_t array_size;
    } array_value;
};

struct __apn_payload_custom_property_t {
    char *name;
    apn_payload_custom_value_t value;
    apn_payload_custom_property_type_t value_type;
};

struct __apn_payload_alert_t {
    char *body;
    char *action_loc_key;
    char *loc_key;
    apn_array_t *loc_args;
    char *launch_image;
};

struct __apn_payload_t {
    uint8_t content_available;
    apn_notification_priority_t priority;
    int32_t badge;
    time_t expiry;
    apn_payload_alert_t *alert;
    char *sound;
    char *category;
    apn_array_t *custom_properties;
};

char *apn_create_json_document_from_payload(const apn_payload_t *payload)
        __apn_attribute_nonnull__((1));

#endif
