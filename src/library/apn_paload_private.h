/*
 * Copyright (c) 2013, 2104, 2015 Anton Dobkin
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

#define APN_PAYLOAD_MAX_SIZE  2048

union __apn_payload_custom_value {
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
} ;

struct __apn_payload_custom_property {
        char *name;
        union __apn_payload_custom_value value;
        apn_payload_custom_property_type value_type;
};

struct __apn_payload_alert {
        uint16_t loc_args_count;
        char *body;
        char *action_loc_key;
        char *loc_key;
        char **loc_args;
        char *launch_image;
};

struct __apn_payload {
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
};

char *apn_create_json_document_from_payload(const apn_payload_ref payload)
        __apn_attribute_nonnull__((1));

#endif
