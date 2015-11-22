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

#include <string.h>
#include <errno.h>
#include <assert.h>

#include "src/jansson.h"
#include "apn_strings.h"
#include "apn_memory.h"
#include "apn.h"
#include "apn_array.h"
#include "apn_paload_private.h"

#ifdef APN_HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

static apn_payload_alert_t *__apn_payload_alert_init();
static uint8_t __apn_payload_custom_property_name_already_is_used(apn_payload_t *payload, const char *property_key);

static apn_payload_custom_property_t *__apn_payload_custom_property_init(const char *name);
static void __apn_payload_custom_property_free(apn_payload_custom_property_t *property);
static apn_payload_custom_property_t *__apn_payload_custom_property_copy(const apn_payload_custom_property_t * const property);

static void __apn_payload_custom_property_dtor(void *data);
static void *__apn_payload_custom_property_ctor(const void * const data);

apn_payload_t *apn_payload_init() {
    apn_payload_t *payload = NULL;
    payload = malloc(sizeof(apn_payload_t));
    if (!payload) {
        errno = ENOMEM;
        return NULL;
    }
    if (NULL == (payload->alert = __apn_payload_alert_init())) {
        apn_payload_free(payload);
        return NULL;
    }

    if (NULL == (payload->custom_properties = apn_array_init(20, __apn_payload_custom_property_dtor, __apn_payload_custom_property_ctor))) {
        apn_payload_free(payload);
        return NULL;
    }

    payload->badge = -1;
    payload->sound = NULL;
    payload->category = NULL;
    payload->expiry = 0;
    payload->content_available = 0;
    payload->priority = APN_NOTIFICATION_PRIORITY_DEFAULT;

    return payload;
}

void apn_payload_free(apn_payload_t *payload) {
    if (payload) {
        if (payload->alert) {
            apn_mem_free(payload->alert->action_loc_key);
            apn_mem_free(payload->alert->body);
            apn_mem_free(payload->alert->launch_image);
            apn_mem_free(payload->alert->loc_key);
            apn_array_free(payload->alert->loc_args);
            free(payload->alert);
        }
        apn_mem_free(payload->sound);
        apn_mem_free(payload->category);
        apn_array_free(payload->custom_properties);
        free(payload);
    }
}

void apn_payload_set_priority(apn_payload_t *const payload, apn_notification_priority_t priority) {
    assert(payload);
    if (APN_NOTIFICATION_PRIORITY_DEFAULT != priority && APN_NOTIFICATION_PRIORITY_HIGH != priority) {
        priority = APN_NOTIFICATION_PRIORITY_DEFAULT;
    }
    payload->priority = priority;
}

void apn_payload_set_expiry(apn_payload_t *const payload, time_t expiry) {
    assert(payload);
    payload->expiry = expiry;
}

apn_return apn_payload_set_badge(apn_payload_t *const payload, int32_t badge) {
    assert(payload);
    if (badge < 0 || badge > UINT16_MAX) {
        errno = APN_ERR_PAYLOAD_BADGE_INVALID_VALUE;
        return APN_ERROR;
    }
    payload->badge = badge;
    return APN_SUCCESS;
}

apn_return apn_payload_set_sound(apn_payload_t *const payload, const char *const sound) {
    assert(payload);
    if (payload->sound) {
        apn_strfree(&payload->sound);
    }
    if (sound && strlen(sound)) {
        if (NULL == (payload->sound = apn_strndup(sound, strlen(sound)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

void apn_payload_set_content_available(apn_payload_t *const payload, uint8_t content_available) {
    assert(payload);
    payload->content_available = (uint8_t) ((content_available == 1) ? 1 : 0);
}

apn_return apn_payload_set_body(apn_payload_t *const payload, const char *const body) {
    assert(payload);
    if (payload->alert->body) {
        apn_strfree(&payload->alert->body);
    }
    if (body && strlen(body) > 0) {
        if (!apn_string_is_utf8(body)) {
            errno = APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS;
            return APN_ERROR;
        }
        if (NULL == (payload->alert->body = apn_strndup(body, strlen(body)))) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

apn_return apn_payload_set_localized_action_key(apn_payload_t *const payload, const char *const key) {
    assert(payload);
    if (payload->alert->action_loc_key) {
        apn_strfree(&payload->alert->action_loc_key);
    }
    if (key && strlen(key) > 0) {
        if ((payload->alert->action_loc_key = apn_strndup(key, strlen(key))) == NULL) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

apn_return apn_payload_set_launch_image(apn_payload_t *const payload, const char *const image) {
    assert(payload);
    if (payload->alert->action_loc_key) {
        apn_strfree(&payload->alert->action_loc_key);
    }
    if (image && strlen(image)) {
        if ((payload->alert->launch_image = apn_strndup(image, strlen(image))) == NULL) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

apn_return apn_payload_set_localized_key(apn_payload_t *const payload, const char *const key, apn_array_t * const args) {
    assert(payload);
    assert(key && strlen(key) > 0);

    if (payload->alert->loc_key) {
        apn_strfree(&payload->alert->loc_key);
        apn_array_free(payload->alert->loc_args);
    }

    payload->alert->loc_key = apn_strndup(key, strlen(key));
    payload->alert->loc_args = apn_array_copy(args);
    return APN_SUCCESS;
}

apn_return apn_payload_set_category(apn_payload_t *const payload, const char *const category) {
    assert(payload);
    if (payload->category) {
        apn_strfree(&payload->category);
    }
    if (category && strlen(category)) {
        if ((payload->category = apn_strndup(category, strlen(category))) == NULL) {
            errno = ENOMEM;
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

#define APN_PAYLOAD_CHECK_KEY(__payload, __property_name) \
    do {\
        if (!apn_string_is_utf8(__property_name)) {\
            errno = APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS;\
            return APN_ERROR;\
        }\
        if (__apn_payload_custom_property_name_already_is_used(__payload, __property_name)) {\
            errno = APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED;\
            return APN_ERROR;\
        }\
    } while(0);

apn_return apn_payload_add_custom_property_integer(apn_payload_t *const payload, const char *const name, int64_t value) {
    apn_payload_custom_property_t *property = NULL;
    assert(payload);
    assert(name);
    APN_PAYLOAD_CHECK_KEY(payload, name);
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NUMERIC;
    property->value.numeric_value = value;
    return apn_array_insert(payload->custom_properties, property);
}

apn_return apn_payload_add_custom_property_double(apn_payload_t *const payload, const char *const name, double value) {
    apn_payload_custom_property_t *property = NULL;
    assert(payload);
    assert(name);
    APN_PAYLOAD_CHECK_KEY(payload, name);
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_DOUBLE;
    property->value.double_value = value;
    return apn_array_insert(payload->custom_properties, property);
}

apn_return apn_payload_add_custom_property_bool(apn_payload_t *const payload, const char *const name, unsigned char value) {
    apn_payload_custom_property_t *property = NULL;
    assert(payload);
    assert(name);
    APN_PAYLOAD_CHECK_KEY(payload, name);
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_BOOL;
    property->value.bool_value = (uint8_t) ((value == 0) ? 0 : 1);
    return apn_array_insert(payload->custom_properties, property);
}

apn_return apn_payload_add_custom_property_null(apn_payload_t *const payload, const char *const name) {
    apn_payload_custom_property_t *property = NULL;
    assert(payload);
    assert(name);
    APN_PAYLOAD_CHECK_KEY(payload, name);
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NULL;
    property->value.string_value.value = NULL;
    property->value.string_value.length = 0;
    return apn_array_insert(payload->custom_properties, property);
}

apn_return apn_payload_add_custom_property_string(apn_payload_t *const payload, const char *const name, const char *value) {
    apn_payload_custom_property_t *property = NULL;
    assert(payload);
    assert(name);
    APN_PAYLOAD_CHECK_KEY(payload, name);
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_STRING;
    property->value.string_value.value = apn_strndup(value, strlen(value));
    if (!property->value.string_value.value) {
        __apn_payload_custom_property_free(property);
        errno = ENOMEM;
        return APN_ERROR;
    }
    property->value.string_value.length = strlen(value);
    return apn_array_insert(payload->custom_properties, property);
}

apn_return apn_payload_add_custom_property_array(apn_payload_t *const payload, const char *const name, const char **array,
                                                 uint8_t array_size) {
    char **_array = NULL;
    apn_payload_custom_property_t *property = NULL;
    uint8_t i = 0;
    assert(payload);
    assert(name);
    assert(array);
    APN_PAYLOAD_CHECK_KEY(payload, name);

    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_ARRAY;

    if (array_size) {
        _array = (char **) malloc(sizeof(char *) * array_size);
        if (!_array) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        for (i = 0; i < array_size; i++) {
            if ((_array[i] = apn_strndup(_array[i], strlen(_array[i]))) == NULL) {
                errno = ENOMEM;
                return APN_ERROR;
            }
        }
        property->value.array_value.array = _array;
        property->value.array_value.array_size = array_size;
    }
    return apn_array_insert(payload->custom_properties, property);
}

uint8_t apn_payload_content_available(const apn_payload_t *const payload) {
    assert(payload);
    return payload->content_available;
}

int32_t apn_payload_badge(const apn_payload_t *const payload) {
    assert(payload);
    return payload->badge;
}

const char *apn_payload_sound(const apn_payload_t *const payload) {
    assert(payload);
    return payload->sound;
}

const char *apn_payload_launch_image(const apn_payload_t *const payload) {
    assert(payload);
    return payload->alert->launch_image;
}

const char *apn_payload_localized_action_key(const apn_payload_t *const payload) {
    assert(payload);
    return payload->alert->action_loc_key;
}

const char *apn_payload_body(const apn_payload_t *const payload) {
    assert(payload);
    return payload->alert->body;
}

const char *apn_payload_localized_key(const apn_payload_t *const payload) {
    assert(payload);
    return payload->alert->loc_key;
}

apn_array_t *apn_payload_localized_key_args(const apn_payload_t * const payload) {
    assert(payload);
    return payload->alert->loc_args;
}

time_t apn_payload_expiry(const apn_payload_t *const payload) {
    assert(payload);
    return payload->expiry;
}

apn_notification_priority_t apn_payload_priority(const apn_payload_t *const payload) {
    assert(payload);
    return payload->priority;
}

const char *apn_payload_category(const apn_payload_t *const payload) {
    assert(payload);
    return payload->category;
}

char *apn_create_json_document_from_payload(const apn_payload_t *const payload) {
    json_t *root = NULL;
    json_t *aps = NULL;
    json_t *alert = NULL;
    json_t *args = NULL;
    json_t *array = NULL;
    char *json_document = NULL;
    uint32_t i = 0;
    uint32_t j = 0;

    assert(payload);

    root = json_object();
    aps = json_object();
    if (!root || !aps) {
        errno = APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT;
        return NULL;
    }

    if (!payload->alert || (!payload->alert->loc_key && !payload->alert->body && !payload->content_available)) {
        json_decref(root);
        json_decref(aps);
        errno = APN_ERR_PAYLOAD_ALERT_IS_NOT_SET;
        return NULL;
    }

    if (!payload->alert->action_loc_key && !payload->alert->launch_image && !payload->alert->loc_args &&
        !payload->alert->loc_key) {
        json_object_set_new(aps, "alert", json_string(payload->alert->body));
    } else {
        alert = json_object();
        if (!alert) {
            json_decref(root);
            json_decref(aps);
            errno = APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT;
            return NULL;
        }
        if (payload->alert->body) {
            json_object_set_new(alert, "body", json_string(payload->alert->body));
        }

        if (payload->alert->launch_image) {
            json_object_set_new(alert, "launch-image", json_string(payload->alert->launch_image));
        }

        if (payload->alert->action_loc_key) {
            json_object_set_new(alert, "action-loc-key", json_string(payload->alert->action_loc_key));
        }

        if (payload->alert->loc_key) {
            json_object_set_new(alert, "loc-key", json_string(payload->alert->loc_key));
        }

        if (payload->alert->loc_args) {
            args = json_array();
            for (i = 0; i < apn_array_count(payload->alert->loc_args); i++) {
                json_array_append(args, json_string(apn_array_item_at_index(payload->alert->loc_args, i)));
            }
            json_object_set_new(alert, "loc-args", args);
        }

        json_object_set_new(aps, "alert", alert);
    }

    if (payload->content_available == 1) {
        json_object_set_new(aps, "content-available", json_integer(payload->content_available));
    }

    if (payload->badge > -1) {
        json_object_set_new(aps, "badge", json_integer(payload->badge));
    }

    if (payload->sound) {
        json_object_set_new(aps, "sound", json_string(payload->sound));
    }

    if (payload->category) {
        json_object_set_new(aps, "category", json_string(payload->category));
    }

    json_object_set_new(root, "aps", aps);

    if(payload->custom_properties) {
        for (i = 0; i < apn_array_count(payload->custom_properties); i++) {
            apn_payload_custom_property_t *property = apn_array_item_at_index(payload->custom_properties, i);
            switch (property->value_type) {
                case APN_CUSTOM_PROPERTY_TYPE_BOOL:
                    json_object_set_new(root, property->name,
                                        ((property->value.bool_value == 0) ? json_false() : json_true()));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NUMERIC:
                    json_object_set_new(root, property->name, json_integer((json_int_t) property->value.numeric_value));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_NULL:
                    json_object_set_new(root, property->name, json_null());
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_STRING:
                    json_object_set_new(root, property->name, json_string(property->value.string_value.value));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_DOUBLE:
                    json_object_set_new(root, property->name, json_real(property->value.double_value));
                    break;
                case APN_CUSTOM_PROPERTY_TYPE_ARRAY: {
                    for (j = 0; j < property->value.array_value.array_size; j++) {
                        json_array_append(array, json_string(*(property->value.array_value.array + j)));
                    }
                    json_object_set_new(root, property->name, array);
                }
                    break;
            }
        }
    }
    json_document = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return json_document;
}

static apn_payload_custom_property_t *__apn_payload_custom_property_init(const char *name) {
    apn_payload_custom_property_t *property = malloc(sizeof(apn_payload_custom_property_t));
    if (!property) {
        errno = ENOMEM;
        return NULL;
    }
    if ((property->name = apn_strndup(name, strlen(name))) == NULL) {
        errno = ENOMEM;
        __apn_payload_custom_property_free(property);
        return NULL;
    }
    return property;
}

static uint8_t __apn_payload_custom_property_name_already_is_used(apn_payload_t *payload, const char *property_key) {
    apn_payload_custom_property_t *property = NULL;
    uint32_t i = 0;
    if (apn_array_count(payload->custom_properties)) {
        return 0;
    } else if (strcasecmp(property_key, "aps") == 0) {
        return 1;
    }
    for (i = 0; i < apn_array_count(payload->custom_properties); i++) {
        property = apn_array_item_at_index(payload->custom_properties, i);
        if (strcmp(property->name, property_key) == 0) {
            return 1;
        }
    }
    return 0;
}

static void __apn_payload_custom_property_dtor(void *data) {
    __apn_payload_custom_property_free(data);
}

void *__apn_payload_custom_property_ctor(const void * const data) {
    return __apn_payload_custom_property_copy(data);
}

static void __apn_payload_custom_property_free(apn_payload_custom_property_t *property) {
    uint32_t array_size = 0;
    uint32_t i = 0;

    if (property) {
        free(property->name);
        switch (property->value_type) {
            case APN_CUSTOM_PROPERTY_TYPE_STRING: {
                apn_mem_free(property->value.string_value.value);
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_ARRAY: {
                array_size = property->value.array_value.array_size;
                if (property->value.array_value.array && array_size > 0) {
                    for (i = 0; i < array_size; i++) {
                        free(*(property->value.array_value.array + i));
                    }
                    free(property->value.array_value.array);
                }
            } break;
            default: break;
        }
        free(property);
    }
}

static apn_payload_custom_property_t *__apn_payload_custom_property_copy(const apn_payload_custom_property_t * const property) {
    apn_payload_custom_property_t *new_property = NULL;
    uint32_t array_size = 0;
    uint32_t i = 0;
    if (property) {
        new_property =__apn_payload_custom_property_init(property->name);
        if(!new_property) {
            return NULL;
        }
        new_property->value_type = property->value_type;
        switch (property->value_type) {
            case APN_CUSTOM_PROPERTY_TYPE_STRING: {
                new_property->value.string_value.value = apn_strndup(property->value.string_value.value, property->value.string_value.length);
                new_property->value.string_value.length = property->value.string_value.length;
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_NULL: {
                new_property->value.string_value.value = NULL;
                new_property->value.string_value.length = 0;
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_BOOL: {
                new_property->value.bool_value = property->value.bool_value;
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_DOUBLE: {
                new_property->value.double_value = property->value.bool_value;
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_NUMERIC: {
                new_property->value.numeric_value = property->value.numeric_value;
            } break;
            case APN_CUSTOM_PROPERTY_TYPE_ARRAY: {
                if (property->value.array_value.array && property->value.array_value.array_size > 0) {
                    char **array = (char **) malloc(sizeof(char *) * array_size);
                    if (!array) {
                        errno = ENOMEM;
                        __apn_payload_custom_property_free(new_property);
                        return NULL;
                    }
                    for (i = 0; i < array_size; i++) {
                        if(NULL == (array[i] = apn_strndup(property->value.array_value.array[i], strlen(property->value.array_value.array[i])))){
                            errno = ENOMEM;
                            __apn_payload_custom_property_free(new_property);
                            return NULL;
                        }
                    }
                    new_property->value.array_value.array_size = property->value.array_value.array_size;
                    new_property->value.array_value.array = array;
                }
            }break;
        }
    }
    return new_property;
}

static apn_payload_alert_t *__apn_payload_alert_init() {
    apn_payload_alert_t *alert = malloc(sizeof(apn_payload_alert_t));
    if (!alert) {
        errno = ENOMEM;
        return NULL;
    }
    alert->action_loc_key = NULL;
    alert->body = NULL;
    alert->launch_image = NULL;
    alert->loc_args = NULL;
    alert->loc_key = NULL;
    return alert;
}
