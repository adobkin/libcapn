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
#include "apn_paload_private.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

static apn_payload_alert_ref __apn_payload_alert_init();
static void __apn_payload_custom_property_free(apn_payload_custom_property_ref *property);
static uint8_t __apn_payload_custom_property_name_already_is_used(apn_payload_ref payload_ctx, const char *property_key);
static apn_return __apn_payload_custom_property_realloc_if_needed(apn_payload_ref payload);
apn_payload_custom_property_ref __apn_payload_custom_property_init(const char *name);

apn_payload_ref apn_payload_init() {
    apn_payload_ref payload = NULL;
    payload = malloc(sizeof(apn_payload));
    if (!payload) {
        errno = ENOMEM;
        return NULL;
    }

    if (NULL == (payload->alert = __apn_payload_alert_init())) {
        free(payload);
        return NULL;
    }

    payload->badge = -1;
    payload->sound = NULL;
    payload->category = NULL;
    payload->custom_properties_count = 0;
    payload->custom_properties = NULL;
    payload->expiry = 0;
    payload->content_available = 0;
    payload->custom_properties_allocated = 0;
    payload->priority = APN_NOTIFICATION_PRIORITY_DEFAULT;

    return payload;
}

void apn_payload_free(apn_payload_ref *payload) {
    if (payload && *payload) {
        if ((*payload)->alert) {
            if ((*payload)->alert->action_loc_key) {
                free((*payload)->alert->action_loc_key);
            }
            if ((*payload)->alert->body) {
                free((*payload)->alert->body);
            }
            if ((*payload)->alert->launch_image) {
                free((*payload)->alert->launch_image);
            }
            if ((*payload)->alert->loc_key) {
                free((*payload)->alert->loc_key);
            }

            if ((*payload)->alert->loc_args && (*payload)->alert->loc_args_count > 0) {
                uint16_t i = 0;
                for (i = 0; i < (*payload)->alert->loc_args_count; i++) {
                    char *arg = *((*payload)->alert->loc_args + i);
                    free(arg);
                }
                free((*payload)->alert->loc_args);
            }
            free((*payload)->alert);
        }
        if ((*payload)->sound) {
            free((*payload)->sound);
        }
        if ((*payload)->category) {
            free((*payload)->category);
        }
        if ((*payload)->custom_properties && (*payload)->custom_properties_allocated > 0) {
            uint8_t i = 0;
            for (i = 0; i < (*payload)->custom_properties_allocated; i++) {
                __apn_payload_custom_property_free((*payload)->custom_properties + i);
            }
            free((*payload)->custom_properties);
        }
        free((*payload));
        *payload = NULL;
    }
}

void apn_payload_set_priority(apn_payload_ref payload, apn_notification_priority priority) {
    assert(payload);
    if(APN_NOTIFICATION_PRIORITY_DEFAULT != priority && APN_NOTIFICATION_PRIORITY_HIGH != priority) {
        priority = APN_NOTIFICATION_PRIORITY_DEFAULT;
    }
    payload->priority = priority;
}

void apn_payload_set_expiry(apn_payload_ref payload, time_t expiry) {
    assert(payload);
    payload->expiry = expiry;
}

apn_return apn_payload_set_badge(apn_payload_ref payload, int32_t badge) {
    assert(payload);
    if (badge < 0 || badge > UINT16_MAX) {
        errno = APN_ERR_PAYLOAD_BADGE_INVALID_VALUE;
        return APN_ERROR;
    }
    payload->badge = badge;
    return APN_SUCCESS;
}

apn_return apn_payload_set_sound(apn_payload_ref payload, const char *const sound) {
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

void apn_payload_set_content_available(apn_payload_ref payload, uint8_t content_available) {
    assert(payload);
    payload->content_available = (uint8_t) ((content_available == 1) ? 1 : 0);
}

apn_return apn_payload_set_body(apn_payload_ref payload, const char *const body) {
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

apn_return apn_payload_set_localized_action_key(apn_payload_ref payload, const char *const key) {
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

apn_return apn_payload_set_launch_image(apn_payload_ref payload, const char *const image) {
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

apn_return apn_payload_set_localized_key(apn_payload_ref payload, const char *const key, char **args, uint16_t args_count) {
    char *arg = NULL;
    uint16_t i = 0;
    uint16_t args_i = 0;

    assert(payload);
    assert(key && strlen(key) > 0);

    if (payload->alert->loc_key) {
        apn_strfree(&payload->alert->loc_key);
        if (payload->alert->loc_args && payload->alert->loc_args_count) {
            for (i = 0; i < payload->alert->loc_args_count; i++) {
                arg = *(payload->alert->loc_args + i);
                free(arg);
            }
            free(payload->alert->loc_args);
            payload->alert->loc_args = NULL;
        }
    }

    payload->alert->loc_key = apn_strndup(key, strlen(key));
    if (args && args_count > 0) {
        payload->alert->loc_args = (char **) malloc((args_count) * sizeof(char *));
        if (!payload->alert->loc_args) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        for (args_i = 0; args_i < args_count; args_i++) {
            if ((payload->alert->loc_args[args_i] = apn_strndup(args[args_i], strlen(args[args_i]))) == NULL) {
                errno = ENOMEM;
                return APN_ERROR;
            }
            payload->alert->loc_args_count++;
        }
    }

    return APN_SUCCESS;
}

apn_return apn_payload_set_category(apn_payload_ref payload, const char *const category) {
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

apn_return apn_payload_add_custom_property_integer(apn_payload_ref payload, const char *const name, int64_t value) {
    apn_payload_custom_property_ref property = NULL;

    assert(payload);
    assert(name);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }

    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NUMERIC;
    property->value.numeric_value = value;
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;

    return APN_SUCCESS;
}

apn_return apn_payload_add_custom_property_double(apn_payload_ref payload, const char *const name, double value) {
    apn_payload_custom_property_ref property = NULL;

    assert(payload);
    assert(name);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }

    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_DOUBLE;
    property->value.double_value = value;
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;

    return APN_SUCCESS;
}

apn_return apn_payload_add_custom_property_bool(apn_payload_ref payload, const char *const name, unsigned char value) {
    apn_payload_custom_property_ref property = NULL;

    assert(payload);
    assert(name);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }
    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_BOOL;
    property->value.bool_value = (uint8_t) ((value == 0) ? 0 : 1);
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;

    return APN_SUCCESS;
}

apn_return apn_payload_add_custom_property_null(apn_payload_ref payload, const char *const name) {
    apn_payload_custom_property_ref property = NULL;

    assert(payload);
    assert(name);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }

    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }
    property->value_type = APN_CUSTOM_PROPERTY_TYPE_NULL;
    property->value.string_value.value = NULL;
    property->value.string_value.length = 0;
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;

    return APN_SUCCESS;
}

apn_return apn_payload_add_custom_property_string(apn_payload_ref payload, const char *const name, const char *value) {
    apn_payload_custom_property_ref property = NULL;

    assert(payload);
    assert(name);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }

    property = __apn_payload_custom_property_init(name);
    if (!property) {
        return APN_ERROR;
    }

    property->value_type = APN_CUSTOM_PROPERTY_TYPE_STRING;
    property->value.string_value.value = apn_strndup(value, strlen(value));
    if (!property->value.string_value.value) {
        __apn_payload_custom_property_free(&property);
        errno = ENOMEM;
        return APN_ERROR;
    }
    property->value.string_value.length = 0;
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;

    return APN_SUCCESS;
}

apn_return apn_payload_add_custom_property_array(apn_payload_ref payload, const char *const name, const char **array, uint8_t array_size) {
    char **_array = NULL;
    apn_payload_custom_property_ref property = NULL;
    uint8_t i = 0;

    assert(payload);
    assert(name);
    assert(array);

    APN_PAYLOAD_CHECK_KEY(payload, name);

    if (APN_ERROR == __apn_payload_custom_property_realloc_if_needed(payload)) {
        return APN_ERROR;
    }

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
    payload->custom_properties[payload->custom_properties_count] = property;
    payload->custom_properties_count++;
    return APN_SUCCESS;
}

uint8_t apn_payload_content_available(const apn_payload_ref payload) {
    assert(payload);
    return payload->content_available;
}

int32_t apn_payload_badge(const apn_payload_ref payload) {
    assert(payload);
    return payload->badge;
}

const char *apn_payload_sound(const apn_payload_ref payload) {
    assert(payload);
    return payload->sound;
}

const char *apn_payload_launch_image(const apn_payload_ref payload) {
    assert(payload);
    return payload->alert->launch_image;
}

const char *apn_payload_localized_action_key(const apn_payload_ref payload) {
    assert(payload);
    return payload->alert->action_loc_key;
}

const char *apn_payload_body(const apn_payload_ref payload) {
    assert(payload);
    return payload->alert->body;
}

const char *apn_payload_localized_key(const apn_payload_ref payload) {
    assert(payload);
    return payload->alert->loc_key;
}

uint16_t apn_payload_localized_key_args(const apn_payload_ref payload, char ***args) {
    assert(payload);
    *args = NULL;
    if (payload->alert->loc_args && payload->alert->loc_args_count) {
        *args = payload->alert->loc_args;
        return payload->alert->loc_args_count;
    }
    return 0;
}

time_t apn_payload_expiry(apn_payload_ref payload) {
    assert(payload);
    return payload->expiry;
}

apn_notification_priority apn_payload_priority(const apn_payload_ref payload) {
    assert(payload);
    return payload->priority;
}

const char *apn_payload_category(const apn_payload_ref payload) {
    assert(payload);
    return payload->category;
}

static void __apn_payload_custom_property_free(apn_payload_custom_property_ref *property) {
    apn_payload_custom_property_ref _property = NULL;
    uint8_t array_size = 0;
    uint8_t i = 0;

    if (property && *property) {
        _property = *property;
        free(_property->name);
        switch (_property->value_type) {
            case APN_CUSTOM_PROPERTY_TYPE_STRING: {
                if (_property->value.string_value.value) {
                    free(_property->value.string_value.value);
                }
            }
                break;
            case APN_CUSTOM_PROPERTY_TYPE_ARRAY: {
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

static apn_payload_alert_ref __apn_payload_alert_init() {
    apn_payload_alert_ref alert = malloc(sizeof(apn_payload_alert));
    if (!alert) {
        errno = ENOMEM;
        return NULL;
    }
    alert->action_loc_key = NULL;
    alert->body = NULL;
    alert->launch_image = NULL;
    alert->loc_args = NULL;
    alert->loc_key = NULL;
    alert->loc_args_count = 0;
    return alert;
}

static uint8_t __apn_payload_custom_property_name_already_is_used(apn_payload_ref payload_ctx, const char *property_key) {
    apn_payload_custom_property_ref property = NULL;
    uint8_t i = 0;
    if (payload_ctx->custom_properties_count == 0 || payload_ctx->custom_properties == NULL) {
        return 0;
    } else if(strcasecmp(property_key, "aps") == 0) {
        return 1;
    }
    for (i = 0; i < payload_ctx->custom_properties_count; i++) {
        property = *(payload_ctx->custom_properties + 0);
        if (strcmp(property->name, property_key) == 0) {
            return 1;
        }
    }
    return 0;
}

static apn_return __apn_payload_custom_property_realloc_if_needed(apn_payload_ref payload) {
    apn_payload_custom_property_ref *properties = NULL;
    size_t chunk = sizeof(apn_payload_custom_property_ref *) * 10;
    if (payload->custom_properties_allocated == 0) {
        payload->custom_properties = (apn_payload_custom_property_ref *) malloc(chunk);
        if (!payload->custom_properties) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        memset(payload->custom_properties, 0, chunk);
        payload->custom_properties_allocated = 10;
    } else if (payload->custom_properties_allocated <= payload->custom_properties_count + 1) {
        properties = (apn_payload_custom_property_ref *) apn_realloc(payload->custom_properties, (payload->custom_properties_allocated * sizeof(apn_payload_custom_property_ref)) + chunk);
        if (!properties) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        memset(properties + payload->custom_properties_allocated, 0, chunk);
        payload->custom_properties = properties;
        payload->custom_properties_allocated *= 2;
    }
    return APN_SUCCESS;
}

char *apn_create_json_document_from_payload(const apn_payload_ref payload) {
    json_t *root = NULL;
    json_t *aps = NULL;
    json_t *alert = NULL;
    json_t *args = NULL;
    json_t *array = NULL;
    char *json_document = NULL;
    uint16_t i = 0;
    uint8_t array_i = 0;

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

    if (!payload->alert->action_loc_key && !payload->alert->launch_image && !payload->alert->loc_args && !payload->alert->loc_key) {
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

        if (payload->alert->loc_args_count > 0 && payload->alert->loc_args) {
            args = json_array();
            for (i = 0; i < payload->alert->loc_args_count; i++) {
                json_array_append(args, json_string(*(payload->alert->loc_args + i)));
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

    if (payload->custom_properties && payload->custom_properties_count) {
        for (i = 0; i < payload->custom_properties_count; i++) {
            apn_payload_custom_property_ref property = *(payload->custom_properties + i);
            switch (property->value_type) {
                case APN_CUSTOM_PROPERTY_TYPE_BOOL:
                    json_object_set_new(root, property->name, ((property->value.bool_value == 0) ? json_false() : json_true()));
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
                    for (array_i = 0; array_i < property->value.array_value.array_size; array_i++) {
                        json_array_append(array, json_string(*(property->value.array_value.array + array_i)));
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

apn_payload_custom_property_ref __apn_payload_custom_property_init(const char *name) {
    apn_payload_custom_property_ref property = malloc(sizeof(apn_payload_custom_property));
    if (!property) {
        errno = ENOMEM;
        return NULL;
    }
    if ((property->name = apn_strndup(name, strlen(name))) == NULL) {
        errno = ENOMEM;
        __apn_payload_custom_property_free(&property);
        return NULL;
    }
    return property;
}
