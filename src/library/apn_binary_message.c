/*
* Copyright (c) 2013, 2014, 2015 Anton Dobkin
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

#include "apn_platform.h"
#include <errno.h>
#include <assert.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "apn.h"
#include "apn_strings.h"
#include "apn_binary_message_private.h"
#include "apn_paload_private.h"
#include "apn_tokens.h"

static apn_return __apn_binary_message_set_token(apn_binary_message_ref binary_message, const uint8_t * const token_binary, const char * const token_hex);

apn_binary_message_ref apn_binary_message_init(uint32_t size) {
    apn_binary_message_ref binary_message = malloc(sizeof(apn_binary_message));
    if (!binary_message) {
        errno = ENOMEM;
        return NULL;
    }
    binary_message->message = malloc(size);
    if (!binary_message->message) {
        errno = ENOMEM;
        free(binary_message);
        return NULL;
    };
    binary_message->size = size;
    binary_message->id_position = NULL;
    binary_message->token_position = NULL;
    binary_message->token_hex = NULL;
    return binary_message;
}

void apn_binary_message_free(apn_binary_message_ref binary_message) {
    if (binary_message) {
        if (binary_message->message) {
            free(binary_message->message);
        }
        if(binary_message->token_hex) {
            free(binary_message->token_hex);
        }
        free(binary_message);
    }
}

void apn_binary_message_set_id(apn_binary_message_ref binary_message, uint32_t id) {
    uint32_t id_n = htonl(id);
    if (binary_message && binary_message->id_position) {
        memcpy(binary_message->id_position, &id_n, sizeof(uint32_t));
    }
}

void apn_binary_message_set_token(apn_binary_message_ref binary_message, const uint8_t * const token_binary) {
    char *token_hex = NULL;
    assert(token_binary);
    token_hex = apn_token_binary_to_hex(token_binary);
    __apn_binary_message_set_token(binary_message, token_binary, token_hex);
    free(token_hex);
}

apn_return apn_binary_message_set_token_hex(apn_binary_message_ref binary_message, const char * const token_hex) {
    uint8_t *token_binary = NULL;
    apn_return ret;
    assert(token_hex);
    token_binary = apn_token_hex_to_binary(token_hex);
    ret = __apn_binary_message_set_token(binary_message, token_binary, token_hex);
    free(token_binary);
    return ret;
}

const char * apn_binary_message_token_hex(apn_binary_message_ref binary_message) {
    assert(binary_message);
    return binary_message->token_hex;
}

apn_binary_message_ref apn_create_binary_message(const apn_payload_ref payload) {
    char *json = NULL;
    size_t json_size = 0;
    uint8_t *frame = NULL;
    uint8_t *frame_ref = NULL;
    size_t frame_size = 0;
    uint32_t id_n = 0; // ID (network ordered)
    uint32_t expiry_n = htonl((uint32_t) payload->expiry); // expiry time (network ordered)
    uint8_t item_id = 1; // Item ID
    uint16_t item_data_size_n = 0; // Item data size (network ordered)
    uint8_t *message_ref = NULL;
    uint32_t frame_size_n; // Frame size (network ordered)
    apn_binary_message_ref binary_message;

    json = apn_create_json_document_from_payload(payload);
    if (!json) {
        return NULL;
    }

    json_size = strlen(json);
    if (json_size > APN_PAYLOAD_MAX_SIZE) {
        errno = APN_ERR_INVALID_PAYLOAD_SIZE;
        free(json);
        return NULL;
    }

    frame_size = ((sizeof(uint8_t) + sizeof(uint16_t)) * 5)
            + APN_TOKEN_BINARY_SIZE
            + json_size
            + sizeof(uint32_t)
            + sizeof(uint32_t)
            + sizeof(uint8_t);

    frame_size_n = htonl(frame_size);
    frame = malloc(frame_size);
    if (!frame) {
        errno = ENOMEM;
        return NULL;
    }
    frame_ref = frame;

    binary_message = apn_binary_message_init((uint32_t) (frame_size + sizeof(uint32_t) + sizeof(uint8_t)));
    if (!binary_message) {
        return NULL;
    }
    message_ref = binary_message->message;

    /* Token */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(APN_TOKEN_BINARY_SIZE);
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    frame_ref += APN_TOKEN_BINARY_SIZE;

    /* Payload */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(json_size);
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, json, json_size);
    frame_ref += json_size;

    free(json);

    /* Message ID */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof(uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, &id_n, sizeof(uint32_t));
    frame_ref += sizeof(uint32_t);

    /* Expires */
    *frame_ref++ = item_id++;
    item_data_size_n = htons(sizeof(uint32_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    memcpy(frame_ref, &expiry_n, sizeof(uint32_t));
    frame_ref += sizeof(uint32_t);

    /* Priority */
    *frame_ref++ = item_id;
    item_data_size_n = htons(sizeof(uint8_t));
    memcpy(frame_ref, &item_data_size_n, sizeof(uint16_t));
    frame_ref += sizeof(uint16_t);
    *frame_ref = (uint8_t) payload->priority;

    /* Binary message */
    *message_ref++ = 2;
    memcpy(message_ref, &frame_size_n, sizeof(uint32_t));
    message_ref += sizeof(uint32_t);
    memcpy(message_ref, frame, frame_size);

    binary_message->token_position = message_ref + (sizeof(uint8_t) + sizeof(uint16_t));
    binary_message->id_position = binary_message->token_position + (APN_TOKEN_BINARY_SIZE + ((sizeof(uint8_t) + sizeof(uint16_t)) * 2) + json_size);

    free(frame);
    return binary_message;
}

static apn_return __apn_binary_message_set_token(apn_binary_message_ref binary_message, const uint8_t * const token_binary, const char * const token_hex) {
    if(!apn_hex_token_is_valid(token_hex)) {
        errno = APN_ERR_TOKEN_INVALID;
        return APN_ERROR;
    }
    if (binary_message && binary_message->token_position) {
        memcpy(binary_message->token_position, token_binary, APN_TOKEN_BINARY_SIZE);
        binary_message->token_hex = apn_strndup(token_hex, APN_TOKEN_LENGTH);
    }
    return APN_SUCCESS;
}
