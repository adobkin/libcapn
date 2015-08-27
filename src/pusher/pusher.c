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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "apn.h"
#include "apn_payload.h"
#include "apn_strings.h"

void __apn_logging(apn_log_levels level, const char *const message, uint32_t len) {
    const char *prefix = NULL;
    switch (level) {
        case APN_LOG_LEVEL_INFO:
            prefix = "inf";
            break;
        case APN_LOG_LEVEL_ERROR:
            prefix = "err";
            break;
        case APN_LOG_LEVEL_DEBUG:
            prefix = "dbg";
            break;
    }
    fprintf(stdout, "======> [apn][%s]: %s\n", prefix, message);
}

void __apn_invalid_token(const char *const token, uint32_t index) {
    fprintf(stderr, "Invalid token: %s\n", token);
}

void __apn_token_free(uint32_t index, void *data) {
    free(data);
}

apn_array_ref __apn_split_tokens(char *const tokens) {
    apn_array_ref array = apn_array_init(20, __apn_token_free, NULL);
    if (array) {
        char *p = strtok(tokens, ":");
        while (p) {
            char *token = apn_strndup(p, strlen(p));
            apn_array_insert(array, (void *) token);
            p = strtok(NULL, ":");
        }
        return array;
    }
    return NULL;
}

static void __apn_pusher_usage(void) {

    fprintf(stderr, "apn-pusher - simple tool to send push notifications to iOS and OS X devices \n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: apn-pusher [OPTION]\n");
    fprintf(stderr, "    -h Print this message and exit\n");
    fprintf(stderr, "    -c Path to .p12 file (required)\n");
    fprintf(stderr, "    -p Passphrase for .p12 file (required)\n");
    fprintf(stderr, "    -d Use sandbox mode\n");
    fprintf(stderr, "    -m Body of the alert to send in notification\n");
    fprintf(stderr, "    -a Indicates content available\n");
    fprintf(stderr, "    -c Body of the alert to send in notification\n");
    fprintf(stderr, "    -b Badge number to set with notification\n");
    fprintf(stderr, "    -s Name of a sound file in the app bundle\n");
    fprintf(stderr, "    -l Name of an image file in the app bundle\n");
    fprintf(stderr, "    -y Category name of notification\n");
    fprintf(stderr, "    -t Device token(s). Separate multiple tokens with ':' (required)\n");
    fprintf(stderr, "    -t Make the operation more talkative\n");
}

int main(int argc, char **argv) {
    uint8_t args_error = 0;
    uint8_t ret = 0;

    char *pass = NULL;
    char *p12 = NULL;

    apn_ctx_ref apn_ctx = NULL;
    apn_payload_ref payload = NULL;

    if (argc < 2) {
        __apn_pusher_usage();
        return 1;
    }

    setvbuf(stderr, NULL, _IOLBF, 0);

    assert(apn_library_init() == APN_SUCCESS);

    if (NULL == (apn_ctx = apn_init())) {
        printf("Unable to init context: %d\n", errno);
        apn_library_free();
        return -1;
    }

    if (NULL == (payload = apn_payload_init())) {
        printf("Unable to init payload: %d\n", errno);
        apn_free(&apn_ctx);
        apn_library_free();
        return -1;
    }

    apn_array_ref tokens = NULL;

    apn_set_log_level(apn_ctx, APN_LOG_LEVEL_ERROR);
    apn_set_log_cb(apn_ctx, __apn_logging);
    apn_set_invalid_token_cb(apn_ctx, __apn_invalid_token);
    apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH);

    const char *const opts = "ahc:p:dm:b:s:l:e:y:t:v";
    int c = -1;

    while ((c = getopt(argc, argv, opts)) != -1) {
        switch (c) {
            case 'h':
                __apn_pusher_usage();
                return 1;
            case 'd':
                apn_set_mode(apn_ctx, APN_MODE_SANDBOX);
                break;
            case 'b':
                apn_payload_set_badge(payload, atoi(optarg));
            case 'm':
                apn_payload_set_body(payload, optarg);
                break;
            case 'c':
                p12 = apn_strndup(optarg, strlen(optarg));
                break;
            case 'p':
                pass = apn_strndup(optarg, strlen(optarg));
                break;
            case 's':
                apn_payload_set_sound(payload, optarg);
                break;
            case 'l':
                apn_payload_set_launch_image(payload, optarg);
                break;
            case 'y':
                apn_payload_set_category(payload, optarg);
                break;
            case 't':
                tokens = __apn_split_tokens(optarg);
                break;
            case 'a':
                apn_payload_set_content_available(payload, 1);
                break;
            case 'v':
                apn_set_log_level(apn_ctx, APN_LOG_LEVEL_INFO | APN_LOG_LEVEL_ERROR | APN_LOG_LEVEL_DEBUG);
                break;
            case '?':
                if (optopt == 'c') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                }
                args_error = 1;
                break;
        }
    }

    if (args_error) {
        ret = 1;
        goto finish;
    }

    if (p12) {
        if (!pass) {
            fprintf(stderr, "Missing passphrase option\n");
            ret = 1;
            goto finish;
        }
        apn_set_pkcs12_file(apn_ctx, p12, pass);
    } else {
        fprintf(stderr, "Missing .p12 file option\n");
    }

    if (!tokens || apn_array_count(tokens) == 0) {
        fprintf(stderr, "Missing device token\n");
        ret = 1;
        goto finish;
    }

    if (APN_ERROR == apn_connect(apn_ctx)) {
        fprintf(stderr, "Could not connected to Apple Push Notification Service: %s (errno: %d)\n",
                apn_error_string(errno), errno);
        ret = 1;
    } else {
        if (APN_ERROR == apn_send2(apn_ctx, payload, tokens)) {
            ret = 1;
            fprintf(stderr, "Could not send push: %s (errno: %d)\n", apn_error_string(errno), errno);
        } else {
            fprintf(stderr, "Notification was sucessfully sent!\n");
        }
    }

    finish:
    apn_strfree(&pass);
    apn_strfree(&p12);

    apn_free(&apn_ctx);
    apn_payload_free(&payload);
    apn_library_free();
    apn_array_free(tokens);
    apn_library_free();

    return ret;

}
