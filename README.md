# LIBCAPN
[![Build Status](http://img.shields.io/travis/adobkin/libcapn.svg?style=flat&branch=experimental)](http://travis-ci.org/adobkin/libcapn) [![MIT](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://github.com/adobkin/libcapn/blob/master/LICENSE)

libcapn is a C Library to interact with the [Apple Push Notification Service](http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html) using simple and intuitive API. 
With the library you can easily send push notifications to iOS and OS X (>= 10.8) devices. 

__THIS BRANCH IS EXPIREMENTAL__

## Examples

#### Send notification

```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <capn/apn.h>

int main() {
    apn_payload_ref payload = NULL;
    apn_ctx_ref ctx = NULL;
    time_t time_now = 0;
    uint8_t ret = 0;

    if(APN_ERROR == apn_library_init()) {
        printf("Unable to init capn library: %d\n", errno);
        return 1;
    }

    ctx = apn_init("apns_test_cert.pem", "apns_test_key.pem", "12345678");
    if(!ctx) {
        printf("Unable to init context: %d\n", errno);
        apn_library_free();
        return 1;
    }

    apn_set_mode(ctx,  APN_MODE_PRODUCTION); // mode APN_MODE_PRODUCTION or APN_MODE_SANDBOX

    payload = apn_payload_init();
    if(!payload) {
        printf("Unable to init payload: %d\n", errno);
        apn_free(&ctx);
        apn_library_free();
        return 1;
    }

    apn_payload_add_token(payload, "XXXXXXXX");
    apn_payload_add_token(payload, "YYYYYYYY");

    time(&time_now);

    apn_payload_set_badge(payload, 10); // Icon badge             
    apn_payload_set_body(payload, "Test Push Message");  // Notification text
    apn_payload_set_expiry(payload, time_now + 3600); // Expires
    apn_payload_set_category(payload, "MY_CAT"); // Notification category
    apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH);  // Notification priority
    apn_payload_add_custom_property_integer(payload, "custom_property_integer", 100); // Custom property

    if(APN_ERROR == apn_connect(ctx)) {
       printf("Could not connected to Apple Push Notification Servece: errno: %d\n", errno);
       ret =  1;
    } else {
        if(APN_ERROR == apn_send(ctx, payload)) {
           printf("Could not sent push: errno: %d\n", errno);
           ret = 1;
        } else {
            printf("Success!");
        }
    }

    apn_close(ctx);
    
    apn_payload_free(&payload);
    apn_free(&ctx);

    apn_library_free();

    return ret;
}

```

