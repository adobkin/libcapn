# libcapn

[![Build Status](http://img.shields.io/travis/adobkin/libcapn.svg?style=flat&branch=experimental)](http://travis-ci.org/adobkin/libcapn) [![MIT](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://github.com/adobkin/libcapn/blob/master/LICENSE)

libcapn is a C Library to interact with the [Apple Push Notification Service](http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html) using simple and intuitive API. 
With the library you can easily send push notifications to iOS and OS X (>= 10.8) devices. 

__THIS BRANCH IS EXPIREMENTAL__

## Installation

### on *nix

__Requires__

- CMake >= 2.8
- Clang 3 and later or GCC 4.6 and later
- make

__Builds__

```sh
$ git clone -b experimental https://github.com/adobkin/libcapn.git
$ git submodule update --init
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ../
$ make
$ sudo make install
```
		
### on Windows

__Requires__

- Microsoft Visual Studio >= 2008
- CMake >= 2.8

__Builds__

1. Download archive of sources from GitHub https://github.com/adobkin/libcapn/archive/experimental.zip and unpack it on your disk, e.g. `C:\libcapn`

2. Open command console (Win-R ==> "cmd" => Enter)

3. Go to the libcapn directory and run `win_build\build.bat`

```sh
cd C:\libcapn
win_build\build.bat
```
		
## Quick Start

In first step initialize library, calling `apn_library_init()`. This function must be called at least once within a program before the program calls any other other `libcapn` functions. `apn_library_init()` is not thread safe, you must not call it when any other thread in the program is running. `apn_library_init()` calls initialize functions of SSL library that are thread unsafe.

### Connecting

Initialize a new apn `context`, passing path to certificate and path to private key. If private key is password protected, pass it too, otherwise pass `NULL`:

```c
apn_ctx_ref ctx = apn_init("apns_test_cert.pem", "apns_test_key.pem", "12345678");
if(!ctx) {
	// error
}

```

By default the library uses production environment to interact with Apple Push Notification Service (APNS). Call `apn_set_mode()` passing `APN_MODE_SANDBOX` to use sandbox environment 

```c
 apn_set_mode(ctx,  APN_MODE_SANDBOX);
``` 

To create connection to the APNS, calling `apn_connect()` 

```c
if(APN_ERROR == apn_connect(ctx)) {
	printf("Could not connected to Apple Push Notification Service: %s (errno: %d)\n", apn_error_string(errno), errno);
	// error
}
```

### Sending a notification

To send a notification create a `payload` and set it properties:

```c
apn_payload_ref payload = apn_payload_init();
if(!payload) {
	printf("Unable to init payload: %s (%d)\n", apn_error_string(errno), errno);
	// error
}

apn_payload_set_badge(payload, 10);           
apn_payload_set_body(payload, "Test Push Message"); 
apn_payload_add_custom_property_integer(payload, "custom_property_integer", 100);
...
```

By default the library uses default priority to send notifications. Call `apn_payload_set_priority()`, passing `APN_NOTIFICATION_PRIORITY_HIGH` to use high priority:

```c
apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH); 
```

Next, add the device tokens as either a hexadecimal string:

```c
apn_payload_add_token(payload, "XXXXXXXX");
apn_payload_add_token(payload, "YYYYYYYY");
```

alternatively you can add tokens to `contex`:

```c
apn_add_token(ctx, "XXXXXXXX");
apn_add_token(ctx, "YYYYYYYY");
```

To send notification to devices call `apn_send()`, passing a `context` and a `payload`:

```c
if(APN_ERROR == apn_send(ctx, payload, &invalid_token)) {
	if(errno == APN_ERR_TOKEN_INVALID) {
		printf("Invalid token: %s\n", token);
	} else {
		printf("Could not sent push: %s (errno: %d)\n", apn_error_string(errno), errno);
	}
} 
```

## Example

#### Send notification

```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <capn/apn.h>

int main() {
    apn_payload_ref payload = NULL;
    apn_ctx_ref ctx = NULL;
    time_t time_now = 0;
    char *invalid_token = NULL;

    assert(apn_library_init());

    time(&time_now);

    if(NULL == (ctx = apn_init("apns_test_cert.pem", "apns_test_key.pem", "12345678"))) {
        printf("Unable to init context: %d\n", errno);
        goto error;
    }

    apn_set_mode(ctx,  APN_MODE_PRODUCTION); //APN_MODE_PRODUCTION or APN_MODE_SANDBOX

    if(APN_ERROR == apn_connect(ctx)) {
        printf("Could not connected to Apple Push Notification Service: %s (errno: %d)\n", apn_error_string(errno), errno);
        goto error;
    }
    
    if(NULL == (payload = apn_payload_init())) {
        printf("Unable to init payload: %d\n", errno);
        goto error;
    }

    apn_payload_add_token(payload, "XXXXXXXX");
    apn_payload_add_token(payload, "YYYYYYYY");
    apn_payload_set_badge(payload, 10); // Icon badge
    apn_payload_set_body(payload, "Test Push Message");  // Notification text
    apn_payload_set_expiry(payload, time_now + 3600); // Expires
    apn_payload_set_category(payload, "MY_CAT"); // Notification category
    apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH);  // Notification priority
    apn_payload_add_custom_property_integer(payload, "custom_property_integer", 100); // Custom property
    
    if(APN_ERROR == apn_send(ctx, payload, &invalid_token)) {
        if(errno == APN_ERR_TOKEN_INVALID) {
            printf("Invalid token: %s\n", invalid_token);
        } else {
            printf("Could not sent push: %s (errno: %d)\n", apn_error_string(errno), errno);
        }
        goto error;
    } 
    
    printf("Success!");
    
    apn_close(ctx);
    apn_free(&ctx);
    apn_payload_free(&payload);
    apn_library_free();

    return 0;

    error:
        apn_close(ctx);
        apn_free(&ctx);
        apn_payload_free(&payload);
        apn_library_free();
        return 1;
}

```

