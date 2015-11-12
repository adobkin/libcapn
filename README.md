# libcapn

![](doc/images/apns.png)

[![Build Status](http://img.shields.io/travis/adobkin/libcapn.svg?style=flat&branch=experimental)](http://travis-ci.org/adobkin/libcapn) [![MIT](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://github.com/adobkin/libcapn/blob/master/LICENSE)

libcapn is a C Library to interact with the [Apple Push Notification Service](http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html) (APNs for short) using simple and intuitive API.
With the library you can easily send push notifications to iOS and OS X (>= 10.8) devices.

__Version 2.0.0 isn't compatible to version 1.0.x__

<!-- toc -->
* [Installation](#installation)
  * [on *nix](#on-nix)
  * [on Windows](#on-windows)
* [Quick Start](#quick-start)
  * [Initialize and configure context](#initialize-and-configure-context)
    * [Logging](#logging)
    * [Connection](#connection)
  * [Sending notifications](#sending-notifications)
    * [The notification payload](#the-notification-payload)
    * [Tokens](#tokens)
    * [Send](#send)
* [Example](#example)
    * [Send notification](#send-notification)

<!-- toc stop -->
## Installation

### on *nix

__Requirements__

- CMake >= 2.8
- Clang 3 and later or GCC 4.6 and later
- make

__Build instructions__

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

__Requirements__

- Microsoft Visual Studio >= 2008
- CMake >= 2.8

__Build instructions__

1. Download the source archive from GitHub https://github.com/adobkin/libcapn/archive/experimental.zip and extract it somewhere on your disk, e.g. `C:\libcapn`

2. Open command console (Win-R ==> "cmd" => Enter)

3. Go to the libcapn directory and run `win_build\build.bat`

```sh
cd C:\libcapn
win_build\build.bat
```

## Quick Start

First, initialize the library by calling `apn_library_init()`. This function must be called at least once before any calls to other `libcapn` functions. Because `apn_library_init()` is not thread-safe, you must not call it while any other thread in the program is running. The reason is that
`apn_library_init()` calls initialization functions of SSL library that are not thread-safe.

### Initialize and configure context

Create a new apn `context` and specify the path to a certificate file and the path to a private key file using `apn_set_certificate()`.
If the private key is password protected, pass it as well, otherwise pass `NULL`. The Certificate and the private key must be in PEM format.
An alternative way is to use a .p12 file instead of a certificate and a private key. Use `apn_set_pkcs12_file()` to specify the path to a .p12 file .
If a .p12 file is specified, certificate and private key arguments will be ignored.

```c
apn_ctx_t *ctx = apn_init();
if(!ctx) {
	// error
}

// Uses certificate and private key (in PEM format)
apn_set_certificate(ctx, "push_test.pem", "push_test_key.pem", "12345678");

// Uses .p12 file
apn_set_pkcs12_file(ctx, "push_test.p12", "123");
```

By default the library uses production environment to interact with Apple Push Notification Service (APNs). Call `apn_set_mode()` passing `APN_MODE_SANDBOX` to
use sandbox environment.

>Certificate and private key (or .p12 file) must conform to the specified mode, otherwise the notifications will not be
transported to the device.

```c
 apn_set_mode(ctx,  APN_MODE_SANDBOX);
```

#### Logging

For logging specify log level and pointer to callback-function using `apn_set_log_level()` and `apn_set_log_callback()`:

```c
void logfunc(apn_log_level level, const char * const message, uint32_t len) {
    printf("======> %s\n", message);
}

apn_set_log_level(ctx, APN_LOG_LEVEL_INFO | APN_LOG_LEVEL_ERROR | APN_LOG_LEVEL_DEBUG);
apn_set_log_callback(ctx, logfunc);

```

#### Connection

To establishes connection to the APNs, calling `apn_connect()`:

```c
if(APN_ERROR == apn_connect(ctx)) {
	printf("Could not connected to Apple Push Notification Service: %s (errno: %d)\n", apn_error_string(errno), errno);
	// error
}
```

### Sending notifications

#### The notification payload

Every remote notification includes a payload. The payload contains information about how the system should alert
the user as well as any custom data you provide.

To create a payload you need to use `apn_payload_init()`; to set general properties of the payload, use `apn_payload_set_*()` functions. You can also specify
custom properties using `apn_payload_add_custom_property_*()` functions:


```c
apn_payload_t *payload = apn_payload_init();
if(!payload) {
	printf("Unable to init payload: %s (%d)\n", apn_error_string(errno), errno);
	// error
}

apn_payload_set_badge(payload, 10);           
apn_payload_set_body(payload, "Test Push Message");

// Custom property
apn_payload_add_custom_property_integer(payload, "custom_property_integer", 100);
...
```

>In iOS 8 and later, the maximum size allowed for a payload is 2 kilobytes; prior to iOS 8
and in OS X, the maximum payload size is 256 bytes. APNs rejects any notification that exceeds this limit.

A payload may contain the `content-available` property. If this property is set to a value of 1, it lets the remote notification act as a “silent”
notification. When a silent notification arrives, iOS wakes up your app in the background so that you can get new data from your server or do background
information processing. Users aren’t told about the new or changed information that results from a silent notification.

By default the library uses default priority to notifications. Call `apn_payload_set_priority()`, passing `APN_NOTIFICATION_PRIORITY_HIGH`
to use high priority:

```c
apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH);
```

When you set high priority, notifications are sent immediately to devices. The notification must trigger an alert, sound, or badge
on the device. It is an error to use this priority for a push that contains only the `content-available` key. When you set default priority, notifications are sent at a time that
conserves power on the device receiving them.

#### Tokens

Next, create array of tokens and add the device tokens as either a hexadecimal string to array:

```c
apn_array_t *tokens = apn_array_init(2, NULL, NULL);
if(tokens) {
    apn_array_insert(tokens, "XXXXXXXX");
    apn_array_insert(tokens, "YYYYYYYY");
    apn_array_insert(tokens, "ZZZZZZZZ");
}
```

>Each push environment will issue a different token(s) for the same device or computer. The device token(s) for production
is different from the development one. If you are using a production mode, you must use a production token(s) and vice versa

#### Send

To send notification to devices call `apn_send()`, passing `context`, `payload` and array of `tokens`:

```c

uint32 invalid_token_index;

if(APN_ERROR == apn_send(ctx, payload, tokens, &invalid_token_index)) {
	if(errno == APN_ERR_TOKEN_INVALID) {
		printf("Invalid token: %s\n", (const char * const) apn_array_item_at_index(tokens, invalid_token_index));
	} else {
		printf("Could not sent push: %s (errno: %d)\n", apn_error_string(errno), errno);
	}
}
```

>The APNs drops the connection if it receives an invalid token. The APNs drops the connection if it receives an invalid token.
The function passes out an index of array for invalid token via pointer `invalid_token_index`. You'll need to reconnect and send notification to token(s)
following it, again.

You can use `apn_send2()` instead of `apn_send()`, this function automatically establishes new connection to APNs when connection is dropped.
The function establishes new connection to APNs only when invalid token has been sent, otherwise new connection will not be established.

When you use this function you can take invalid token, just specify a pointer to callback-function using `apn_set_invalid_token_callback`:

```c
void invalid_token(const char * const token, uint32_t index) {
    printf("======> Invalid token: %s (index: %d)\n", token, index);
}

...

apn_ctx_t *ctx = ...
apn_set_invalid_token_callback(ctx, invalid_token);
```

Callback function has the following prototype:

```c
void (*invalid_token_callback)(const char * const token, uint32_t index)
```

## Example

#### Send notification

```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <capn/apn.h>

void __apn_logging(apn_log_levels level, const char * const message, uint32_t len) {
    printf("======> %s\n", message);
}

void __apn_invalid_token(const char * const token, uint32_t index) {
    printf("======> Invalid token: %s (index: %d)\n", token, index);
}

int main() {
    apn_payload_t *payload = NULL;
    apn_ctx_t *ctx = NULL;
    time_t time_now = 0;
    char *invalid_token = NULL;

    assert(apn_library_init() == APN_SUCCESS);

    time(&time_now);

    if(NULL == (ctx = apn_init())) {
        printf("Unable to init context: %d\n", errno);
        apn_library_free();
        return -1;
    }

    apn_set_pkcs12_file(ctx, "push_test.p12", "12345678");
    apn_set_mode(ctx,  APN_MODE_PRODUCTION); //APN_MODE_PRODUCTION or APN_MODE_SANDBOX
    apn_set_log_level(ctx, APN_LOG_LEVEL_INFO | APN_LOG_LEVEL_ERROR | APN_LOG_LEVEL_DEBUG);
    apn_set_log_callback(ctx, __apn_logging);
    apn_set_invalid_token_callback(ctx, __apn_invalid_token);

    if(NULL == (payload = apn_payload_init())) {
        printf("Unable to init payload: %d\n", errno);
        apn_free(ctx);
        apn_library_free();
        return -1;
    }

    apn_payload_set_badge(payload, 10); // Icon badge
    apn_payload_set_body(payload, "Test Push Message");  // Notification text
    apn_payload_set_expiry(payload, time_now + 3600); // Expires
    apn_payload_set_priority(payload, APN_NOTIFICATION_PRIORITY_HIGH);  // Notification priority
    apn_payload_add_custom_property_integer(payload, "custom_property_integer", 100); // Custom property

    apn_array_t *tokens = apn_array_init(2, NULL, NULL);
    if(!tokens) {
        apn_free(ctx);
        apn_payload_free(payload);
        apn_library_free();
        return -1;
    }

    apn_array_insert(tokens, "XXXXXXXX");
    apn_array_insert(tokens, "YYYYYYYY");
    apn_array_insert(tokens, "ZZZZZZZZ");

    if(APN_ERROR == apn_connect(ctx)) {
        printf("Could not connect to Apple Push Notification Service: %s (errno: %d)\n", apn_error_string(errno), errno);
        apn_free(ctx);
        apn_payload_free(payload);
        apn_array_free(tokens);
        apn_library_free();
        return -1;
    }

    if(APN_ERROR == apn_send2(ctx, payload, tokens)) {
        printf("Could not send push: %s (errno: %d)\n", apn_error_string(errno), errno);
        apn_free(ctx);
        apn_payload_free(payload);
        apn_array_free(tokens);
        apn_library_free();
        return -1;
    }

    // Uses apn_send
    //if(APN_ERROR == apn_send(ctx, payload, tokens, &invalid_token)) {
    //    if(errno == APN_ERR_TOKEN_INVALID) {
    //        printf("Invalid token: %s\n", invalid_token);
    //    } else {
    //        printf("Could not send push: %s (errno: %d)\n", apn_error_string(errno), errno);
    //    }
    //    apn_free(ctx);
    //    apn_payload_free(payload);
    //    apn_array_free(tokens);
    //    apn_library_free();
    //    return -1;
    //}

    printf("Success!\n");

    apn_free(ctx);
    apn_payload_free(payload);
    apn_array_free(tokens);
    apn_library_free();

    return 0;
}

```
