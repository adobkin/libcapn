#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <capn/apn.h>
#include <capn/apn_array.h>

void __apn_logging(apn_log_levels level, const char * const message, uint32_t len) {
    const char *prefix = NULL;
    switch(level) {
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

    printf("======> [apn][%s]: %s\n", prefix, message);
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
    apn_set_mode(ctx,  APN_MODE_SANDBOX); //APN_MODE_PRODUCTION or APN_MODE_SANDBOX
    apn_set_log_callback(ctx, __apn_logging);
    apn_set_behavior(ctx, APN_OPTION_RECONNECT);
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
    apn_array_insert(tokens, "1D2EE2B3A38689E0D43E6608FEDEFCA534BBAC6AD6930BFDA6F5CD72A7845671");
    apn_array_insert(tokens, "B80D06E9830D66EAE57CA1D4E139B7407A1C8C89E05644DA991825768CF65346");

    if(APN_ERROR == apn_connect(ctx)) {
        printf("Could not connected to Apple Push Notification Service: %s (errno: %d)\n", apn_error_string(errno), errno);
        apn_free(ctx);
        apn_payload_free(payload);
        apn_array_free(tokens);
        apn_library_free();
        return -1;
    }

    apn_array_t *invalid_tokens = NULL;
    int ret = 0;
    if (APN_ERROR == apn_send(ctx, payload, tokens, &invalid_tokens)) {
        printf("Could not send push: %s (errno: %d)\n", apn_error_string(errno), errno);
        ret = -1;
    } else {
        printf("Notification was successfully sent to %u device(s)\n",
               apn_array_count(tokens) - ((invalid_tokens) ? apn_array_count(invalid_tokens) : 0));
        if (invalid_tokens) {
            printf("Invalid tokens:\n");
            uint32_t i = 0;
            for (; i < apn_array_count(invalid_tokens); i++) {
                printf("    %u. %s\n", i, apn_array_item_at_index(invalid_tokens, i));
            }
            apn_array_free(invalid_tokens);
        }
    }

    apn_free(ctx);
    apn_payload_free(payload);
    apn_array_free(tokens);
    apn_library_free();

    return ret;
}