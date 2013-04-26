#include <stdio.h>
#include <string.h>
#include <capn/apn.h>
#include <capn/version.h>

int main() {
    apn_payload_ctx_ref payload_ctx = NULL;
    apn_ctx_ref ctx = NULL;
    apn_error_ref error = NULL;
    const char *push_message = "Test Push Message";
    const char *cert_path = "apns-dev-cert.pem";
    const char *key_path = "apns-dev-key.pem";
    const char *token = "04C11AF19F8535381BC30D1F875EF9A0C626466932571C2AA2296B8C562D397C";
    time_t time_now = 0;

    if(apn_init(&ctx, cert_path, key_path, NULL, &error) == APN_ERROR){
        printf("%s: %d\n", error->message,  APN_ERR_CODE_WITHOUT_CLASS(error->code));
        apn_error_free(&error);
        return 1;
    }
    apn_set_mode(ctx, APN_MODE_SANDBOX, NULL);
    apn_add_token(ctx, token, NULL);

    if(apn_payload_init(&payload_ctx, &error) == APN_ERROR) {
        printf("%s: %d\n", error->message, APN_ERR_CODE_WITHOUT_CLASS(error->code));
        apn_free(&ctx);
        apn_error_free(&error);
        return 1;
    }

    time(&time_now);
    
    apn_payload_set_badge(payload_ctx, 10, NULL);
    apn_payload_set_body(payload_ctx, push_message, NULL);
    apn_payload_set_expiry(payload_ctx, time_now + 3600, NULL);
    apn_payload_set_sound(payload_ctx, "default",  NULL);
    apn_payload_add_custom_property_integer(payload_ctx, "int_property", 20, NULL);
  
    if(apn_connect(ctx, &error) == APN_ERROR) {
       printf("Could not connected to Apple Push Notification Servece: %s (%d)\n", error->message, APN_ERR_CODE_WITHOUT_CLASS(error->code));
       apn_payload_free(&payload_ctx);
       apn_free(&ctx);
       apn_error_free(&error);
       return 1;
    }
    
    if(apn_send(ctx, payload_ctx, &error) == APN_ERROR) {
       printf("Could not sent push: %s (%d)\n", error->message,  APN_ERR_CODE_WITHOUT_CLASS(error->code));
       apn_close(ctx);
       apn_payload_free(&payload_ctx);
       apn_free(&ctx);
       apn_error_free(&error);
       return 1;
    } 

    apn_close(ctx);
    apn_payload_free(&payload_ctx);
    apn_free(&ctx);
    
    return 0;
}
