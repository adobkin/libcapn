#include <stdio.h>
#include <string.h>
#include <capn/apn.h>

int main() {
    apn_payload_ctx_ref payload_ctx = NULL;
    apn_ctx_ref ctx = NULL;
    apn_error error;
    const char *push_message = "Test Push Message";
    const char *cert_path = "apns-dev-cert.pem";
    const char *key_path = "apns-dev-key.pem";
    const char *token = "04C11AF19F8535381BC30D1F875EF9A0C626466932571C2AA2296B8C562D397C";

    if(apn_init(&ctx, &error) == APN_ERROR){
        printf("%s: %d\n", error.message,  APN_ERR_CODE_WITHOUT_CLASS(error.code));
        return 1;
    }

    apn_set_certificate(ctx, cert_path, NULL);
    
#if APN_VERSION_NUM >= 0x010000
    apn_set_private_key(ctx, key_path, NULL, NULL);
#else
    apn_set_private_key(ctx, key_path, NULL);
#endif
    
    apn_add_token(ctx, token, NULL);

    if(apn_payload_init(&payload_ctx, &error) == APN_ERROR) {
        printf("%s: %d\n", error.message, APN_ERR_CODE_WITHOUT_CLASS(error.code));
        apn_free(&ctx, NULL);
        return 1;
    }

    apn_payload_set_badge(payload_ctx, 10, NULL);
    apn_payload_set_body(payload_ctx, push_message, NULL);
    apn_payload_set_sound(payload_ctx, "default",  NULL);
    apn_payload_add_custom_property_integer(payload_ctx, "int_property", 20, NULL);
  
    if(apn_connect(ctx, 1, &error) == APN_ERROR) {
       printf("Could not connected to Apple Push Notification Servece: %s (%d)\n", error.message, error.code);
       apn_payload_free(&payload_ctx, NULL);
       apn_free(&ctx, NULL);
       return 1;
    }

    if(apn_send(ctx, payload_ctx, &error) == APN_ERROR) {
       printf("Could not sent push: %s (%d)\n", error.message,  APN_ERR_CODE_WITHOUT_CLASS(error.code));
       apn_close(ctx);
       apn_payload_free(&payload_ctx, NULL);
       apn_free(&ctx, NULL);
       return 1;
    } 

    apn_close(ctx);
    apn_payload_free(&payload_ctx, NULL);
    apn_free(&ctx, NULL);
    
    return 0;
}