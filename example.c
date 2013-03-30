#include <stdio.h>
#include <string.h>
#include <apn.h>

int main() {
    apn_payload_ctx_ref payload_ctx = NULL;
    apn_ctx_ref ctx = NULL;
    apn_error error;

    const char *cert_path = "/Users/antonio/apns-dev-cert.pem";
    const char *key_path = "/Users/antonio/apns-dev-key.pem";
    const char *token = "04C11AF19F8535381BC30D1F875EF9A0C626466932571C2AA2296B8C562D397C";

    if(apn_init(&ctx, &error) == APN_ERROR){
        printf("%s: %d\n", error.message, error.code);
        return 1;
    }
    
    apn_set_certificate(ctx, cert_path, NULL);
    apn_set_private_key(ctx, key_path, NULL);
    apn_add_token(ctx, token, NULL);
    
    if(apn_payload_init(&payload_ctx, &error) == APN_ERROR) {
        apn_free(&ctx, NULL);
        printf("%s: %d\n", error.message, error.code);
        return 1;
    }

    apn_payload_set_badge(payload_ctx, 10, NULL);
    apn_payload_set_body(payload_ctx, "This push was sent using libcapn. Please visit http://libcapn.org for more information",  NULL);    
      
    if(apn_connect(ctx, 1, &error) == APN_ERROR) {
       printf("Could not connected to Apple Push Notification Servece: %s (%d)\n", error.message, error.code);
       apn_payload_free(&payload_ctx, NULL);
       apn_free(&ctx, NULL);
       return 1;
    }
    
    /* Send first push message */
    if(apn_send(ctx, payload_ctx, &error) == APN_ERROR) {
       printf("Could not sent push: %s (%d)\n", error.message, error.code);
       apn_close(ctx);
       apn_payload_free(&payload_ctx, NULL);
       apn_free(&ctx, NULL);
       return 1;
    } 
    
    /* Сhange push message */
    // apn_payload_set_body(payload_ctx, "New Message", NULL); 
    // apn_payload_set_sound(payload_ctx, "default",  NULL);
    // apn_payload_add_custom_property_integer(payload_ctx, "test", 10, NULL);
    
    // /* Send changed push message */
    // apn_send(ctx, payload_ctx, NULL);
    
    apn_close(ctx);
    apn_payload_free(&payload_ctx, NULL);
    apn_free(&ctx, NULL);
    
    return 0;
}
