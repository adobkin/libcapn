#include <stdio.h>
#include <string.h>
#include <apn.h>
#include <version.h>

int main() {
    apn_ctx_ref ctx = NULL;
    apn_error error;
    char **tokens = NULL;
    uint32_t tokens_count = 0;
    uint32_t i = 0;
    
    if(apn_init(&ctx, &error) == APN_ERROR){
        printf("%s: %d\n", error.message, error.code);
        return 1;
    }

    apn_set_certificate(ctx, "/Users/antonio/apns-dev-cert.pem", NULL);
    
#if APN_VERSION_NUM >= 0x010000
    apn_set_private_key(ctx, "/Users/antonio/apns-dev-key.pem", NULL, NULL);
#else
    apn_set_private_key(ctx, "apns-dev-key.pem", NULL);
#endif
    
   
    if(apn_feedback_connect(ctx, 1, &error) == APN_ERROR) {
       printf("Could not connected to Apple Feedback Servece: %s (%d)\n", error.message, error.code);
       apn_free(&ctx, NULL);
       return 1;
    }
    
    if(apn_feedback(ctx, &tokens, &tokens_count, &error) == APN_ERROR) {
       printf("Could not get tokens: %s (%d)\n", error.message,  APN_ERR_CODE_WITHOUT_CLASS(error.code));
       apn_close(ctx);
       apn_free(&ctx, NULL);
       return 1;
    } 
    
    printf("Count: %d\n", tokens_count);
    
    for(i = 0; i < tokens_count; i++) {
        printf("Token: %s\n", tokens[i]);
    }

    apn_feedback_tokens_array_free(tokens, tokens_count);
    // tokens == NULL
    
    apn_close(ctx);
    apn_free(&ctx, NULL);
    
    return 0;
}