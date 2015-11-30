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

#include "apn_ssl.h"
#include "apn_private.h"
#include "apn_log.h"
#include "apn_strings.h"

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef APN_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#define __APN_X509_ENTRY_BUF_SIZE 1024
#define __APN_X509_ENTRY_CN "CN"

static char *__apn_ssl_cert_entry_string(X509_NAME *name)
        __apn_attribute_nonnull__((1));

static char *__apn_cert_subject_string(X509 *cert)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

static char * __apn_cert_issuer_string(X509 *cert)
        __apn_attribute_nonnull__((1))
        __apn_attribute_warn_unused_result__;

static char *__apn_cert_entry_value_string_by_nib(X509_NAME *name, const char * const nid)
        __apn_attribute_nonnull__((1,2))
        __apn_attribute_warn_unused_result__;

static char *__apn_cert_subject_value_by_nib(X509 *cert, const char * const nid)
        __apn_attribute_nonnull__((1,2))
        __apn_attribute_warn_unused_result__;

static void __apn_ssl_info_callback(const SSL *ssl, int where, int ret)
        __apn_attribute_nonnull__((1));

static int __apn_ssl_password_callback(char *buf, int size, int rwflag, void *password)
        __apn_attribute_nonnull__((1, 4));

void apn_ssl_init() {
    SSL_load_error_strings();
    SSL_library_init();
}

void apn_ssl_free() {
    ERR_free_strings();
    EVP_cleanup();
}

apn_return apn_ssl_connect(apn_ctx_t *const ctx) {
    assert(ctx);

    SSL_CTX *ssl_ctx = NULL;
    if (NULL == (ssl_ctx = SSL_CTX_new(TLSv1_client_method()))) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not initialize SSL context: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return APN_ERROR;
    }

    SSL_CTX_set_ex_data(ssl_ctx, 0, ctx);
    SSL_CTX_set_info_callback(ssl_ctx, __apn_ssl_info_callback);

    X509 *cert = NULL;

    if (ctx->pkcs12_file && ctx->pkcs12_pass) {
        FILE *pkcs12_file = NULL;
#ifdef _WIN32
        fopen_s(&pkcs12_file, ctx->pkcs12_file, "r");
#else
        pkcs12_file = fopen(ctx->pkcs12_file, "r");
#endif
        if (!pkcs12_file) {
            char *error = apn_error_string(errno);
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to open file %s: %s (errno: %d)", ctx->pkcs12_file, error,
                      errno);
            free(error);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            return APN_ERROR;
        }

        PKCS12 *pkcs12_cert = NULL;
        d2i_PKCS12_fp(pkcs12_file, &pkcs12_cert);
        fclose(pkcs12_file);

        EVP_PKEY *private_key = NULL;

        if (!PKCS12_parse(pkcs12_cert, ctx->pkcs12_pass, &private_key, &cert, NULL)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            PKCS12_free(pkcs12_cert);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            return APN_ERROR;
        }
        PKCS12_free(pkcs12_cert);

        if (!SSL_CTX_use_certificate(ssl_ctx, cert)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            X509_free(cert);
            EVP_PKEY_free(private_key);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            return APN_ERROR;
        }

        if (!SSL_CTX_use_PrivateKey(ssl_ctx, private_key)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified PKCS#12 file: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            X509_free(cert);
            EVP_PKEY_free(private_key);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12;
            return APN_ERROR;
        }
        EVP_PKEY_free(private_key);
    } else {
        FILE *cert_file = NULL;
#ifdef _WIN32
        fopen_s(&cert_file, ctx->certificate_file, "r");
#else
        cert_file = fopen(ctx->certificate_file, "r");
#endif
        if (!cert_file) {
            char *error = apn_error_string(errno);
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to open file %s: %s (errno: %d)", ctx->pkcs12_file, error,
                      errno);
            free(error);
            X509_free(cert);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
            return APN_ERROR;
        }

        cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        if (!cert) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified certificate: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(ssl_ctx);
            fclose(cert_file);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
            return EXIT_FAILURE;
        }
        fclose(cert_file);

        if (!SSL_CTX_use_certificate(ssl_ctx, cert)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified certificate: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            X509_free(cert);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
            return APN_ERROR;
        }

        SSL_CTX_set_default_passwd_cb(ssl_ctx, __apn_ssl_password_callback);
        char *password = NULL;
        if (ctx->private_key_pass) {
            password = apn_strndup(ctx->private_key_pass, strlen(ctx->private_key_pass));
            if (!password) {
                X509_free(cert);
                SSL_CTX_free(ssl_ctx);
                return APN_ERROR;
            }
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, password);
        } else {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, NULL);
        }

        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->private_key_file, SSL_FILETYPE_PEM)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified private key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            apn_strfree(&password);
            X509_free(cert);
            SSL_CTX_free(ssl_ctx);
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            return APN_ERROR;
        }

        apn_strfree(&password);

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to use specified private key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY;
            X509_free(cert);
            SSL_CTX_free(ssl_ctx);
            return APN_ERROR;
        }
    }

    if(cert) {
        char *subject = __apn_cert_subject_string(cert);
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Local certificate subject: %s", subject);

        char *issuer = __apn_cert_issuer_string(cert);
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Local certificate issuer: %s", issuer);

        free(subject);
        free(issuer);

        char *cn = __apn_cert_subject_value_by_nib(cert, __APN_X509_ENTRY_CN);
        X509_free(cert);
        if(cn) {
            uint8_t invalid_cert = 0;
            if(apn_mode(ctx) == APN_MODE_PRODUCTION && 0 != strncmp("Apple Production", cn, 16)) {
                invalid_cert = 1;
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Invalid certificate. You are using a PRODUCTION mode, but certificate was created for usage in SANDBOX");
            } else if (apn_mode(ctx) == APN_MODE_SANDBOX && 0 != strncmp("Apple Development", cn, 17)) {
                invalid_cert = 1;
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Invalid certificate. You are using a SANDBOX mode, but certificate was created for usage in PRODUCTION");
            }
            free(cn);
            if(1 == invalid_cert) {
                SSL_CTX_free(ssl_ctx);
                errno = APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE;
                return APN_ERROR;
            }
        }
    }

    ctx->ssl = SSL_new(ssl_ctx);
    SSL_CTX_free(ssl_ctx);

    if (!ctx->ssl) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not initialize SSL");
        errno = APN_ERR_UNABLE_TO_ESTABLISH_SSL_CONNECTION;
        return APN_ERROR;
    }

    int ret = 0;

    if (-1 == (ret = SSL_set_fd(ctx->ssl, ctx->sock))) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to attach socket to SSL: SSL_set_fd() failed (%d)",
                  SSL_get_error(ctx->ssl, ret));
        errno = APN_ERR_UNABLE_TO_ESTABLISH_SSL_CONNECTION;
        return APN_ERROR;
    }

    if (1 > (ret = SSL_connect(ctx->ssl))) {
        char *error = apn_error_string(errno);
        apn_log(ctx, APN_LOG_LEVEL_ERROR,
                  "Could not initialize SSL connection: SSL_connect() failed: %s, %s (errno: %d):",
                  ERR_error_string((unsigned long) SSL_get_error(ctx->ssl, ret), NULL), error, errno);
        free(error);
        return APN_ERROR;
    }
    apn_log(ctx, APN_LOG_LEVEL_INFO, "SSL connection has been established");

    X509 *remote_cert = SSL_get_peer_certificate(ctx->ssl);
    if (remote_cert) {
        char *subject = __apn_cert_subject_string(remote_cert);
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Remote certificate subject: %s", subject);

        char *issuer = __apn_cert_issuer_string(remote_cert);
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Remote certificate issuer: %s", issuer);

        free(subject);
        free(issuer);
        X509_free(remote_cert);
    }
    return APN_SUCCESS;
}

int apn_ssl_write(const apn_ctx_t *const ctx, const uint8_t *message, size_t length) {
    int bytes_written = 0;
    int bytes_written_total = 0;

    while (length > 0) {
        bytes_written = SSL_write(ctx->ssl, message, (int) length);
        if (bytes_written <= 0) {
            switch (SSL_get_error(ctx->ssl, bytes_written)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_SYSCALL:
                    switch (errno) {
                        case EINTR:
                            continue;
                        case EPIPE:
                            errno = APN_ERR_NETWORK_UNREACHABLE;
                            return -1;
                        case ETIMEDOUT:
                            errno = APN_ERR_NETWORK_TIMEDOUT;
                            return -1;
                        default:
                            errno = APN_ERR_SSL_WRITE_FAILED;
                            return -1;
                    }
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_NONE:
                    errno = APN_ERR_CONNECTION_CLOSED;
                    return -1;
                default:
                    errno = APN_ERR_SSL_WRITE_FAILED;
                    return -1;
            }
        }
        message += bytes_written;
        bytes_written_total += bytes_written;
        length -= bytes_written;
    }
    return bytes_written_total;
}

int apn_ssl_read(const apn_ctx_t *const ctx, char *buff, size_t length) {
    int read;
    for (; ;) {
        read = SSL_read(ctx->ssl, buff, (int) length);
        if (read > 0) {
            break;
        }
        switch (SSL_get_error(ctx->ssl, read)) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                continue;
            case SSL_ERROR_SYSCALL:
                switch (errno) {
                    case EINTR:
                        continue;
                    case EPIPE:
                        errno = APN_ERR_NETWORK_UNREACHABLE;
                        return -1;
                    case ETIMEDOUT:
                        errno = APN_ERR_NETWORK_TIMEDOUT;
                        return -1;
                    default:
                        errno = APN_ERR_SSL_READ_FAILED;
                        return -1;
                }
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_NONE:
                errno = APN_ERR_CONNECTION_CLOSED;
                return -1;
            default:
                errno = APN_ERR_SSL_READ_FAILED;
                return -1;
        }
    }
    return read;
}

void apn_ssl_close(apn_ctx_t *const ctx) {
    if (ctx->ssl) {
#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN);
#endif
        if (!SSL_shutdown(ctx->ssl)) {
            shutdown(ctx->sock, SHUT_RDWR);
            SSL_shutdown(ctx->ssl);
        }
#ifndef _WIN32
        signal(SIGPIPE, SIG_DFL);
#endif
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
}


static char *__apn_ssl_cert_entry_string(X509_NAME *name) {
    char subject_entry_buffer[__APN_X509_ENTRY_BUF_SIZE] = {0};
    int entry_count = X509_NAME_entry_count(name);
    for (int i = 0; i < entry_count; i++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);

        ASN1_OBJECT *entry_object = X509_NAME_ENTRY_get_object(entry);
        const char *entry_name = OBJ_nid2sn(OBJ_obj2nid(entry_object));
        const unsigned char *entry_value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(entry));

        apn_strcat(subject_entry_buffer, entry_name, __APN_X509_ENTRY_BUF_SIZE, strlen(entry_name));
        apn_strcat(subject_entry_buffer, "=", __APN_X509_ENTRY_BUF_SIZE, 1);
        apn_strcat(subject_entry_buffer, (const char *)entry_value, __APN_X509_ENTRY_BUF_SIZE, strlen((const char *)entry_value));
        if(i + 1 < entry_count) {
            apn_strcat(subject_entry_buffer, ", ", __APN_X509_ENTRY_BUF_SIZE, 2);
        }
    }
    return apn_strndup(subject_entry_buffer, strlen(subject_entry_buffer));
}

static char * __apn_cert_subject_string(X509 *cert) {
    return __apn_ssl_cert_entry_string(X509_get_subject_name(cert));
}

static char * __apn_cert_issuer_string(X509 *cert) {
    return __apn_ssl_cert_entry_string(X509_get_issuer_name(cert));
}

static char *__apn_cert_entry_value_string_by_nib(X509_NAME *name, const char * const nid_str) {
    int nid = OBJ_txt2nid(nid_str);
    int index = X509_NAME_get_index_by_NID(name, nid, -1);
    if(index != -1) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
        const unsigned char *entry_value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(entry));
        if(entry_value) {
            return apn_strndup((const char *)entry_value, strlen((const char *)entry_value));
        }
    }
    return NULL;
}

static char *__apn_cert_subject_value_by_nib(X509 *cert, const char * const nid_str) {
    return __apn_cert_entry_value_string_by_nib(X509_get_subject_name(cert), nid_str);
}

static void __apn_ssl_info_callback(const SSL *ssl, int where, int ret) {
    apn_ctx_t *ctx = SSL_CTX_get_ex_data(ssl->ctx, 0);
    if (!ctx) {
        return;
    }
    if (where & SSL_CB_LOOP) {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: %s:%s:%s",
                (where & SSL_ST_CONNECT) ? "connect" : "undef",
                SSL_state_string_long(ssl),
                SSL_get_cipher_name(ssl));
    } else if (where & SSL_CB_EXIT) {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: %s:%s", (where & SSL_ST_CONNECT) ? "connect" : "undef",
                SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: alert %s:%s", (where & SSL_CB_READ) ? "read" : "write",
                SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_HANDSHAKE_START) {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: handshake started %s:%s:%s", (where & SSL_CB_READ) ? "read" : "write",
                SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_HANDSHAKE_DONE) {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: handshake done %s:%s:%s", (where & SSL_CB_READ) ? "read" : "write",
                SSL_state_string_long(ssl), SSL_alert_desc_string_long(ret));
    } else {
        apn_log(ctx, APN_LOG_LEVEL_INFO, "ssl: state %s:%s:%s", SSL_state_string_long(ssl),
                SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
}

static int __apn_ssl_password_callback(char *buf, int size, int rwflag, void *password) {
    (void) rwflag;
    if (!password || size <= 0) {
        return 0;
    }
#ifdef _WIN32
    strncpy_s(buf, size, (char *) password, size);
#else
    strncpy(buf, (char *) password, (size_t) size);
#endif
    buf[size - 1] = '\0';

    return (int) strlen(buf);
}
