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

#include "apn_log.h"
#include "apn_private.h"
#include "apn_strings.h"

#define __APN_LOG_BUFFER 1024

void apn_log(const apn_ctx_t *const ctx, apn_log_levels level, const char *const message, ...) {
    if (ctx && ((ctx->log_callback || ctx->options & APN_OPTION_LOG_STDERR) && (ctx->log_level & level))) {
        va_list args;
        va_start(args, message);

        char buffer[__APN_LOG_BUFFER] = {0};
#ifdef _WIN32
        vsnprintf_s(buffer, __APN_LOG_BUFFER, _TRUNCATE, message, args);
#else
        vsnprintf(buffer, __APN_LOG_BUFFER, message, args);
#endif

        if(ctx->log_callback && (ctx->log_level & level)) {
            ctx->log_callback(level, buffer, __APN_LOG_BUFFER);
        }

        if(ctx->options & APN_OPTION_LOG_STDERR) {
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
            fprintf(stderr, "[%s] %s\n", prefix, buffer);
        }
        va_end(args);
    }
}
