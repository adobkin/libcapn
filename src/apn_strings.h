/* 
 * Copyright (c) 2013, Anton Dobkin
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

#ifndef __APN_STRINGS_H__
#define	__APN_STRINGS_H__

#include "platform.h"

#ifdef	__cplusplus
extern "C" {
#endif

__apn_export__ char *apn_strndup(const char *str, size_t len) __apn_attribute_nonnull__((1)) __apn_attribute_warn_unused_result__;
__apn_export__ uint8_t apn_strcpy(char *destination, const char *source, size_t destination_size) __apn_attribute_nonnull__((1,2));
__apn_export__ uint8_t apn_string_is_utf8(const char *str);
__apn_export__ void apn_strfree(char **str);

#ifdef	__cplusplus
}
#endif

#endif	/* __APN_STRINGS_H__ */

