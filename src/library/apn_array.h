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

#ifndef __APN_ARRAY_H__
#define	__APN_ARRAY_H__

#include "apn_platform.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef void *(*apn_array_ctor)(const void * const data);
typedef void (*apn_array_dtor)(void *data);

typedef struct __apn_array_t apn_array_t;

__apn_export__ apn_array_t *apn_array_init(uint32_t min_size, apn_array_dtor dtor, apn_array_ctor ctor)
        __apn_attribute_warn_unused_result__;

__apn_export__ void apn_array_free(apn_array_t *array);

__apn_export__ apn_array_t *apn_array_copy(const apn_array_t * const array)
        __apn_attribute_warn_unused_result__
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_array_insert(apn_array_t *array, void *item)
        __apn_attribute_nonnull__((1,2));

__apn_export__ uint32_t apn_array_count(const apn_array_t * const array)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_array_insert_at_index(apn_array_t * const array, uint32_t index, void *item)
        __apn_attribute_nonnull__((1,3));

__apn_export__ void * apn_array_item_at_index(const apn_array_t * const array, uint32_t index)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_array_remove(apn_array_t * const array, uint32_t index)
        __apn_attribute_nonnull__((1));

#ifdef	__cplusplus
}
#endif

#endif
