/*
 * Copyright (c) 2013, 2014, 2015 Anton Dobkin
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "apn_array_private.h"
#include "apn_memory.h"
#include "apn_memory.h"

apn_array *apn_array_init(uint32_t minsize, apn_array_dtor dtor, apn_array_ctor ctor) {
    apn_array *array = NULL;
    assert(minsize < (UINT32_MAX - 1));
    array = malloc(sizeof(apn_array));
    if (!array) {
        errno = ENOMEM;
        return NULL;
    }
    array->items = malloc(sizeof(void *) * minsize);
    if (!array->items) {
        errno = ENOMEM;
        free(array);
        return NULL;
    }
    array->allocated_size = minsize;
    array->dtor = dtor;
    array->ctor = ctor;
    array->count = 0;
    return array;
}

void apn_array_free(apn_array *array) {
    apn_array_dtor dtor = NULL;
    uint32_t i = 0;
    if (!array) {
        return;
    }
    if (array->items) {
        dtor = array->dtor;
        for (; i < array->count; i++) {
            if (dtor) {
                dtor(i, array->items[i]);
            }
        }
        free(array->items);
    }
    free(array);
}

apn_return apn_array_insert(apn_array *array, void *item) {
    void **new_items = NULL;
    assert(array);
    assert((array->count + 1) < UINT32_MAX);

    if (array->count == array->allocated_size) {
        new_items = apn_realloc(array->items, sizeof(void *) * (array->allocated_size * 2));
        if (!new_items) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        array->items = new_items;
        array->allocated_size *= 2;
    }

    if (array->ctor) {
        array->items[array->count] = array->ctor(array->count, item);
    } else {
        array->items[array->count] = item;
    }
    array->count++;

    return APN_SUCCESS;
}

uint32_t apn_array_count(const apn_array *const array) {
    assert(array);
    return array->count;
}

apn_return apn_array_insert_at_index(apn_array *const array, uint32_t index, void *item) {
    void **new_items = NULL;
    void *data = NULL;
    assert(array);
    assert(index < array->count);

    if (array->count == array->allocated_size) {
        new_items = (void **) apn_realloc(array->items, sizeof(void *) * (array->allocated_size * 2));
        if (!new_items) {
            errno = ENOMEM;
            return APN_ERROR;
        }
        array->items = new_items;
        array->allocated_size *= 2;
    }

    data = array->items[index];
    if (!data) {
        array->count++;
    }

    if (array->dtor && data) {
        array->dtor(index, data);
    }

    array->items[index] = item;
    return APN_SUCCESS;
}

void *apn_array_item_at_index(const apn_array *const array, uint32_t index) {
    assert(array);
    assert(index < array->count);
    return array->items[index];
}

void apn_array_remove(apn_array *const array, uint32_t index) {
    void *data = NULL;
    assert(array);
    assert(index < array->count);

    data = array->items[index];
    if (data && array->dtor) {
        array->dtor(index, data);
    }
    array->items[index] = NULL;
}

apn_array *apn_array_copy(const apn_array *const array) {
    apn_array *dst = NULL;
    uint32_t i = 0;

    assert(array);
    dst = apn_array_init(array->allocated_size, array->dtor, array->ctor);
    if (!dst) {
        errno = ENOMEM;
        return NULL;
    }

    if (array->items) {
        for (; i < array->count; i++) {
            if (!apn_array_insert(dst, array->items[i])) {
                apn_array_free(dst);
                return NULL;
            }
        }
    }
    return dst;
}
