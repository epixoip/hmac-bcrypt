#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

typedef struct {
    size_t size;
    char **elements;
} array_t;

array_t *split(const char delim, const char *str) {
    array_t *array = (array_t *) calloc(1, sizeof(array_t));
    size_t len = strlen(str);

    array->size = 0;

    for (size_t pos = 0; pos <= len; pos++) {
        if (str[pos] == delim || str[pos] == 0) {
            array->size++;
        }
    }

    array->elements = (char **) calloc(array->size, sizeof(char *));

    if (!array->elements) {
        perror(strerror(ENOMEM));
        exit(-ENOMEM);
    }

    size_t element = 0;
    size_t offset  = 0;

    for (size_t pos = 0; pos <= len; pos++) {
        if (str[pos] == delim || str[pos] == 0) {
            size_t element_len = pos - offset;           
            array->elements[element] = (char *) calloc(element_len + 1, sizeof(char));

            if (!array->elements[element]) {
                perror(strerror(ENOMEM));
                exit(-ENOMEM);
            }

            memcpy(array->elements[element++], str + offset, element_len);
            offset = ++pos;
        }
    }

    return array;
}

void free_array(array_t *array) {
    if (!array) {
        return;
    }

    for (size_t pos = 0; pos < array->size; pos++) {
        if (array->elements[pos]) {
            free(array->elements[pos]);
        }
    }

    free(array->elements);
    free(array);
    
    array = NULL;
}

char *substr(const char *src, int start, int len) {
    if (
        src == NULL       ||
        len > strlen(src) ||
        (src + start) - src > strlen(src)
    ) {
        return NULL;
    }

    char *dst = (char *) calloc(len + 1, sizeof(char));
    char *dst_ptr = dst;
 
    for (int i = start; i < start + len && (*(src + i) != 0); i++) {
        *dst = *(src + i);
        dst++;
    }
 
    *dst = 0;

    return dst_ptr;
}
