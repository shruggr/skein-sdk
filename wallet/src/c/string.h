/* See stdlib.h. memcpy is compiler_rt's. */
#pragma once
#include <stddef.h>
size_t strlen(const char *s);
void *memcpy(void *dst, const void *src, size_t n);
