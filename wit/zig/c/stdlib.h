/* The C library surface wit-bindgen's program.c needs, for the component
 * build without wasi-libc (issue #34): the functions are ../cabi.zig. */
#pragma once
#include <stddef.h>
void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
_Noreturn void abort(void);
