#ifndef __UTIL__H
#define __UTIL__H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

struct token_t {
	char **token_list;
	int list_size;
};

struct token_t *Token_tokenize (const unsigned char *, size_t, const char *, int);

void Token_free (struct token_t *);

void* clear_memory (void*, int, size_t);

void secure_free (void*, size_t);

#endif
