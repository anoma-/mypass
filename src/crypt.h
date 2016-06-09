#ifndef __CRYPT_H__
#define __CRYPT_H__
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "common.h"
#include "skein/skein.h"
#include "util.h"

struct Crypt {
    int   start;
    char *password;
    byte *password_hashed;
    char *delimeter;
};

struct Crypt * new_crypt ();

void free_crypt (Crypt *c);

byte * get_var_len_hash (byte* seed, size_t seed_size, size_t bytes_requested);

byte * enc_buffer (byte *input, size_t input_length, byte *key_hash_128);

char * dec_buffer (byte *input, size_t input_length, byte *key_hash_128);

#endif
