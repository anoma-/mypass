#ifndef __PASSMAN_H__
#define __PASSMAN_H__
#define _GNU_SOURCE
#include "common.h"
#include "util.h"
#include "records.h"
#include "crypt.h"
#include <ctype.h>
#include <unistd.h>

struct User_Account {
    size_t db_size;
    char *db_path;
    byte *user_salt;
};

User_Account * new_user_account ();

void free_user_account (User_Account *user);

int get_start (byte *password_hashed);

int convert_3_bytes (byte *in, uint8_t *out);

void eliminate (char *base, char *exclude);

int comp (const void *_a, const void *_b);

char * convert_to_64 (byte *hash, uint8_t length, char *exclude);

char * get_delimeter (byte *hashed_password);

int print_record_password (Record *r, byte *user_salt, byte *password_hashed);

int list_aliases (Record_List *rl);

void print_help ();

int write_buf_to_disk (char *db_path, byte *buffer, size_t buf_size);

int process_request (Record *r, uint16_t actions, Record_List *rl, 
                     User_Account *user, Crypt *crypt);

int create_account (char *db_path, uint8_t overwrite);

uint8_t get_uint (char *arg);

byte * get_db_buffer (User_Account *user);

byte * get_user_salt (byte *dec_db, int start_position);

int sanitize_input (byte *input, size_t input_len);

#endif
