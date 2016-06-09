#ifndef __RECORDS_H__
#define __RECORDS_H__
#include "common.h"
#include "util.h"

struct Record {
    char *alias;
    char *exclusion_chars;
    char *mandatory_chars;
    char *stored_password;
    uint8_t flags;
    uint8_t pass_length;
    uint8_t dep_counter;
};

struct Record_List {
    struct Record **record_list;
    int record_count;
};

/*  Free a single record */
void free_record (Record *r); 

Record * new_record ();

char * write_records_to_buffer (Record_List *rl, char *delimeter);

int add_record (Record_List *rl, Record *r);

int remove_record (Record_List *rl, char *alias);

/*  Fill out a record from a string buffer, in a format that records knows */
Record * load_record_from_token (char *record_buf);
/*  Free an entire records list */
void free_record_list (Record_List *rl); 

 /* Fill out an entire record list, with each record deliminated */ 
Record_List * get_record_list_from_buffer (char *records, size_t record_size,  char *delimeter);

/*  Remove an existing exclusion char, or just unflag it */
int rm_exclusion_chars (Record *r);

/*  Overwrite an existing excluding character list, or add new one */
int set_exlusion_chars (Record *r, char *excluding_chars);

/*  Remove an existing appending character list, or unflag it */
int rm_mandatory_chars (Record *r);

/*  Overwrite an existing appending character list, or add a new one */
int set_mandatory_chars (Record *r, char *mandatory_chars);

/*  Set the record pass_len, Unless it is a stored password.
    The length does not include the optional mandatory character list */
int set_record_len (Record *r, uint8_t len);

/*  Deprecate an alias, unless it has been deprecated 255 times */
int deprecate_record (Record *r);

/*  Remove a stored password for an alias */
int remove_stored_password (Record *r);

/*  Undeprecate an alias, unless it is already at 0 */
int undeprecate_alias (Record *r);

/*  Import a password for an alias. Reset flags, and destroy any 
    Stored lists and password length */
int import_password (Record *r, char *pass);

Record * match_record_with_alias (Record_List *rl, char *alias);
#endif
