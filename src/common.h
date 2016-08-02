#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdint.h>
#include <stdlib.h>
#define MYPASS_VERSION "0.93\n"
static const int DEFAULT_RELATIVE_PATH_LENGTH  = 11;
static const int MAX_RECORD_LENGTH            = 135;

static const uint16_t NEW_ACCOUNT_ACTION    = 0x001;
static const uint16_t GET_ALIAS_ACTION      = 0x002; 
static const uint16_t WRITE_RECORD_ACTION   = 0x004;
static const uint16_t NO_ADD_ALIAS_ACTION   = 0x008;
static const uint16_t ADD_NEW_ALIAS_ACTION  = 0x010;
static const uint16_t REMOVE_ALIAS_ACTION   = 0x020;
static const uint16_t LIST_ALIASES_ACTION   = 0x040;


static const uint16_t SET_LENGTH_ATTR       = 0x080;
static const uint16_t SET_MANDATORY_ATTR    = 0x100;
static const uint16_t SET_EXCLUSION_ATTR    = 0x200;
static const uint16_t IMPORT_PASS_ATTR      = 0x400;
static const uint16_t DEPRECATE_ATTR        = 0x800;
static const uint16_t DEPRECATE_SET         = 0x1000;

static const int NUM_HASHES                = 200000;

static const uint8_t MANDATORY_FLAG        = 0x08; /*  00001000  */
static const uint8_t DEPRECATED_FLAG       = 0x04; /*  00000100  */
static const uint8_t EXCLUSION_FLAG        = 0x02; /*  00000010  */
static const uint8_t STORED_PASSWORD_FLAG  = 0x01; /*  00000001  */
static const uint8_t DEFAULT_FLAG          = 0x80; /*  10000000  */

typedef struct Account      Account;
typedef struct Record       Record;
typedef struct token_t      token_t;
typedef struct Record_List  Record_List;
typedef struct User_Account User_Account;
typedef struct Crypt        Crypt;

typedef unsigned char       byte;

static const char *Error_Memory = "Fatal Error: Unable to allocate memory\n";

static const int ALIAS_MAX_LENGTH     = 64;
static const int MAX_PASS_LENGTH      = 64;
static const int MAX_EXCLUDE_LENGTH   = 18;
static const int MAX_MANDATORY_LENGTH = 8;

#ifndef DEFAULT_PASS_LENGTH
#define DEFAULT_PASS_LENGTH 18
#endif
#ifdef DEBUG
#define ASSERT(cond, mesg) if (!cond) {\
    fprintf (stderr, "File: %s in function: %s at line %d\n%s", __FILE__, \
            __FUNCTION__, __LINE__, mesg);\
    exit (1);\
}
#else
#define ASSERT(...) 
#endif
#endif

