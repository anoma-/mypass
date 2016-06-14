/* mypass a deterministic password generator
* Copyright (C) <2016>  <Tyler Stafos>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "passman.h"

#define ______II 0x03 /* 00000011 \3 */
#define ____IIII 0xf  /* 00001111 \15 */
#define __II____ 0x30 /* 00110000 \48 */
#define __IIII__ 0x3c /* 00111100 \60 */
#define __IIIIII 0x3f /* 00111111 \63 */

static const char base64[]   = "aBcDeFgHiJkLMnPqRsTuVwXyZ0123456789@#$%^&()-_=+[{]}<>.,?:*AbCdEf";
static const char replace[]  = "GhIjKmNpQrStUvWxYz";


User_Account * new_user_account  ()
{
    User_Account *act = calloc (sizeof (User_Account), 1);
    act->db_path  = NULL;
    act->user_salt = NULL;
    return act;
}

void free_user_account (User_Account *act)
{
    if (act)
    {
        free (act->db_path);
        act->db_path = NULL;
        if (act->user_salt)
            secure_free (act->user_salt, 16);
        act->user_salt = NULL;
        free (act);
        act = NULL;
    }
}

/*  Get the starting position of the user_salt and records */
int get_start (byte *password_hashed)
{
    uint32_t tmp = 0;
    memcpy (&tmp, password_hashed, 4);
    int ret = tmp % 1024;
    return ret;
}

/*  6 bits can be up to 63 in value. 64 slots counting 0. We pull 6 bits out of 24 total
 *  or 3 bytes. And directly convert them into signed and printable chars */
int convert_3_bytes (byte *in, uint8_t *out)
{
    ASSERT((in && out), "Null arguments\n");
    uint8_t byte_1  = 0;
    uint8_t byte_2  = 0;
    uint8_t byte_3  = 0;
    uint8_t byte_4  = 0;

    /*  Set the first out char equal to the first 6 bytes of in */
    byte_1 = (uint8_t) (in[0] & __IIIIII);  
    /* Bit shift the last 2 bits into the first 2 bit slot, and the next bytes 
     *  bit shifted up two to slide into the middle 4 slots */
    byte_2 = (uint8_t) (((in[0] >> 6) & ______II) | ((in[1] << 2) & __IIII__));
    /*  Slide the last 4 bits from second in char into the first 4 slots + the 
     *  first 2 bits of the 3rd byte into the 5th and 6th slot of out 3 */
    byte_3 = (uint8_t) (((in[1] >> 4) & ____IIII) | ((in[2] << 4) & __II____));
    /*  Finally read the last 6 bits of the third in byte */
    byte_4 = (uint8_t) ((in[2] >> 2) & __IIIIII);

    out[0] = byte_1;
    out[1] = byte_2;
    out[2] = byte_3;
    out[3] = byte_4;
        
    return 0;
}

/*  Eliminate characters contained in the base, that are also in exclude 
 *  replace is an array of replacement characters. Find the default characters
 *  that are in exclude, and replace them with a character from the replace 
 *  array.
 * 
 *  Need to sort exclude so that it replaces in the same way, no matter 
 *  the order of the exclusion character list */
void eliminate (char *base, char *exclude)
{
    if (!base || !exclude)
        return;

    size_t i = 0;
    size_t j = 0;
    size_t k = 0;
    size_t len = strlen (exclude);
    if (len > 18)
    {
        fprintf (stderr, "Cannot exclude more than 18 characters\n");
        return;
    }

    for (i = 0; i < len; i++)
    {
        j = 0;
        while (j < 64)
        {
            if (base[j] == exclude[i])
            {
                base[j] = replace[k++];
                j = 64;
            }
            else
                j++;
        }
    }
}

int comp (const void *_a, const void *_b)
{
    uint8_t a = *((uint8_t*) _a);
    uint8_t b = *((uint8_t*) _b);
    if (a == b) return 0;
    return (a > b) ? 1 : -1;
}
    
char* convert_to_64 (byte *hash, uint8_t length, char *exclude)
{
    ASSERT(hash, "Null argument\n");
    char *failure = NULL;
    char *pass_64 = NULL;
    int set_c     = 0;
    int out_c     = 0;  
    uint8_t out[64];
    /*  Hash is longer than we need for the password length, and is a 
     *  multiple of 3 */
    /*  Get memory at a 4/3 ratio of hash_len + null char */
    pass_64 = malloc (64 + 1);
    if (!pass_64)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }
    while (set_c <= 45 && out_c <= 60)
    {
        /*  Convert 3 bytes at a time, into 4 bytes of pass_64 */
        
        if (convert_3_bytes (&hash[set_c], &out[out_c]) != 0)
        {
            fprintf (stderr, "Error converting hash to base 64\n");
            secure_free (pass_64, 64);
            return failure;
        }

        set_c += 3;
        out_c += 4;
    }

    if (exclude)
    {
        /*  cpy_key is the base64 array reference characters. Or 
         *  the pool of available characters a number can equal 
         *  So we remove the excluding characters that intersect with it
         *  and then continue as normal converting the 6 bits into 
         *  an index of the cpy_key. But first we make sure the exclusion 
         *  list is sorted, so that it produces the same password, no matter
         *  the order the exlusion characters are entered  
         *  Fill out all 64 characters for password, and just place NULL at length*/
        size_t ex_len = strlen (exclude);
        qsort (exclude, ex_len, sizeof (uint8_t), comp);
        char cpy_key[65];
        memset (cpy_key, 0, 65);
        strcpy (cpy_key, base64);
        eliminate (cpy_key, exclude);
        
        out_c = 0;
        for (set_c = 0; set_c < 64; set_c++)
            pass_64[set_c] = cpy_key[out[out_c++]];
        pass_64[length] = '\0';
        return pass_64;
    }   
    /*  Write the chars from base64 with index of the out array.
     *  out[64] are the values of the 6 bits in the 384 bit hash
     *  maximum value of all 6 bits is 63, min 0. So each value 
     *  corresponds to the base[64] char array. 
     *  Create a 64 char password everytime, set length with null char */
    out_c = 0;
    for (set_c = 0; set_c < 64; set_c++)
        pass_64[set_c] = base64[out[out_c++]];

    /*  Set the length by adding a null char to length. */
    pass_64[length] = '\0';
    return pass_64;
}

/*  set a unique delimeter 8 bytes long based on a password 
 *  Unique for the purpose of not having known plain text
 *  8 bytes to reduce the chances of accidentally coming accross
 *  this sequence at random */
char* get_delimeter (byte* password_hashed)
{
    ASSERT(password_hashed, "Null argument\n");
    uint8_t a       = 0;
    uint8_t b       = 0;
    uint8_t mod     = 0;
    int     i       = 0;
    int     c       = 0;
    int     product = 0;

    char  ch        = '\0';
    char *failure   = NULL;
    char *del = malloc (9);

    if (!del)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    /*  To avoid NULL as a char in delimeter incr mod.
     *  Take the product of 2 bytes (as int) of the password_hashed
     *  and the modulus of 254 to cram it into a char */
    for (i = 0; i < 16; i+=2)
    {
        memcpy (&a, &password_hashed[i], 1);
        memcpy (&b, &password_hashed[i+1], 1);
        product = a*b; 
        mod = (uint8_t) (product % 254);    
        mod++;
        memcpy (&ch, &mod, 1);
        del[c++] = ch;
    }

    del[8] = '\0';  
    return del;
}

int print_record_password (Record *r, byte *user_salt, byte *password_hashed)
{
    int failure = 1;
    size_t alias_length = strlen (r->alias);    

    if (r->flags & STORED_PASSWORD_FLAG)
    {
        if (!r->stored_password)
        {
            fprintf (stderr, "Error: Alias: %s password field is null\n", 
                                                                r->alias);
            return failure;
        }
        printf ("%s\n",r->stored_password);
        return 0;   
    }
    
    byte *unsignedpass = NULL; 
    char *pass         = NULL;
    byte *seed         = NULL;

    seed = calloc (alias_length + 32 + 1, 1);

    if (!seed)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }
    /*  catonate values, alias + dep_counter + user_salt + password_hashed */
    memcpy (seed, r->alias, alias_length);
    /*  Add the deprecate counter to the end */
    seed[alias_length] = (byte) r->dep_counter; 
    memcpy (&seed[alias_length + 1], user_salt, 16);
    memcpy (&seed[alias_length + 16 + 1], password_hashed, 16);

    /*  48 bytes will get maximum 64 character password */
    unsignedpass = get_var_len_hash (seed, alias_length + 33, 48);
    /*  Converting the byte* to a singed char *. It is the same pointer, just casted and 
     *  edited. So only free the pass pointer, and consider unsignedpass freed */
    secure_free (seed, alias_length + 32);
    if (!unsignedpass)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    pass = convert_to_64 (unsignedpass, r->pass_length, r->exclusion_chars);
    secure_free (unsignedpass, 48);

    if (pass && r->mandatory_chars)
    {
        printf ("%s%s\n", pass, r->mandatory_chars);
        secure_free (pass, 64);
        return 0;
    }
    else if (pass)
    {
        printf ("%s\n", pass);
        secure_free (pass, 64);
        return 0;
    }
    return failure;
}

int list_aliases (Record_List *rl)
{
    ASSERT(rl, "Null arguments\n");
    int failure = 1;
    int i       = 0;

    for (i = 0; i < rl->record_count; i++)
    {
        if (!rl->record_list[i])
        {
            fprintf (stderr, "Error: Null entry\n");
            return failure;
        }
        printf ("%s\n", rl->record_list[i]->alias);
    }
    return 0;
}

void print_help ()
{
    printf ("mypass: create and manage deterministic passwords\n");
    printf ("\n");
    printf ("optional arguments in brackets, mandatory arguments in parenthesis\n");
    printf ("long and short flags available for all operations, and behave the same\n");
    printf ("password flag is required by all operations, other than the -n --new option\n");
    printf ("\n\n");
    printf ("  -a (alias)           add an (alias) to the db\n");
    printf ("  --add=alias\n");
    printf ("  -g (alias)           printf the password generated by (alias), if it exists\n");
    printf ("  --get=alias\n");
    printf ("  -r (alias)           remove (alias) from the database\n");
    printf ("  --remove=alias\n");
    printf ("  -x (alias)           print password of (alias) without adding it to the\n");
    printf ("                         database\n");
    printf ("  --xget=alias\n");
    printf ("  -L (num)             set new length of the generated password Min 1 Max 64\n");
    printf ("  --length=num\n");
    printf ("  -d                   deprecate password, and return new password for selection\n");
    printf ("                         maximum of 254 deprecations\n");
    printf ("  --deprecate\n");
    printf ("  -D (num)             set deprecation of selection to (num) Min 1 Max 254\n");
    printf ("  --deprecate_set\n");
    printf ("  -m[chars]            append [chars] to generated password for selection Max\n");
    printf ("                         length of [chars] is 8 characters. Any [chars] list\n");
    printf ("                         will overwrite the old one, including an empty list\n");
    printf ("                         do note, optional args must touch flag -mexample\n");
    printf ("  --mandatory=[chars]\n");
    printf ("  -e[chars]            remove [chars] from the password generated for selection\n");
    printf ("                         Max length of [chars] is 18. Will replace [chars] with\n");
    printf ("                         alphabetic letters. Any [chars] list will overwrite an\n");
    printf ("                         older [chars] list, including an empty list\n");
    printf ("                         do note, optional args must touch flag -eexample\n");
    printf ("  --exclude=chars\n");
    printf ("  -i (password)        import (password) for selection. Will not generate a\n");
    printf ("                         password just returns the imported (password) when\n"); 
    printf ("                         (alias) is entered. Cannot alter the records, just use\n");
    printf ("                         --add,--remove, or --get\n");
    printf ("  --import=password\n");
    printf ("  -f (fullpathname)    use (fullpathname) for the database instead of default\n");
    printf ("  --file=path\n");
    printf ("  -l                   list all aliases in the database\n");
    printf ("  --list\n");
    printf ("  -n[o]                complete questionaire and create a new database\n");
    printf ("                         will not overwrite existing database without\n");
    printf ("                         including optional character argument 'o'\n");
    printf ("  --new=[o]\n");
    printf ("  -h                   print this help text\n");
    printf ("  --help\n");
    printf ("\n\n\nExample Usage:\n");
    printf ("mypass -n [-f fullpathname]\n");
    printf ("  created a new database, optionally with a new path and name for the database\n");
    printf ("\n");
    printf ("mypass -a (alias) [-L12] [-e+_-] [-m101] (-p password)\n");
    printf ("  added an (alias) and optionally set length, excluding chars, and mandatory\n");
    printf ("    chars\n");
    printf ("\n");
    printf ("mypass -g (alias) [-L64] [-e] [-m] (-p password)\n");
    printf ("  retreived (password) from (alias), set a new length, while also removing any\n");
    printf ("  exclusion character lists, or mandatory characters list\n");
    printf ("\n");
    printf ("mypass -g (alias) (-p password)\n");
    printf ("  simple get (get_password) for (alias)\n");
    printf ("\n");
    printf ("mypass -g (alias) [-d] (-p password)\n");
    printf ("  get a new password for (alias)\n");
    printf ("\n");
    printf ("mypass -l (-p password)\n");
    printf ("  list all (aliases)\n");
    printf ("\n");
    printf ("mypass -i (existing_password) (-a (alias)) (-p password) [-f fullpathname]\n");
    printf ("  import (existing_password) for (alias) with optional [fullpathname] to \n");
    printf ("    database\n");
    printf ("  *note, must use --add(alias) for the --import flag. Cannot make changes\n");
    printf ("    in the future. If you want to alter it, you'll need to --remove (alias)\n");
    printf ("    to reimport\n");
    printf ("\n");
    printf ("mypass -x (alias) [-L12] [-D231] [-e012] [-m!] [-f fullpathname] (-p password)\n");
    printf ("  does not add (alias) to the database, but retreives a password as if it had\n");
    printf ("\n\n\n");
    printf ("*******************************************************************************\n");
    printf ("If you are regenerating a database by answering the questionaire the same way. \n");
    printf ("Do keep in mind, that the deterministic aspect of the generated passwords are\n");
    printf ("altered when you use flags to alter the generated password of a recorded (alias)\n");
    printf ("If you attempt to recreate the database, in order to get the same generated\n");
    printf ("passwords as previously, you will have to remember the alterations you made\n");
    printf ("before as well. Also, the imported passwords cannot be regenerated, and must be\n");
    printf ("reimported\n\n");
    printf ("And use a strong password\n");
    printf ("\n\n");
}

int write_buf_to_disk (char *db_path, byte *buffer, size_t buf_size)
{
    ASSERT((db_path && buffer && buf_size), "Null arguments");
    int failure = 1;
    errno = 0;
    size_t wrote = 0;
    FILE *fp = fopen (db_path, "w");
    if (!fp)
    {
        perror ("Error: Could not open database to write changes\n");
        return failure;
    }

    wrote = fwrite (buffer, 1, buf_size, fp);
    fclose (fp);
    if (wrote != buf_size)
    {
        perror ("Error: Could not write all of the data\n");
        return failure;
    }
    return 0;
}

int write_changes_to_disk (Record_List *rl, User_Account *user, Crypt *crypt)
{
    ASSERT((rl && user && crypt), "Null arguments\n");
    int failure = 1;
    int rt_val  = 0;
    /*  -1024 in case maximum offset for start is used
     *  -32 for the IV and signature
     *  -16 for user_salt
     *  We will be adding them back in at certain steps
     */
    size_t min_db_size = 10240 - 1024 - 32 - 16;
    size_t db_size     = 0;
    char *db_buf = write_records_to_buffer (rl, crypt->delimeter);
    if (!db_buf)
    {
        fprintf (stderr, "Error: Could not write changes\n");
        return failure;
    }
    db_size = strlen (db_buf);
    while (db_size > min_db_size)
        min_db_size += 10240;
    min_db_size += 1024 + 16;

    byte rnd[16];
    if (!(RAND_bytes (rnd, 16)))
    {
        fprintf (stderr, "Errror: Could not get random bytes\n");
        return failure;
    }

    byte *dec_db = get_var_len_hash (rnd, 16, min_db_size);
    if (!dec_db)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        secure_free (db_buf, db_size);
        return failure;
    }

    memcpy (&dec_db[crypt->start], user->user_salt, 16);
    memcpy (&dec_db[crypt->start + 16], db_buf, db_size);

    /*  This step adds 32 bytes to the buffer */
    byte *encrypted_db = enc_buffer (dec_db, min_db_size, crypt->password_hashed);
    if (!encrypted_db)
    {
        fprintf (stderr, "Error: Unable to write changes to disk\n");
        secure_free (db_buf, db_size);
        secure_free (dec_db, min_db_size);
        return failure;
    }
    secure_free (dec_db, min_db_size);
    secure_free (db_buf, db_size);

    ASSERT(((min_db_size + 32) % 10240 == 0), 
            "Min db size is not a product of 10240\n");

    rt_val = write_buf_to_disk (user->db_path, encrypted_db, min_db_size+32);   
    secure_free (encrypted_db, min_db_size + 32);
    return rt_val;
}

int process_request (Record *r, uint16_t actions, Record_List *rl, 
                     User_Account *user, Crypt *crypt)
{
    Record *match = NULL;
    int failure = 1;
    int rt_val  = 0;
    ASSERT((r && rl && actions && user && crypt), "Null arguments\n");
    
    if (actions & LIST_ALIASES_ACTION)
        return list_aliases (rl);

    if (actions & NO_ADD_ALIAS_ACTION)
        return print_record_password (r, user->user_salt, 
                                      crypt->password_hashed);

    if ((actions & WRITE_RECORD_ACTION) && !(actions & ADD_NEW_ALIAS_ACTION))
    {

        match = match_record_with_alias (rl, r->alias);

        if (!match)
        {
            fprintf (stderr, "Did not find alias: %s\n", r->alias);
            return failure;
        }

        if (r->stored_password != NULL || match->stored_password != NULL)
        {
            fprintf (stderr, "Error: Cannot alter imported password\n");
            return failure;
        }

        if (actions & SET_LENGTH_ATTR)
            match->pass_length = r->pass_length;

        if (actions & SET_MANDATORY_ATTR)
        {
            if ((set_mandatory_chars (match, r->mandatory_chars)))
            {
                fprintf (stderr, 
                "Error: Failed to add mandatory characters to record: %s\n",
                r->alias);

                return failure;
            }
        }

        if (actions & SET_EXCLUSION_ATTR)
            set_exlusion_chars (match, r->exclusion_chars);

        if (actions & DEPRECATE_ATTR)
            deprecate_record (match);

        if (actions & DEPRECATE_SET)
            match->dep_counter = r->dep_counter;
    }


    if (actions & ADD_NEW_ALIAS_ACTION)
    {
        if ((match = match_record_with_alias (rl, r->alias)))
        {
            fprintf (stderr, "Error: A record with alias: %s is ", r->alias);
            fprintf (stderr, "already entered in the database\n");
            return failure;
        }
        rt_val = add_record (rl, r);
    }

    if (actions & GET_ALIAS_ACTION && rt_val == 0)
    {
        if (!(match = match_record_with_alias (rl, r->alias)))
        {
            fprintf (stderr, "Error: Could not match a record with alias:");
            fprintf (stderr, " %s\n", r->alias);
            return failure;
        }

        rt_val = print_record_password (match, user->user_salt, 
                                        crypt->password_hashed);
    }

    if (actions & REMOVE_ALIAS_ACTION)
        if ((rt_val = remove_record (rl, r->alias)))
            fprintf (stderr, "Error: No alias with that name to remove\n");

    if (rt_val == 0)
        return write_changes_to_disk (rl, user, crypt);
    return failure;
}

void capitalize_input (char *buffer, int buffer_size)
{
    int  i = 0;
    char c = 0;
    for (i = 0; i < buffer_size; i++)
    {
        if (isalpha (buffer[i]))
        {
            c = toupper (buffer[i]);
            buffer[i] = c;
        }
    }
}

ssize_t getline (char **arg, size_t *read, FILE *stream)
{
    char *line = NULL;
    char *temp = NULL;
    size_t so_far      =  0;
    ssize_t failure    = -1;
    size_t current_max = 64;
    int c = 0;
    int nl = '\n';

    if (*arg == NULL && *read == 0)
    {
            line = malloc (65);
        if (!line)
            return failure;

        do {
            if (so_far == current_max)
            {
                temp = realloc (line, (current_max*2) + 1);
                if (!temp)
                {
                    free (line);
                    return failure;
                }
                line = temp;
                current_max *= 2;
            } 
            c = fgetc (stream);
            line[so_far++] = (char) c;
            if (c == nl)
                break;
            
        } while (1);

        line[so_far] = '\0';
        *read = so_far;
        *arg = line;
        return so_far;
    }

    if (*arg == NULL && *read != 0) 
        return failure;
    line = *arg;
    while (so_far < *read)
    {
        c = fgetc (stream);
        line[so_far++] = (char) c;
        if (c == nl)
            break;
    }
    line[so_far] = '\0';
    return so_far;
}

byte * complete_questionaire ()
{
    size_t tot_len     = 0;
    size_t length      = 0;
    ssize_t read       = 0;
    byte *failure   = NULL;
    byte *user_salt = NULL;
    char *fname     = NULL;
    char *mname     = NULL;
    char *lname     = NULL;
    char *bdate     = NULL;
    char *mscho     = NULL;
    char *street    = NULL;
    char *ssn       = NULL;
    char *combo     = NULL;
    ssize_t fname_len =   0;
    ssize_t mname_len =   0;
    ssize_t lname_len =   0;
    ssize_t bdate_len =   0;
    ssize_t mscho_len =   0;
    ssize_t street_len =  0;
    ssize_t ssn_len =     0;

    printf ("  The following questionaire will be used in salting the passwords generated\n");
    printf ("this program. To recreate the same passwords, the exact same answers need to\n");
    printf ("given. The capitalization won't matter. If you can't think of a good answer\n");
    printf ("to a question, just leave it blank.\n\n");
    printf ("Some hints on formatting your answers are given for convenience, in order to\n");
    printf ("make it easier to remember the format you answered it in\n\n");

    printf ("First Name:\n");
    if ((fname_len = getline (&fname, &length, stdin)) == -1)    
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (fname_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        free (fname);
        return failure;
    }
    tot_len += fname_len;
    capitalize_input (fname, fname_len);
    length = 0;

    printf ("Middle Name:\n");
    if ((mname_len = getline (&mname, &length, stdin)) == -1)    
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (mname_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        free (mname);
        return failure;
    }
    tot_len += mname_len;
    capitalize_input (mname, mname_len);
    length = 0;

    printf ("Last Name:\n");
    if ((lname_len = getline (&lname, &length, stdin)) == -1)    
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (lname_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        secure_free (mname, mname_len);
        free (lname);
        return failure;
    }

    tot_len += lname_len;
    capitalize_input (lname, lname_len);
    length = 0;

    printf ("Birthdate (00/00/0000):\n");
    if ((bdate_len = getline (&bdate, &length, stdin)) == -1)    
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (bdate_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        secure_free (mname, mname_len);
        secure_free (lname, lname_len);
        free (bdate);
        return failure;
    }

    tot_len += bdate_len;
    capitalize_input (bdate, bdate_len);
    length = 0;

    printf ("Middle School Attended:\n");
    if ((mscho_len = getline (&mscho, &length, stdin)) == -1)    
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (mscho_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        secure_free (mname, mname_len);
        secure_free (lname, lname_len);
        secure_free (bdate, bdate_len);
        free (mscho);
        return failure;
    }

    tot_len += mscho_len;
    capitalize_input (mscho, mscho_len);
    length = 0;

    printf ("Street you grew up on\n");
    if ((street_len = getline (&street, &length, stdin)) == -1)   
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (street_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        secure_free (mname, mname_len);
        secure_free (lname, lname_len);
        secure_free (bdate, bdate_len);
        secure_free (mscho, mscho_len);
        free (street);
        return failure;
    }
 
    tot_len += street_len;
    capitalize_input (street, street_len);
    length = 0;

    printf ("Social Security Number (xxx-xx-xxxx):\n");
    if ((ssn_len = getline (&ssn, &length, stdin)) == -1)  
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (ssn_len <= 0)
    {
        fprintf (stderr, "Error: invalid read of input\n");
        secure_free (fname, fname_len);
        secure_free (mname, mname_len);
        secure_free (lname, lname_len);
        secure_free (bdate, bdate_len);
        secure_free (mscho, mscho_len);
        secure_free (street, street_len);
        free (ssn);
        return failure;
    }

    tot_len += ssn_len;
    capitalize_input (ssn, ssn_len);
    length = 0;

    combo = calloc (tot_len + 1, 1);
    strncat (combo, fname, fname_len);
    strncat (combo, mname, mname_len);
    strncat (combo, lname, lname_len);
    strncat (combo, bdate, bdate_len);
    strncat (combo, mscho, mscho_len);
    strncat (combo, street, street_len);
    strncat (combo, ssn, ssn_len);

    user_salt = get_var_len_hash ((byte*) combo, tot_len, 16);
    secure_free (fname, fname_len); secure_free (mname, mname_len); 
    secure_free (bdate, bdate_len); secure_free (lname, lname_len);  
    secure_free (street, street_len); secure_free (mscho, mscho_len);  
    secure_free (ssn, ssn_len); secure_free (combo, tot_len);

    return user_salt;
}

char * get_new_password ()
{
    char *failure  = NULL;
    char *password = NULL;
    size_t length = 0;
    ssize_t read  = 0;
    char newline = '\n';

    printf ("Warning: Most of the entropy comes from your password\n");
    printf ("Make it a good one\n");
    printf ("Enter Password:\n");
    if ((read = getline (&password, &length, stdin)) == -1)
    {
        fprintf (stderr, "Error: Could not read input\n");
        return failure;
    }
    if (read == 1)
    {
        fprintf (stderr, "Error: Password must be at least length 1\n");
        return failure;
    }
    if (memcmp (&password[read-1], &newline, 1) == 0)
    {
        password[read-1] = '\0';    
    }
    return password;
}

int create_account (char *db_path, uint8_t overwrite)
{
    ASSERT(db_path, "Null arguments\n");
    int failure = 1;
    int rt_val  = 0;
    if (access (db_path, F_OK) != -1 && !overwrite)
    {
        fprintf (stderr, "Error: Cannot overwrite an existing database\n");
        return failure;
    }
    byte *user_salt = complete_questionaire ();
    if (!user_salt)
    {
        fprintf (stderr, "Error: Could not get information\n");
        fprintf (stderr, "Cannot create new account\n");
        return failure;
    }

    char *password = get_new_password ();
    if (!password)
    {
        fprintf (stderr, "Error: Did not get a password for account\n");
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        return failure;
    }

    if (!user_salt)
    {
        fprintf (stderr, "Error: Could not generate user salt\n");
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        secure_free (password, strlen (password));
        return failure;
    }
    char *db_buf = calloc (10208, 1);
    if (!db_buf)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        secure_free (password, strlen (password));
        return failure;
    }

    byte *password_hashed = get_var_len_hash ((byte*) password, 
                                              strlen (password), 16);
    if (!password_hashed)
    {
        fprintf (stderr, "Error: Could not complete operation\n");
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        secure_free (password, strlen (password));
        secure_free (db_buf, 10208);
        return failure;
    }



    int start = get_start (password_hashed);
    if (!start)
    {
        fprintf (stderr, "Error: Could not complete operation\n");
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        secure_free (password, strlen (password));
        secure_free (password_hashed, 16);
        secure_free (db_buf, 10208);
        return failure;
    }

    memcpy (&db_buf[start], user_salt, 16);

    byte *encrypted_db = enc_buffer ((byte*) db_buf, 10208, password_hashed);
    if (!encrypted_db)
    {
        fprintf (stderr, "Error: Could not encrypt database\n");
        fprintf (stderr, "Cannot create new account\n");
        secure_free (user_salt, 16);
        secure_free (password, strlen (password));
        secure_free (password_hashed, 16);
        secure_free (db_buf, 10208);
        return failure;
    }
    secure_free (user_salt, 16);
    secure_free (password, strlen (password));
    secure_free (password_hashed, 16);
    secure_free (db_buf, 10208);

    rt_val = write_buf_to_disk (db_path, encrypted_db, 10240);
    secure_free (encrypted_db, 10240);
    return rt_val;
}

uint8_t get_uint (char *arg)
{
    uint8_t failure = 0;
    errno = 0;
    long int convert = strtol (arg, NULL, 10);  
    if (errno)
    {
        perror ("Error: Parsing integer\n");
        return failure;
    }
    if (convert < 0)
    {
        fprintf (stderr, "Error: Integer must be a positive whole number\n");
        return failure;
    }
    if (convert > 255)
        return failure;
    return (uint8_t) convert;
}

byte * get_db_buffer (User_Account *user)
{
    ASSERT((user), "Null arguments\n");
    byte *db_buf  = NULL;
    byte *failure = NULL;
    FILE *fp      = NULL;
    errno = 0;  
    long int f    = 0;
    
    fp = fopen (user->db_path, "r");
    if (!fp)
    {
        perror ("Error: Could not open database\n");
        return failure;
    }
    errno = 0;
    fseek (fp, 0L, SEEK_END);
    f = ftell (fp);
    if (f < 0)
    {
        perror ("Error: Couldn't get file size\n");
        return failure;
    }
    else
        user->db_size = (size_t) f;

    rewind (fp);

    db_buf = malloc (user->db_size + 1);
    if (!db_buf)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    errno = 0;
    if ((fread (db_buf, 1, user->db_size, fp) != user->db_size))
    {
        perror ("Error: Could not read database\n");
        fclose (fp);
        free (db_buf);
        return failure;
    }
    fclose (fp);
    db_buf[user->db_size] = '\0';
    return db_buf;
}
    
byte * get_user_salt (byte *dec_db, int start_position)
{
    ASSERT((dec_db && start_position), "Null arguments\n");
    byte *user_salt = calloc (17, 1);
    if (!user_salt)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return NULL;
    }

    memcpy (user_salt, &dec_db[start_position + 16], 16);
    return user_salt;
}

int sanitize_input (byte *input, size_t input_len)
{
    size_t i = 0;
    for (i = 0; i < input_len; i++)
    {
        if (input[i] == 0xff)
            return 1;
    }
    return 0;
}
