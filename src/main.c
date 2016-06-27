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
#include <getopt.h>
#include "common.h"
#include "util.h"
#include "records.h"
#include "passman.h"
#include "crypt.h"

void print_version ()
{
    printf (MYPASS_VERSION);
}

int main (int argc, char **argv)
{
    if (argc <= 1)
        print_help ();

    int c              = 0;
    int rt_val         = 0;
    int failure        = 1;
    int opt_len        = 0;
    uint16_t actions   = 0;
    uint8_t overwrite  = 0;
    Record_List *rl = NULL; 
    extern char *optarg;
    extern int optind, optopt;
    byte *db_buffer = NULL;
    char *dec_db    = NULL;
    User_Account *user = new_user_account ();
    Crypt *crypt      = new_crypt ();   
    Record *r = new_record (); 
    if (!r)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        exit (failure);
    }
    int option_index = 0;
    static struct option long_options[] = {
        { "add",           required_argument, 0, 'a'},
        { "get",           required_argument, 0, 'g'},
        { "list",          optional_argument, 0, 'l'},
        { "length",        required_argument, 0, 'L'},
        { "new",           optional_argument, 0, 'n'},
        { "xget",          required_argument, 0, 'x'},
        { "exclude",       optional_argument, 0, 'e'},
        { "mandatory",     optional_argument, 0, 'm'},
        { "deprecate",     no_argument,       0, 'd'},
        { "deprecate-set", required_argument, 0, 'D'},
        { "import",        required_argument, 0, 'i'},
        { "help",          no_argument,       0, 'h'},
        { "version",       no_argument,       0, 'v'},
        { "file",          required_argument, 0, 'f'},
        { "password",      required_argument, 0, 'p'},
        { 0,               0,                 0,  0 }
    };
    /*  Initialize deprecation counter to 1 */
    r->dep_counter = 1;
    while ((c = getopt_long (argc, argv, "vdhL:p:a:g:f:x:s:r:m::e::i:D:n::l::", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'p' :
                opt_len = strlen (optarg);
                crypt->password = calloc (opt_len + 1, 1);
                if (!crypt->password)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                memcpy (crypt->password, optarg, opt_len);  
                crypt->password_hashed = get_var_len_hash ((byte*)crypt->password, opt_len, 16);
                if (!crypt->password_hashed)
                {
                    fprintf (stderr, "Error: Could not get hash\n");
                    goto cleanup;
                }
                break;

            case 'a' :
                opt_len = strlen (optarg);
                if (r->alias)
                {
                    fprintf (stderr, "Error: An alias has already been selected\n");
                    fprintf (stderr, "One operation at a time\n");
                    goto cleanup;
                }
                if (opt_len > ALIAS_MAX_LENGTH)
                {
                    fprintf (stderr, "Error: Alias length is to large\nMax = %d\n", ALIAS_MAX_LENGTH);
                    goto cleanup;
                }
                if (sanitize_input ((byte*)optarg, opt_len))
                {
                    fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                    goto cleanup;
                }
                /*  Plus 2. One for NULL and one for deprecate counter */
                r->alias = calloc (opt_len + 2, 1);
                if (!r->alias)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                memcpy (r->alias, optarg, opt_len);
                actions |= ADD_NEW_ALIAS_ACTION;    
                actions |= GET_ALIAS_ACTION;
                break;

            case 'x' :
                opt_len = strlen (optarg);
                if (r->alias)
                {
                    fprintf (stderr, "Error: An alias has already been selected\n");
                    fprintf (stderr, "One operation at a time\n");
                    goto cleanup;
                }
                if (opt_len > ALIAS_MAX_LENGTH)
                {
                    fprintf (stderr, "Error: Alias length is to large\nMax = %d\n", ALIAS_MAX_LENGTH);
                    goto cleanup;
                }
                /*  1 for NULL one for Deprecate counter */
                r->alias = calloc (opt_len + 2, 1);
                if (!r->alias)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }

                memcpy (r->alias, optarg, opt_len);
                actions |= NO_ADD_ALIAS_ACTION;
                break;

            case 'r' :
                opt_len = strlen (optarg);
                if (r->alias)
                {
                    fprintf (stderr, "Error: An alias has already been selected\n");
                    fprintf (stderr, "One operation at a time\n");
                    goto cleanup;
                }
                if (opt_len > 64)
                {
                    fprintf (stderr, "Error: Alias length is to large\nMax = %d\n", ALIAS_MAX_LENGTH);
                    goto cleanup;
                }
                if (sanitize_input ((byte*)optarg, opt_len))
                {
                    fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                    goto cleanup;
                }

                r->alias = calloc (opt_len + 2, 1);
                if (!r->alias)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                memcpy (r->alias, optarg, opt_len);
                actions |= REMOVE_ALIAS_ACTION;
                break;

            case 'g' :
                opt_len = strlen (optarg);
                if (r->alias)
                {
                    fprintf (stderr, "Error: An alias has already been selected\n");
                    fprintf (stderr, "One operation at a time\n");
                    goto cleanup;
                }
                if (opt_len > 64)
                {
                    fprintf (stderr, "Error: Alias length is to large\nMax = %d\n", ALIAS_MAX_LENGTH);
                    goto cleanup;
                }
                if (sanitize_input ((byte*)optarg, opt_len))
                {
                    fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                    goto cleanup;
                }
                
                r->alias = calloc (opt_len + 2, 1);
                if (!r->alias)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                
                memcpy (r->alias, optarg, opt_len); 
                actions |= GET_ALIAS_ACTION;
                break;          

            case 'f' :
                opt_len = strlen (optarg);
                user->db_path = calloc (opt_len + 1, 1);
                if (!user->db_path)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                memcpy (user->db_path, optarg, opt_len);
                break;

            case 'n' :
                actions |= NEW_ACCOUNT_ACTION;
                char o = 'o';
                if (optarg)
                    if (memcmp (&o, optarg, 1) == 0)
                        overwrite=1;
                break;

            case 'l' :
				if (optarg)
				{
					if (r->alias)
					{
						fprintf (stderr, "Error: Only one operation per alias\n");
						goto cleanup;
					}
					opt_len = strlen (optarg);
					r->alias = calloc (opt_len + 1, 1);
				   	memcpy (r->alias, optarg, opt_len);	
				}
                actions |= LIST_ALIASES_ACTION;
                break;

            case 'h' :
                print_help ();
                exit (0);
                break;

            case 'L' :
                r->pass_length = get_uint (optarg);
                if (!(r->pass_length > 0 && r->pass_length <= MAX_PASS_LENGTH))
                {
                    fprintf (stderr, "Error: Length must be Min 1 Max %d\n", MAX_PASS_LENGTH);
                    goto cleanup;
                }

                actions |= SET_LENGTH_ATTR;
                actions |= WRITE_RECORD_ACTION;
                break;

            case 'D' :
                r->dep_counter = get_uint (optarg);
                if (r->dep_counter == 0)
                {
                    fprintf (stderr, "Error: Deprecation min 1 Max 254\n");
                    goto cleanup;
                }
                if (r->dep_counter == 255)  
                {
                    fprintf (stderr, "Error: Deprecation min 1 max 254\n");
                    goto cleanup;
                }
                actions |= WRITE_RECORD_ACTION;
                actions |= DEPRECATE_SET;
                break;


            case 'i' :
                opt_len = strlen (optarg);
                if (r->stored_password)
                {
                    fprintf (stderr, "Error: Can only import one password at a time\n");
                    goto cleanup;
                }
                if (opt_len > 64)
                {
                    fprintf (stderr, "Error: Max password length is %d\n", MAX_PASS_LENGTH);
                    goto cleanup;
                }
                ASSERT((opt_len != 0), "Importing password with 0 length\n" );
                if (sanitize_input ((byte*)optarg, opt_len))
                {
                    fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                    goto cleanup;
                }
                r->stored_password = calloc (opt_len + 1, 1);
                if (!r->stored_password)
                {
                    fprintf (stderr, "%s\n", Error_Memory);
                    goto cleanup;
                }
                memcpy (r->stored_password, optarg, opt_len);
                r->flags |= STORED_PASSWORD_FLAG;
                r->pass_length = (uint8_t) opt_len;
                actions  |= IMPORT_PASS_ATTR;
                break;

            case 'e' :
                if (optarg)
                {
                    opt_len = strlen (optarg);
                    if (opt_len > MAX_EXCLUDE_LENGTH)
                    {
                        fprintf (stderr, "Error: Can only exclude Max %d characters\n", MAX_EXCLUDE_LENGTH);
                        goto cleanup;
                    }
                    ASSERT((opt_len != 0), "Excluding 0 characters\n");
                    if (r->exclusion_chars)
                    {
                        fprintf (stderr, "Error: Can only set exclusion characters once per operation\n");
                        goto cleanup;
                    }

                    if (sanitize_input ((byte*)optarg, opt_len))
                    {
                        fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                        goto cleanup;
                    }
                    r->exclusion_chars = calloc (opt_len + 1, 1);
                    if (!r->exclusion_chars)
                    {
                        fprintf (stderr, "%s\n", Error_Memory);
                        goto cleanup;
                    }
                    memcpy (r->exclusion_chars, optarg, opt_len);
                }

                r->flags |= EXCLUSION_FLAG;

                actions  |= WRITE_RECORD_ACTION;
                actions  |= SET_EXCLUSION_ATTR;
                break;

            case 'd' :
                actions |= WRITE_RECORD_ACTION;
                actions |= DEPRECATE_ATTR;
                break;

            case 'm' :
                if (optarg)
                {
                    opt_len = strlen (optarg);
                    if (opt_len > MAX_MANDATORY_LENGTH)
                    {
                        fprintf (stderr, "Error: Maximum characters to append is %d\n", MAX_MANDATORY_LENGTH);
                        goto cleanup;
                    }
                    ASSERT((opt_len != 0), "Adding 0 mandatory chars\n");
                    if (r->mandatory_chars)
                    {
                        fprintf (stderr, "Error: Can only set mandatory characters once per operation\n");
                        goto cleanup;
                    }
                    if (sanitize_input ((byte*)optarg, opt_len))
                    {
                        fprintf (stderr, "Error: Invalid character, cannot input %c\n", 0xff);
                        goto cleanup;
                    }

                    r->mandatory_chars = calloc (opt_len + 1, 1);
                    if (!r->mandatory_chars)
                    {
                        fprintf (stderr, "%s\n", Error_Memory);
                        goto cleanup;
                    }

                    memcpy (r->mandatory_chars, optarg, opt_len);
                }

                r->flags |= MANDATORY_FLAG;
                actions  |= WRITE_RECORD_ACTION;
                actions  |= SET_MANDATORY_ATTR;
                break;

            case 'v' :
                print_version ();
                exit (0);
                break;

            case ':' :
                print_help ();
                exit (1);
                break;

            case '?' :
                print_help ();
                exit (1);
                break;

            default:
                print_help ();  
                exit (1);
                break;
        }

    }

    if (!user->db_path)
    {
        char *home = getenv ("HOME");
        if (!home)
        {
            fprintf (stderr, "Error: HOME environmental variable is not set\n");
            goto cleanup;
        }

        char def_path[] = "/.mypass/db";
        int path_len = strlen (home);
        path_len += strlen (def_path);
        user->db_path = calloc (path_len + 1, 1);
        if (!user->db_path)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            goto cleanup;
        }
        strcat (user->db_path, home);
        strcat (user->db_path, def_path);
    }

    
    if ((actions & NEW_ACCOUNT_ACTION) == NEW_ACCOUNT_ACTION)
    {
        rt_val = create_account (user->db_path, overwrite);
        free_record (r);
        free_crypt  (crypt);
        free_user_account (user);
        return rt_val;
    }
    else if (r->alias || (actions & LIST_ALIASES_ACTION)) 
    {
        if (!crypt->password)
        {
            fprintf (stderr, "Error: No password supplied.");
            fprintf (stderr, " Cannot process request\n");
            goto cleanup;
        }
        db_buffer = get_db_buffer (user);   
        if (!db_buffer)
        {
            fprintf (stderr, "Error: Cannot process request\n");
            goto cleanup;
        }

        crypt->delimeter = get_delimeter (crypt->password_hashed);
        if (!crypt->delimeter)
        {
            fprintf (stderr, "Error: Cannot process request\n");
            goto cleanup;
        }

        crypt->start = get_start (crypt->password_hashed);
        if (!crypt->start)
        {
            fprintf (stderr, "Error: Cannot process request\n");
            goto cleanup;
        }

        dec_db = dec_buffer (db_buffer, user->db_size, crypt->password_hashed);
        if (!dec_db)
        {
            fprintf (stderr, "Error: Unable to decrypt database\n");
            fprintf (stderr, "Please check that the password is correct\n");
            free (db_buffer);
            goto cleanup;
        }

        user->user_salt = get_user_salt ((byte*)dec_db, crypt->start);
        if (!user->user_salt)
        {
            fprintf (stderr, "Error: Cannot process request\n");
            secure_free (dec_db, user->db_size);
            free (db_buffer);
            goto cleanup;
        }

        rl = _get_record_list_from_buffer (dec_db, user->db_size,  
                                          crypt->delimeter);    
        if (!rl)
        {
            fprintf (stderr, "Error: Could not parse database\n");
            goto cleanup;
        }
        secure_free (dec_db, user->db_size);
        free (db_buffer);
        rt_val = process_request (r, actions, rl, user, crypt);
        /*  Cleanup */
        free_user_account (user);
        free_crypt (crypt);
        free_record (r);
        free_record_list (rl);
        return rt_val;
    }
    fprintf (stderr, "Error: No actions to take\n");
    cleanup:
    free_user_account (user);
    free_crypt (crypt);
    free_record (r);
    free_record_list (rl);
    return 1;
}

