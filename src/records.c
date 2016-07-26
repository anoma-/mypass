/* /ypass a deterministic password generator
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


#include "records.h"

void free_record (Record *r)
{
    if (r)
    {
        if (r->alias)
            secure_free (r->alias, strlen (r->alias));
        if (r->exclusion_chars)
            secure_free (r->exclusion_chars, strlen (r->exclusion_chars));
        if (r->stored_password)
            secure_free (r->stored_password, r->pass_length);
        if (r->mandatory_chars)
            secure_free (r->mandatory_chars, strlen (r->mandatory_chars));
        free (r);
        r = NULL;
    }
}   

Record * new_record ()
{
    Record *r = calloc (sizeof (Record), 1);
    r->flags = DEFAULT_FLAG;
    r->pass_length = DEFAULT_PASS_LENGTH;
    r->dep_counter = 1;
    r->stored_password = NULL;
    r->mandatory_chars = NULL;
    r->exclusion_chars = NULL;
    r->alias           = NULL;
    return r;
}

Record * cpy_record (Record *_r)
{
    Record *r = new_record ();
    Record *failure = NULL;
    if (!r)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    r->alias = calloc (strlen (_r->alias) + 1, 1);
    if (!r->alias)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        free_record (r);
        return failure;
    }

    memcpy (r->alias, _r->alias, strlen (_r->alias));
    if (_r->mandatory_chars)
    {
        r->mandatory_chars = calloc (strlen (_r->mandatory_chars) + 1, 1);
        if (!r->mandatory_chars)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }

        memcpy (r->mandatory_chars, _r->mandatory_chars, 
                strlen (_r->mandatory_chars));
    }
    if (_r->exclusion_chars)
    {
        r->exclusion_chars = calloc (strlen (_r->exclusion_chars) + 1, 1);
        if (!r->exclusion_chars)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }

        memcpy (r->exclusion_chars, _r->exclusion_chars, 
                strlen (_r->exclusion_chars));
    }
    if (_r->stored_password)
    {
        r->stored_password = calloc (strlen (_r->stored_password) + 1, 1);
        if (!r->stored_password)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }

        memcpy (r->stored_password, _r->stored_password, 
                strlen (_r->stored_password));
    }
    r->flags = _r->flags;
    r->dep_counter = _r->dep_counter;
    r->pass_length = _r->pass_length;
    return r;
}

/*  Return length of a record or 0 on failure */
int count_record_length (Record *r)
{
	int failure = 0;
	int length  = 0;

	if (!r)
		return failure;
	if (!r->alias)
		return failure;

	length += strlen (r->alias);
	length += 1;
	length += 3;
	length += 1;
	if (r->mandatory_chars && (r->flags & MANDATORY_FLAG))
		length += strlen (r->mandatory_chars) + 1;
	if (r->exclusion_chars && (r->flags & EXCLUSION_FLAG))
		length += strlen (r->exclusion_chars) + 1;
	if (r->stored_password && (r->flags & STORED_PASSWORD_FLAG))
		length += strlen (r->stored_password) + 1;
	r->total_length = length;
	return length;
}

char * _write_records_to_buffer (Record_List *rl, char *delimeter)
{
	char *failure = NULL;
	char *rec_buf = NULL;
	int   rec     = 0;
	char  del     = (char) 0xff;
    /*  Get a buffer at maximum length, plus the delimeters and NULL */
    rec_buf = malloc ((rl->record_count * MAX_RECORD_LENGTH) + 
                      (16 + 1));
	if (!rec_buf)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		return failure;
	}	
	/*  For strncat */
	rec_buf[0] = '\0';
    /*  Add the Delimeter to the record buffer */
	strncat (rec_buf, delimeter, strlen (delimeter));
    /*  Add each record and field delimeter, and field to the record buffer */
	for (rec = 0; rec < rl->record_count; rec++)
	{
		Record *r         = rl->record_list[rec];

		strncat (rec_buf, r->alias, strlen (r->alias));
        strncat (rec_buf, &del, 1);
        strncat (rec_buf,(char*) &r->flags, 1);
        strncat (rec_buf, (char*) &r->pass_length, 1);
        strncat (rec_buf, (char*) &r->dep_counter, 1);
        strncat (rec_buf, &del, 1);
        if ((r->flags & EXCLUSION_FLAG) && r->exclusion_chars)  
        {
            strncat (rec_buf, r->exclusion_chars, strlen (r->exclusion_chars));     
            strncat (rec_buf, &del, 1);
        }
        if ((r->flags & MANDATORY_FLAG) && r->mandatory_chars)  
        {
            strncat (rec_buf, r->mandatory_chars, strlen (r->mandatory_chars));     
            strncat (rec_buf, &del, 1);
        }   
        if ((r->flags & STORED_PASSWORD_FLAG) && r->stored_password)    
        {
            strncat (rec_buf, r->stored_password, strlen (r->stored_password));     
            strncat (rec_buf, &del, 1);
        }   
	}
    /*  Add the Delimeter to the end of the entries */
    strncat (rec_buf, delimeter, strlen (delimeter));

	return rec_buf;
}
/*
 *  Deprecated 
char * write_records_to_buffer (Record_List *rl, char *delimeter)
{
    char *failure = NULL;
    char *rec_buf = NULL;
    int  rec      = 0;  
    char del      = (char) 0xff;    

    rec_buf = malloc ((rl->record_count * MAX_RECORD_LENGTH) + 
                      (8 * (rl->record_count + 1)) + 1);
    if (!rec_buf)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }
    
    rec_buf[0] = '\0';  
    strncat (rec_buf, delimeter, strlen (delimeter));   
    

    for (rec = 0; rec < rl->record_count; rec++)
    {
        Record *r = rl->record_list[rec];
        strncat (rec_buf, r->alias, strlen (r->alias));
        strncat (rec_buf, &del, 1);
        strncat (rec_buf,(char*) &r->flags, 1);
        strncat (rec_buf, (char*) &r->pass_length, 1);
        strncat (rec_buf, (char*) &r->dep_counter, 1);
        strncat (rec_buf, &del, 1);
        if ((r->flags & EXCLUSION_FLAG) && r->exclusion_chars)  
        {
            strncat (rec_buf, r->exclusion_chars, strlen (r->exclusion_chars));     
            strncat (rec_buf, &del, 1);
        }
        if ((r->flags & MANDATORY_FLAG) && r->mandatory_chars)  
        {
            strncat (rec_buf, r->mandatory_chars, strlen (r->mandatory_chars));     
            strncat (rec_buf, &del, 1);
        }   
        if ((r->flags & STORED_PASSWORD_FLAG) && r->stored_password)    
        {
            strncat (rec_buf, r->stored_password, strlen (r->stored_password));     
            strncat (rec_buf, &del, 1);
        }   
        strncat (rec_buf, delimeter, strlen (delimeter));
    }
    return rec_buf;
}
*/

Record * match_record_with_alias (Record_List *rl, char *alias)
{
    ASSERT((rl && alias), "Null args\n");
    Record *failure = NULL;
    int i       = 0;

    for (i = 0; i < rl->record_count; i++) 
    {
        char *r_alias = rl->record_list[i]->alias;
        if (strcmp (alias, r_alias) == 0)
            return rl->record_list[i];  
    }

    return failure;
}

Record * load_record_from_token (char *record_buf)
{
    ASSERT(record_buf, "Null arguments\n");
    Record      *failure      = NULL;
    Record      *r            = NULL;
    char        *field_token  = NULL;

    int         alias_length     = 0;
    int         exclusion_length = 0;
    int         mandatory_length = 0;
	int 		total_length     = 0;

    char field_del[2];
    memset (&field_del[0], 255, 1);
    field_del[1] = '\0';

    field_token = strtok (record_buf, field_del);
    if (!field_token)
    {
        fprintf (stderr, "Error: Failed to parse db\n");
        return failure;
    }

    r = calloc (1, sizeof (Record));
    if (!r)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    /*  parse the first field: alias   */
    alias_length = (int) strlen (field_token);

    r->alias = calloc (alias_length + 2, 1);
    if (!r->alias)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        free (r);
        return failure;
    }

    memcpy (r->alias, field_token, alias_length);

    /*  parse the second field: flags   */
    field_token = strtok (NULL, field_del);
    
    if (!field_token || strlen (field_token) != 3)
    {
        fprintf (stderr, "Error: Failure to parse record\n");
        free_record (r);
        return failure;
    }
    
    /*  Set flags for the Account   */
    r->flags        = (uint8_t) field_token[0];
    r->pass_length  = (uint8_t) field_token[1];
    r->dep_counter  = (uint8_t) field_token[2];
    if (r->pass_length < 1 || r->pass_length > 64)
    {
        fprintf (stderr, "Error: Invalid fields while parsing record\n");
        free_record (r);
        return failure;
    }

    /*  Parse flags   */
    /*  If we expect some characters to be excluded   */
    if (r->flags & EXCLUSION_FLAG)
    {
        field_token = strtok (NULL, field_del);

        if (!field_token)
        {
            fprintf (stderr, "Error: Failure to parse record\n");
            free_record (r);
            return failure;
        }

        exclusion_length = strlen (field_token);
        if (exclusion_length > 18)
        {
            fprintf (stderr, "Error: Failure to parse record\n");
            free_record (r);
            return failure;
        }

        r->exclusion_chars = calloc (1, exclusion_length + 1);
        if (!r->exclusion_chars)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }

        memcpy (r->exclusion_chars, field_token, exclusion_length);
    }

    /*  If we expect some characters to append */
    if (r->flags & MANDATORY_FLAG)
    {
        field_token = strtok (NULL, field_del);
        if (!field_token)
        {
            fprintf (stderr, "Error: Failed to parse record\n");
            free_record (r);
            return failure;
        }

        mandatory_length = strlen (field_token);
        r->mandatory_chars = calloc (1, mandatory_length + 1);
        if (!r->mandatory_chars)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }
        
        memcpy (r->mandatory_chars, field_token, mandatory_length);
    }

    /* If we are expecting a stored password   */
    if (r->flags & STORED_PASSWORD_FLAG)
    {
        field_token = strtok (NULL, field_del);
        if (!field_token)
        {
            fprintf (stderr, "Error: Failed to parse record\n");
            free_record (r);
            return failure;
        }
        
        r->stored_password = calloc (strlen (field_token) + 1, 1);
        if (!r->stored_password)
        {
            fprintf (stderr, "%s\n", Error_Memory);
            free_record (r);
            return failure;
        }
        memcpy (r->stored_password, field_token, strlen (field_token));
    }
	/*  Add value of the delimeter */
	if (mandatory_length)
		mandatory_length++;	
	/*  Add value of the delimeter */
	if (exclusion_length)
		exclusion_length++;
	/*  Add length of stored password plus delimeter */
	if (r->stored_password)
		total_length += r->pass_length + 1;
	total_length = alias_length + 1 + 3 + 1 + exclusion_length + mandatory_length;
	r->total_length = total_length;
    return r;
}   

void free_record_list (Record_List *rl)
{
    if (rl == NULL) 
        return;
    if (rl->record_list)
    {
        int j = 0;
        for (; j < rl->record_count; j++)
        {
            if (rl->record_list[j])
            {
                free_record (rl->record_list[j]);
            }
        }
        free (rl->record_list);
    }
    free (rl);
    rl = NULL;
}
/*  Parse the buffer between crypt->delimeter and crypt->delimeter */
Record_List * _get_record_list_from_buffer (char *db_buf, size_t db_size, 
                                            char *delimeter)
{
    token_t *records_token = Token_tokenize ((byte*) db_buf, db_size, 
                                             delimeter, strlen (delimeter));
	size_t records_size  = 0;
	char *records        = NULL;
	Record_List *failure = NULL;

	if (!records_token)
		return failure;

	Record_List *rl = malloc (sizeof (Record_List));
	if (!rl)
	{
		fprintf (stderr, "%s\n", Error_Memory);
        Token_free (records_token);
		return failure;
	}

	size_t offset       = 0;
	rl->record_count    = 0;
	rl->record_list     = NULL;
	if (records_token->list_size)
	{
		records = records_token->token_list[records_token->list_size-1];
		records_size  = strlen (records);
	}

	while (offset < records_size)
	{
		/*  Load the offsetted record buffer into the load_from_token function 
			reading the total length of the Record from the return of the function
			if it returns a valid function, grow the record_list and increment the 
			count 
		 */
		Record *current = load_record_from_token (&records[offset]);
		if (current)
		{
			offset += current->total_length; 
			rl->record_count++;
			Record **temp = realloc (rl->record_list, sizeof (Record*) * rl->record_count);
			if (temp)
				rl->record_list = temp;
			else
			{
				fprintf (stderr, "%s\n", Error_Memory);
				free_record_list (rl);
                Token_free (records_token);
				return failure;
			}
			rl->record_list[rl->record_count - 1] = current;
		}
		else
		{
			fprintf (stderr, "Error: Failure to parse database\n");
			free_record_list (rl);	
            Token_free (records_token);
			return failure;
		}
	}
    Token_free (records_token);
	return rl;
}

/*  Deprecated 
Record_List * get_record_list_from_buffer (char *records, size_t records_size, 
                                           char *delimeter)
{
    ASSERT(records && delimeter, "Null arguments\n");
    Record_List *failure    = NULL;
    Record_List *rl         = NULL;
    token_t *record_list    = NULL;
    int i                   = 0;
    int j                   = 0;
    

    record_list = Token_tokenize ((byte*) records, records_size, 
                                  delimeter, strlen (delimeter));
    
    rl = calloc (1, sizeof (Record_List));
    if (!rl)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        Token_free (record_list);
        return failure;
    }

    rl->record_list  = NULL;
    rl->record_count = 0;   
    rl->record_list = malloc (sizeof (Record*) * record_list->list_size);
    if (!rl->record_list)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        Token_free (record_list);
        return failure;
    }
    rl->record_count = record_list->list_size;
    if (rl->record_count == 0)
    {
        Token_free (record_list);
        return rl;
    }

    for (i = 0; i < record_list->list_size; i++) 
    {
        Record *r = load_record_from_token (record_list->token_list[i]);
        
        if (r)
                rl->record_list[j++] = r;
        else 
        {
            rl->record_count--;
            rl->record_list = realloc (rl->record_list, 
                                       sizeof (Record*) * rl->record_count);
        }
    }

    Token_free (record_list);
    return rl;
}
*/

int rm_exclusion_chars (Record *r)
{
    ASSERT(r, "Null arguments\n");
    if (r->exclusion_chars)
    {
        free (r->exclusion_chars);
        r->exclusion_chars = NULL;
    }
    r->flags &= (0xff ^ EXCLUSION_FLAG);
    return 0;
}

int set_exlusion_chars (Record *r, char *excluding_chars)
{
    ASSERT((r), "Null arguments\n");
    int failure = 1;
    int exc_len = 0;
    /*  remove the old excluding characters, if the new is null return */
    if (r->exclusion_chars && (r->flags & EXCLUSION_FLAG))
        rm_exclusion_chars (r);
    if (!excluding_chars)
        return 0;
    exc_len = strlen (excluding_chars);
    if (exc_len <= 0 || exc_len > MAX_EXCLUDE_LENGTH)
    {
        fprintf (stderr, "Error: Maximum characters to exclude is: %d\n", 
                 MAX_EXCLUDE_LENGTH);

        return failure;
    }

    r->exclusion_chars = calloc (exc_len + 1, 1);
    if (!r->exclusion_chars)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }

    strcpy (r->exclusion_chars, excluding_chars);
    r->flags |= EXCLUSION_FLAG;
    return 0;
}

int rm_mandatory_chars (Record *r)
{
    ASSERT((r && r->alias), "Error Null arguments\n");
    if (r->mandatory_chars)
    {
        free (r->mandatory_chars);
        r->mandatory_chars = NULL;
    }

    r->flags &= (0xff ^ MANDATORY_FLAG);
    return 0;   
}

int set_mandatory_chars (Record *r, char *mandatory_chars)
{
    ASSERT(r, "NULL arguments\n");
    int failure = 1;
    int man_len = 0;

    /*  If we already have mandatory_char list, first remove it.
        Or if new list is NULL */
    if (r->mandatory_chars && (r->flags & MANDATORY_FLAG))  
        rm_mandatory_chars (r); 
    if (!mandatory_chars)
        return 0;   
    man_len = strlen (mandatory_chars);
    if (man_len <= 0 || man_len >= MAX_MANDATORY_LENGTH)
    {
        fprintf (stderr, "Error: Maximum %d", MAX_MANDATORY_LENGTH);
        fprintf (stderr, " characters allowed for the mandatory characters\n");
        return failure;
    }

    r->mandatory_chars = calloc (man_len + 1, 1);
    /* Set the flag to 1 */
    r->flags |= MANDATORY_FLAG;
    strcpy (r->mandatory_chars, mandatory_chars);
    return 0;
}
    
int deprecate_record (Record *r)
{
    ASSERT((r && r->alias), "NULL arguments\n");
    char newline = '\n';

    if (r->dep_counter >= 254)
    {
        printf ("This record (%s) cannot be deprecated further\n", r->alias);
        printf ("Please remove and start a new alias\n");
        return 1;
    } else {
        r->dep_counter++;
        if ((uint8_t)newline == r->dep_counter)
        {
            r->dep_counter++;
        }
    }
    return 0;
}

int remove_stored_password (Record *r)
{
    ASSERT((r && r->alias && r->stored_password), "Null arguments\n");
    if (r->flags & STORED_PASSWORD_FLAG)
        r->flags ^= STORED_PASSWORD_FLAG;
    
    secure_free (r->stored_password, r->pass_length);
    return 0;
}

int import_password (Record *r, char *pass)
{
    ASSERT((r && r->alias && pass), "Null arguments\n");
    int failure = 1;
    int pas_len = 0;

    pas_len = strlen (pass);
    if (pas_len <= 0 || pas_len > 64)
    {
        fprintf (stderr, "Error: Imported password size not in range\n");
        fprintf (stderr, "Min size 1, Max size %d\n", MAX_PASS_LENGTH);
        return failure;
    }

    r->stored_password = calloc (pas_len + 1, 1);
    if (!r->stored_password)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        return failure;
    }
    
    strcpy (r->stored_password, pass);
    r->flags = STORED_PASSWORD_FLAG;
    if (r->exclusion_chars)
        free (r->exclusion_chars);
    if (r->mandatory_chars)
        free (r->mandatory_chars);
    r->pass_length = pas_len;

    return 0;
}   

int add_record (Record_List *rl, Record *r)
{
    ASSERT((rl && r), "Null arguments\n");
    int failure = 1;
    Record **tmp;

    tmp = realloc (rl->record_list, sizeof (Record*) * (rl->record_count + 1));
    if (!tmp)
    {
        fprintf (stderr, "%s\n", Error_Memory);
        fprintf (stderr, "Cannot make changes\n");
        return failure;
    }
    rl->record_list = tmp;

    if (r->pass_length == 0)
        r->pass_length = DEFAULT_PASS_LENGTH;
    if (r->mandatory_chars) 
        r->flags |= MANDATORY_FLAG;
    if (r->exclusion_chars) 
        r->flags |= EXCLUSION_FLAG;
    if (r->stored_password)
        r->flags |= STORED_PASSWORD_FLAG;

    rl->record_list[rl->record_count++] = cpy_record (r);
    if (!rl->record_list[rl->record_count - 1])
    {
        fprintf (stderr, "Error: Failed to copy record to database\n");
        return failure;
    }
	rl->total_length += count_record_length (rl->record_list[rl->record_count -1]);
    return 0;
}

int remove_record (Record_List *rl, char *alias)
{
    ASSERT((rl && alias), "Null args\n");
    int i       = 0;
    int j       = 0;
	int rec_len = 0;
    uint8_t f   = 0;

    /*  If we remove a record, move all other records down the line */
    for (i = 0; i < rl->record_count; i++) 
    {
        /*  f will be 1 if we find a matching record to remove */
        if (f)
            rl->record_list[j++] = rl->record_list[i];
        
        else if (strcmp (alias, rl->record_list[i]->alias) == 0)
        {
			rec_len = count_record_length (rl->record_list[i]);
            free_record (rl->record_list[i]);
            f = 1;
            j = i;
        }

    }
    if (f)
        rl->record_count--;

	rl->total_length -= rec_len;
    return f ^ 1;
}
