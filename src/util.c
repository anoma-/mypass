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


#include "util.h"

typedef struct token_t token_t;

inline void 
secure_free (void *ptr, size_t ptr_size)
{
    clear_memory (ptr, 0, ptr_size);
    free (ptr);
}

/*  Helper functions:
    Find first byte occurance of the delimeter, and then check the 
    rest of the delimeter */
static int first_del_offset (const unsigned char *stream, size_t s_len, 
                             const char *del, int d_len)
{
    if (stream == NULL || s_len <= 0 || del == NULL || d_len <= 0)
        return -1;
    /*  iterate thru each byte, and try and match the first char of the 
     *  delimeter */
    size_t i;
    for (i = 0; i < s_len - d_len; i++)
    {
        if (memcmp (&stream[i], del, 1) == 0)
        {
            if (memcmp (&stream[i], del, d_len) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}


/*  Break the stream into substrings. Only return substrings inbetween 
 *  two delimeters.
 *  The memory allocated should be freed with Token_free 
*/
token_t * Token_tokenize (const unsigned char *stream, size_t s_len, 
                         const char *del, int d_len)
{
    if (stream == NULL || s_len <= 0 || del == NULL || d_len <= 0)
        return NULL;
    
    int f_offset = 0; /* The offset to first offsetting byte */
    struct token_t *t = malloc (sizeof (struct token_t));
    if (t == NULL)
    {
        fprintf (stderr, "Token_tokenize: Error allocating memory\n");
        return NULL;
    }

    t->list_size = 0;
    t->token_list = NULL;

    /*  While first_del_offset is return positive numbers 
     *  (or is succesfully finding delimeters */
    while (f_offset >= 0)
    {
        /*  Pass the stream pointer at our current offset location, 
         *  and find the first occurance of delimeter starting here */
        f_offset += first_del_offset (&stream[f_offset], s_len - f_offset, 
                                      del, d_len);
        /*  Sanity check  */
        if (f_offset >= 0 && (size_t) f_offset < s_len)
        {
            /*  Find the next offset with the stream pointer past the 
             *  first delimeter */
            int s_offset = first_del_offset (&stream[f_offset + d_len], 
                                                s_len - (f_offset + d_len),
                                                del, 
                                                d_len);
            if (s_offset > 0)
            {
                /*  We have the first offset value, and a relative offset 
                 *  value of the second. 
                 *  Which means we can allocate space for the substring 
                 *  in the token_list.
                 *  Since s_offset is relative to the end of the delimeter 
                 *  from the f_offset.
                 *  s_offset is the size of the substring */
                /*  Allocate the list of tokens size  */
                errno = 0;
                if (t->list_size < 0)
                {
                    fprintf (stderr, "Error: list_size is a negative number\n");
                    goto cleanup;
                }
                char **temp = realloc (t->token_list,
                                       (t->list_size + 1) * sizeof (char *));
                if (temp == NULL)
                {
                    perror ("util.c: Token_tokenize: Error allocating memory");
                    goto cleanup;
                }
                t->token_list = temp;

                /*  allocate for string + \0 */
                t->token_list[t->list_size] = calloc (1, s_offset+1); 
                errno = 0;
                if (t->token_list[t->list_size] == NULL)
                {
                    perror ("util.c: Token_tokenize: Error allocating memory");
                    goto cleanup;
                }
                errno = 0;
                t->token_list[t->list_size] = memcpy ( 
                                                t->token_list[t->list_size], 
                                                 &stream[f_offset + d_len],
                                                 s_offset);
                
                /*  Increment the list size, and move the f_offset 
                 *  up to the s_offset */
                t->list_size++;
                /*  Add relative value of the s_offset */
                f_offset += (s_offset + d_len); 
            }
            else {
                f_offset = -1;
                break;
            } 
        }
    }
    return t;


    cleanup:
        Token_free (t);
        return NULL;
}           

void Token_free (struct token_t* t)
{

    if (t != NULL)
    {
        if (t->token_list != NULL)
        {
            int i = 0; 
            for (; i < t->list_size; i++)
            {
                if (t->token_list[i] != NULL)
                {
                    size_t len = strlen (t->token_list[i]);
                    clear_memory (t->token_list[i], 1, len);
                    free (t->token_list[i]);
                }
            }
            clear_memory (t->token_list, 1, sizeof (char*) * t->list_size);
            free (t->token_list);
        }
        clear_memory (t, 1, sizeof (token_t*));
        free (t);
    }
}

/* Test 
int main (int argc, char** argv)
{
    char st[] = "A  uu Tesasdfataluadu end uu asdfuu uu u u?#)ALKJDFuu;lkja;slkdf ";
    char del[] = "uu";
    struct token_t *tp = Token_tokenize (st, strlen (st), del, strlen (del));
    if (tp != NULL)
    {
        int i = 0;
        for (; i < tp->list_size; i++)
            printf ("%s\n", tp->token_list[i]);
        Token_free (tp);
    }
    return 0;
}
*/  

/*  Clear a segment of memory */
void * clear_memory (void *v, int c, size_t n)
{
    volatile unsigned char *p = v;
    while (n--)
        *p++ = c;
    return v;
}


