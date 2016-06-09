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


#include "crypt.h"

Crypt * new_crypt ()
{
	Crypt *c = calloc (sizeof (Crypt), 1);
	c->start = 0;
	c->password        = NULL;
	c->password_hashed = NULL;
	c->delimeter       = NULL;
	return c;
}

void free_crypt (Crypt *c)
{
	if (c)
	{
		if (c->password)
			secure_free (c->password, strlen (c->password));
		if (c->password_hashed)
			secure_free (c->password_hashed, 16);
		if (c->delimeter)
			secure_free (c->delimeter, 8);
		c->delimeter = NULL;
		c->password = NULL;
		c->password_hashed = NULL;
		free (c);
		c = NULL;
	}
}

byte * get_var_len_hash (byte *seed, size_t seed_length, size_t bytes_requested)
{
	Skein1024_Ctxt_t 	ctx;

	byte *hash 	  = NULL;
	byte *failure = NULL;


	hash = calloc (bytes_requested + 1, 1);
	if (!hash)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		return failure;
	}

	if (!(Skein1024_Init (&ctx, bytes_requested * 8L) == SKEIN_SUCCESS)) 
	{
		fprintf (stderr, "Error: Unable to get hash\n");
		free (hash);
		return failure;
	}
	
	if (!(Skein1024_Update (&ctx, seed, seed_length) == SKEIN_SUCCESS))
	{
		fprintf (stderr, "Error: Unable to get hash\n");
		free (hash);
		return failure;
	}

	if (!(Skein1024_Final (&ctx, hash) == SKEIN_SUCCESS))
	{
		fprintf (stderr, "Error: Unable to get hash\n");
		free (hash);
		return failure;
	}

	return hash;
}

/*
 *   Encrypt the input with a 128 bit key
 *
 *   return: An encrypted unsigned char* or byte*
 *   Args: byte* input, the sequence to be encrypted
 *        input_length, the length of the sequence
 *        key_hash_128, the 128 bit hash of the password
 *   Failure:
 *         Null pointer
 *   The byte pointer returned will have an additional 32 bytes.
 *   The eplicit iv is prepended
 *   The input buffer is appended
 *   Then a hash of the iv+msg is appended at the end
 *   Block 1       = IV 
 *   Block 2..N-1  =  buffer
 *   Block N       = skein hash msg+IV
*/

byte * enc_buffer (byte *input, size_t input_length, byte *key_hash_128)
{
	byte *failure = NULL;
	int output_length = input_length + 2 * AES_BLOCK_SIZE;

	byte *output = calloc (output_length + 1, 1);	
	if (!output)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		return failure;
	}
	
	AES_KEY enc_key;
	AES_set_encrypt_key (key_hash_128, 128, &enc_key);

	if ((RAND_bytes (output, AES_BLOCK_SIZE) != 1))
	{
		fprintf (stderr, "Error: Insufficient randomness for seed\n");
		free (output);
		return failure;
	}
	
	/*  Output contains explicit IV, append input */
	memcpy (&output[AES_BLOCK_SIZE], input, input_length);
	/*  Calculate the hash of the input+IV and append to buffer */
	byte *hash = get_var_len_hash (output, AES_BLOCK_SIZE + input_length, 
								   AES_BLOCK_SIZE);
	if (!hash)
	{
		fprintf (stderr, "Error: Could not encrypt database\n");
		fprintf (stderr, "Cannot make changes\n");
		free (output);
		return failure;
	}

	memcpy (&output[AES_BLOCK_SIZE + input_length], hash, AES_BLOCK_SIZE);

	/*  IV is explicit, set IV to 0 */
	byte iv[16];
	memset (iv, 0, 16);
	/*  The encrypted output will be returned on success */	
	byte *encrypted_output = calloc (output_length + 1, 1);
	if (!encrypted_output)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		fprintf (stderr, "Error: Could not enrypt database\n");
		fprintf (stderr, "Cannot make changes\n");
		free (output);
		free (hash);
		return failure;
	}

	AES_cbc_encrypt (output, encrypted_output, output_length, 
			        &enc_key, iv, AES_ENCRYPT);

	secure_free (output, output_length);
	secure_free (hash, 16);
	return encrypted_output;
}

/*  Decrypts input buffer, and authenticates against tamper
 *  return: The decrypted input buffer
 *  Arg: 
 *  	input:        the encrypted buffer
 *  	input_length: the length of the buffer
 *  	key_hash_128: the 16 byte hash of the password
 *
 * 	failure: Null pointer
 *
 * 	Decrypt the buffer, and get 16 byte hash of input ranging
 * 	from 0 .. input_length -16
 * 	compare that hash with the last 16 byte block of the decrypted 
 * 	buffer to ensure the contents were not altered
*/

char * dec_buffer (byte *input, size_t input_length, byte *key_hash_128)
{
	ASSERT((input && input_length && key_hash_128), "Null Arguments\n");
	char* failure = NULL;

	char *dec_output = calloc (input_length + 17, 1);
	if (!dec_output)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		fprintf (stderr, "Could not decrypt database. Out of memory\n");
		return failure;
	}

	AES_KEY dec_key;
	AES_set_decrypt_key (key_hash_128, 128, &dec_key);

	/*  Explicit iv so default to 0's */
	byte iv[16];
	memset (iv, 0, 16);

	AES_cbc_encrypt (input,(byte*) dec_output, input_length, 
					&dec_key, iv, AES_DECRYPT);

	/*  Get the hash of the buffer up to the last block */
	byte *hash = get_var_len_hash ((byte*) dec_output, input_length - 16, 
									AES_BLOCK_SIZE);
	if (!hash)
	{
		fprintf (stderr, "%s\n", Error_Memory);
		fprintf (stderr, "Could not decrypt database. Out of memory\n");
		secure_free (dec_output, input_length);
		return failure;
	}
	
	/*  Ensure the hash matches the final block of the decrypted buffer */
	if ((memcmp (&dec_output[input_length - 16], hash, AES_BLOCK_SIZE) !=0))
	{
		fprintf (stderr, "Error: Could not verify database\n");
		secure_free (dec_output, input_length);
		secure_free (hash, 16);
		return failure;
	}
	
	secure_free (hash, 16);
	
	return dec_output;
}
