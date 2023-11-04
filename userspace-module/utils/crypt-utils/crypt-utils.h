#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCKSIZE 1024
#define FAILURE 0
#define SUCCESS 1

/* int do_crypt(FILE* in, FILE* out, int action, char* key_str)
 * Purpose: Perform cipher on in File* and place result in out File*
 * Args: FILE* in      : Input File Pointer
 *       FILE* out     : Output File Pointer
 *       int action    : Cipher action (1=encrypt, 0=decrypt, -1=pass-through (copy))
 *	 char* key_str : C-string containing passpharse from which key is derived
 * Return: FAILURE on error, SUCCESS on success
 */
extern int do_crypt(FILE* in, FILE* out, int action, char* key_str);

/* char *generate_key()
 * Purpose: Generate a random key for AES encryption
 * Return: NULL on error, A char* on success
 */
unsigned char *generate_key();
