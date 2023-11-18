#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "../tcfs_utils/tcfs_utils.h" //TODO: Remove, for debugging only

#define BLOCKSIZE 1024
#define ENCRYPT 1
#define DECRYPT 0

/* int do_crypt(FILE* in, FILE* out, int action, char* key_str)
 * Purpose: Perform cipher on in File* and place result in out File*
 * Args: FILE* in      : Input File Pointer
 *       FILE* out     : Output File Pointer
 *       int action    : Cipher action (1=encrypt, 0=decrypt, -1=pass-through (copy))
 *	 unsigned char *key_str : C-string containing passphrase from which key is derived
 * Return: 0 on error, 1 on success
 */
extern int do_crypt(FILE* in, FILE* out, int action, unsigned char *key_str);

/* void generate_key(unsigned char *destination)
 * Purpose: Generate an AES 256 key of size 32 bytes
 * Args: unsigned char *destination    : The destination for the generated key. it must be 33 bytes long to account for a \0
 * Return: void, if the generation failed an error will be thrown
 */
void generate_key(unsigned char *destination);

/*unsigned char* encrypt_string(unsigned char* plaintext, const char* key, int *encrypted_len)
 * Purpose: Encrypt a string with AES-256
 * Args: unsigned char* plaintext   : The plaintext to be encrypted
 *       const char* key            : The key for the encryption
 *       int *encrypted_len         : This will be filled with the encrypted text length
 * Return: The encrypted string + \0. On error null is returned
 * */
unsigned char* encrypt_string(unsigned char* plaintext, const char* key, int *encrypted_len);

/*unsigned char* decrypt_string(unsigned char* base64_ciphertext, const char* key);
 * Purpose: Decrypt a string with AES-256
 * Args: unsigned char* base64_ciphertext   : The cyphertext to be decrypted
 *       const char* key            : The key for the decryption
 * Return: The decrypted string + \0. On error null is returned
 * */
unsigned char* decrypt_string(unsigned char* base64_ciphertext, const char* key);

/*int is_valid_key(const unsigned char* key);
 * Purpose: Check if a AES-256 key is valid
 * Args: unsigned char* key   : The key to be checked
 * Return: 1 if the key is valid, 0 if it is invalid
 * */
int is_valid_key(const unsigned char* key);

/*
int rebuild_key(char *key, char *cert, char *dest);
*/