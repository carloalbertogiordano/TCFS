/**
 * @file crypt-utils.h
 * @brief Header file for crypt-utils.c, which provides functions for
 * encryption and decryption using AES-256, as well as other utility functions.
 */

#include <ctype.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <setjmp.h>

/**
 * @def ENCRYPT
 * @brief Signifies that the selected action is encryption
 * */
#define ENCRYPT true
/**
 * @def DECRYPT
 * @brief Signifies that the selected action is decryption
 * */
#define DECRYPT false

/**
 * @def IV_SIZE
 * @brief The fixed size of the initialization vector \link
 * https://en.wikipedia.org/wiki/Initialization_vector IV \endlink. \_def
 * */
#define IV_SIZE 16 // 32

/**
 * @def KEY_SIZE
 * @brief The fixed size of the key. \_def
 * */
#define KEY_SIZE 32

// extern int do_crypt (FILE *in, FILE *out, int action, unsigned char
// *key_str);
extern int do_crypt (int mode, FILE *fp, unsigned char **text, int len, unsigned char *key, unsigned char *iv);


void generate_key (unsigned char *destination);

unsigned char *encrypt_string (unsigned char *plaintext, const char *key,
                               int *encrypted_len);

unsigned char *decrypt_string (unsigned char *base64_ciphertext,
                               const char *key);

int is_valid_key (const unsigned char *key);

const char *encrypt_file_name_with_hex (const char *file, const char *key);

const char *decrypt_file_name_with_hex (const char *enc_file, const char *key);

const char *encrypt_path (const char *path, const char *key);

const char *encrypt_path_and_filename (const char *path, const char *key);

const char *decrypt_path (const char *encrypted_path, const char *key);

const char *decrypt_path_and_filename (const char *encrypted_path,
                                       const char *key);

extern unsigned char *generate_iv (void);

unsigned char *encrypt_buffer (const char *buf, size_t size,
                               unsigned char *key);
