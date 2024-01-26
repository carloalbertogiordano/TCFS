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
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../tcfs_utils/tcfs_utils.h" //TODO: Remove, for debugging only

#define BLOCKSIZE 1024
/**
 * @def ENCRYPT
 * @brief Signifies that the selected action is encryption
 * */
#define ENCRYPT 1
/**
 * @def DECRYPT
 * @brief Signifies that the selected action is decryption
 * */
#define DECRYPT 0

extern int do_crypt (FILE *in, FILE *out, int action, unsigned char *key_str);

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