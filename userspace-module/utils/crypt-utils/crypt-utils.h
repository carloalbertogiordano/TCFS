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

/*
int rebuild_key(char *key, char *cert, char *dest);
*/