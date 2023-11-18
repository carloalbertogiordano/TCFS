/*
 * High level function interface for performing AES encryption on FILE pointers
 * Uses OpenSSL libcrypto EVP API
 *
 * By Andy Sayler (www.andysayler.com)
 * Created  04/17/12
 * Modified 18/10/23 by [Carlo Alberto Giordano]
 *
 * Derived from OpenSSL.org EVP_Encrypt_* Manpage Examples
 * http://www.openssl.org/docs/crypto/EVP_EncryptInit.html#EXAMPLES
 *
 * With additional information from Saju Pillai's OpenSSL AES Example
 * http://saju.net.in/blog/?p=36
 * http://saju.net.in/code/misc/openssl_aes.c.txt
 *
 */
#include "crypt-utils.h"

#define BLOCKSIZE 1024
#define IV_SIZE 32
#define KEY_SIZE 32

extern int do_crypt(FILE* in, FILE* out, int action, unsigned char *key_str){
    /* Local Vars */

    /* Buffers */
    unsigned char inbuf[BLOCKSIZE];
    int inlen;
    /* Allow enough space in output buffer for additional cipher block */
    unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    int writelen;

    /* OpenSSL libcrypto vars */
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int nrounds = 5;

    /* tmp vars */
    int i;
    /* Setup Encryption Key and Cipher Engine if in cipher mode */
    if(action >= 0){
        if(!key_str){
            /* Error */
            fprintf(stderr, "Key_str must not be NULL\n");
            return 0;
        }
        /* Build Key from String */
        i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
                           key_str, (int)strlen((const char *)key_str), nrounds, key, iv);
        if (i != 32) {
            /* Error */
            fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
            return 0;
        }
        /* Init Engine */
        EVP_CIPHER_CTX_init(ctx);
        EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, action);
    }

    /* Loop through Input File*/
    for(;;){
        /* Read Block */
        inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, in);
        if(inlen <= 0){
            /* EOF -> Break Loop */
            break;
        }

        /* If in cipher mode, perform cipher transform on block */
        if(action >= 0){
            if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(ctx);
                return 0;
            }
        }
            /* If in pass-through mode. copy block as is */
        else{
            memcpy(outbuf, inbuf, inlen);
            outlen = inlen;
        }

        /* Write Block */
        writelen = fwrite(outbuf, sizeof(*outbuf), outlen, out);
        if(writelen != outlen){
            /* Error */
            perror("fwrite error");
            EVP_CIPHER_CTX_cleanup(ctx);
            return 0;
        }
    }

    /* If in cipher mode, handle necessary padding */
    if(action >= 0){
        /* Handle remaining cipher block + padding */
        if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            return 0;
        }
        /* Write remainign cipher block + padding*/
        fwrite(outbuf, sizeof(*inbuf), outlen, out);
        EVP_CIPHER_CTX_cleanup(ctx);
    }

    /* Success */
    return 1;
}

// Verify the entropy
int check_entropy(void) {
    FILE *entropy_file = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    if (entropy_file == NULL) {
        perror("Err: Cannot open entropy file");
        return -1;
    }

    int entropy_value;
    if (fscanf(entropy_file, "%d", &entropy_value) != 1) {
        perror("Err: Cannot estimate entropy");
        fclose(entropy_file);
        return -1;
    }

    fclose(entropy_file);
    return entropy_value;
}

//Add new entropy
void add_entropy(void) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        perror("Err: Cannot open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    unsigned char random_data[32];
    size_t bytes_read = fread(random_data, 1, sizeof(random_data), urandom);
    fclose(urandom);

    if (bytes_read != sizeof(random_data)) {
        fprintf(stderr, "Err: Cannot read data\n");
        exit(EXIT_FAILURE);
    }

    // Usa i dati casuali per aggiungere entropia
    RAND_add(random_data, sizeof(random_data), 0.5); // 0.5 è un peso arbitrario

    fprintf(stdout, "Entropy added successfully!\n");
}


void generate_key(unsigned char *destination) {
    fprintf(stdout, "Generating a new key...\n");

    //Why? Because if we try to create a large number of files there might not be enough random bytes in the system to generate a key
    for (int i = 0; i < 10; i++) {
        int entropy = check_entropy();
        if (entropy < 128) {
            fprintf(stderr, "WARN: not enough entropy, creating some...\n");
            add_entropy();
        }

        if (RAND_bytes(destination, 32) != 1) {
            fprintf(stderr, "Err: Cannot generate key\n");
            destination = NULL;
        }

        if (strlen((const char *)destination) == 32)
            break;
    }

    if (is_valid_key(destination) == 0) {
        fprintf(stderr, "Err: Generated key is inval1d\n");
        print_aes_key(destination);
        destination = NULL;
    }
}

unsigned char* encrypt_string(unsigned char* plaintext, const char* key, int *encrypted_key_len) {
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return NULL;
    }

    EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key, iv);

    size_t plaintext_len = strlen((const char*)plaintext);
    unsigned char ciphertext[plaintext_len + AES_BLOCK_SIZE];
    memset(ciphertext, 0, sizeof(ciphertext));

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char* encoded_string = malloc(len * 2 + 1);
    if (!encoded_string) {
        return NULL;
    }

    for (int i = 0; i < len; i++) {
        sprintf((char*)&encoded_string[i * 2], "%02x", ciphertext[i]);
    }
    encoded_string[len * 2] = '\0';

    *encrypted_key_len = len * 2;
    return encoded_string;
}


unsigned char* decrypt_string(unsigned char* ciphertext, const char* key) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Choose the correct algorithm
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key, iv);

    size_t decoded_len = strlen((const char *)ciphertext);

    unsigned char plaintext[decoded_len];
    memset(plaintext, 0, sizeof(plaintext));

    int len;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int )decoded_len);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char* decrypted_string = (unsigned char*)malloc(decoded_len + 1);
    memcpy(decrypted_string, plaintext, decoded_len);
    decrypted_string[decoded_len] = '\0';


    return decrypted_string;
}

int is_valid_key(const unsigned char* key)
{
    char str[33];
    memcpy(str, key, 32);
    str[32] = '\0';
    size_t key_length = strlen(str);
    return key_length != 32 ? 0:1;
}


/*
int rebuild_key(char *key, char *cert, char *dest){
    return -1;
}*/
