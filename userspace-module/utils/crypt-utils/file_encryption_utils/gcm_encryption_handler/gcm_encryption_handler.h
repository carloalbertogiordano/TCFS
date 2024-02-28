#include "../common_utils/common_utils.h"

extern int encrypt_file_gcm (FILE *fp, unsigned char *plaintext,
                             size_t plaintext_len, unsigned char *key,
                             unsigned char *iv, off_t offset);

extern int decrypt_file_gcm (FILE *fp, unsigned char *key, unsigned char *iv,
                             unsigned char **plaintext, size_t bytes_to_read,
                             off_t offset);
