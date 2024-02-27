#include "../common_utils/common_utils.h"

extern int
encrypt_file_gcm (FILE *fp, unsigned char *plaintext, int plaintext_len,
                  unsigned char *key, unsigned char *iv);

extern int
decrypt_file_gcm (FILE *fp, unsigned char *key, unsigned char *iv,
                  unsigned char **plaintext, off_t offset);