#include "../common_utils/common_utils.h"

#ifndef TCFS_CTR_ENCRYPTION_HANDLER_H
#define TCFS_CTR_ENCRYPTION_HANDLER_H

extern int encrypt_file_aes_ctr (FILE *fp, unsigned char *plaintext,
                                 int plaintext_len, unsigned char *key,
                                 unsigned char *iv);

extern int
decrypt_file_aes_ctr (FILE *fp, unsigned char **plaintext, unsigned char *key,
                      unsigned char *iv);

#endif // TCFS_CTR_ENCRYPTION_HANDLER_H
