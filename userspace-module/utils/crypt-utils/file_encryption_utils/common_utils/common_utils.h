#ifndef TCFS_COMMON_UTILS_H
#define TCFS_COMMON_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <setjmp.h>
#include "../../../debug_utils/debug_helper.h"

extern jmp_buf jump_buffer;

extern char *
getOpenSSLError (void);
extern void
handleErrors (void);

#endif // TCFS_COMMON_UTILS_H
