/**
* @file tcfs_utils.h
* @brief Header file containing utility functions used by TCFS (Transparent Cryptographic Filesystem)
* @see tcfs_utils.c
*/

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

void get_user_name (char *buf, size_t size);

int is_encrypted (const char *path);

char *prefix_path (const char *path, const char *realpath);

void print_aes_key (unsigned char *key);

char *string_to_hex(const char *input);

char *hex_to_string(const char *input);