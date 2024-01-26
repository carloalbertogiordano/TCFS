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

int read_file (FILE *file);

int get_encrypted_key (char *filepath, unsigned char *encrypted_key);

void print_aes_key (unsigned char *key);

const char *get_name_from_path(const char *path);

const char *get_directory_path(const char *path);

int is_encrypted_name(const char *name);

char *string_to_hex(const char *input);

char *hex_to_string(const char *input);