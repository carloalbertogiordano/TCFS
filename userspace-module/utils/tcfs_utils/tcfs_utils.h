#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <errno.h>

/* void get_user_name(char *buf, size_t size)
 * Purpose: Fetch the username of the current user
 * Args: char *buf      : The username will be written to this buffer
 *       size_t size    : The size of the buffer;
 * Return: Nothing
 */
void get_user_name(char *buf, size_t size);

/* is_encrypted: returns 1 if encryption succeeded, 0 otherwise. There is currently no use for this function */
int is_encrypted(const char *path);

/* char *prefix_path(const char *path))
 * Purpose: Prefix the realpath to the fuse path
 * Args: char *path      : The fuse path
 *       char *realpath  : The realpath
 * Return: NULL on error, char* on success
 */
char *prefix_path(const char *path, const char *realpath);

/* read_file: for debugging tempfiles */
int read_file(FILE *file);

/* int get_encrypted_key(char *filepath, void *encrypted_key)
 * Purpose: Get the encrypted file key from its xattrs
 * Args: char *filepath      : The full-path of the file
 *       char *encrypted_key  : The buffer to save the encrypted key to
 * Return: 0 on error, 1 on success
 */
int get_encrypted_key(char *filepath, unsigned char *encrypted_key);

/*For debugging only*/
void print_aes_key(unsigned char *key);