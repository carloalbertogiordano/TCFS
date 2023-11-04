#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <stdlib.h>

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
