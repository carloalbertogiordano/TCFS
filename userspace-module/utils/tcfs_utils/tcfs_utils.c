#include "tcfs_utils.h"

void get_user_name(char *buf, size_t size)
{
    uid_t uid = geteuid();
    struct passwd *pw = getpwuid(uid);
    if (pw)
        snprintf(buf, size, "%s", pw->pw_name);
    else
        perror("Error: Could not retrieve username.\n");
}

/* is_encrypted: returns 1 if encryption succeeded, 0 otherwise. There is currently no use for this function */
int is_encrypted(const char *path)
{
    int ret;
    char xattr_val[5];
    getxattr(path, "user.tcfs", xattr_val, sizeof(char)*5);
    fprintf(stderr, "xattr set to: %s\n", xattr_val);
    ret = (strcmp(xattr_val, "true") == 0);
    return ret;
}

char *prefix_path(const char *path, const char *realpath)
{
    if (path == NULL || realpath == NULL)
    {
        perror("Err: path or realpath is NULL");
        return NULL;
    }

    size_t len = strlen(path) + strlen(realpath) + 1;
    char *root_dir = malloc(len * sizeof(char));

    if (root_dir == NULL)
    {
        perror("Err: Could not allocate memory while in prefix_path");
        return NULL;
    }

    if (strcpy(root_dir, realpath) == NULL)
    {
        perror("strcpy: Cannot copy path");
        return NULL;
    }
    if (strcat(root_dir, path) == NULL)
    {
        perror("strcat: in prefix_path cannot concatenate the paths");
        return NULL;
    }
    return root_dir;
}

/* read_file: for debugging tempfiles */
int read_file(FILE *file)
{
    int c;
    int file_contains_something = 0;
    FILE *read = file; /* don't move original file pointer */
    if (read) {
        while ((c = getc(read)) != EOF) {
            file_contains_something = 1;
            putc(c, stderr);
        }
    }
    if (!file_contains_something)
        fprintf(stderr, "file was empty\n");
    rewind(file);
    /* fseek(tmpf, offset, SEEK_END); */
    return 0;
}