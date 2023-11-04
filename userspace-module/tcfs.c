#define FUSE_USE_VERSION 30
#define HAVE_SETXATTR
#define ENCRYPT 1
#define DECRYPT 0

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* For pread()/pwrite() */
#if __STDC_VERSION__ >= 199901L
# define _XOPEN_SOURCE 600
#else
# define _XOPEN_SOURCE 500
#endif /* __STDC_VERSION__ */

#include <assert.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <fcntl.h>            /* Definition of AT_* constants */
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <argp.h>
#include <pwd.h>
#include "utils/tcfs_utils/tcfs_utils.h"
#include "utils/crypt-utils/crypt-utils.h"

char *root_path;
char *password;

static int tcfs_opendir(const char *fuse_path, struct fuse_file_info *fi)
{
    /*int res = 0;
    DIR *dp;
    char path[PATH_MAX];

    *path = prefix_path(fuse_path);

    dp = opendir(path);
    if (dp == NULL)
        res = -errno;

    fi->fh = (intptr_t) dp;

    return res;*/
    return 0;
}

static int tcfs_getattr(const char *fuse_path, struct stat *stbuf)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_access(const char *fuse_path, int mask)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_readlink(const char *fuse_path, char *buf, size_t size)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int tcfs_readdir(const char *fuse_path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    char *path = prefix_path(fuse_path, root_path);

    DIR *dp;
    struct dirent *de;
    fprintf(stderr, "Path: %s\n", path);

    (void) offset;
    (void) fi;

    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int tcfs_mknod(const char *fuse_path, mode_t mode, dev_t rdev)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_mkdir(const char *fuse_path, mode_t mode)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_unlink(const char *fuse_path)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_rmdir(const char *fuse_path)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_chmod(const char *fuse_path, mode_t mode)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_chown(const char *fuse_path, uid_t uid, gid_t gid)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_truncate(const char *fuse_path, off_t size)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int tcfs_utimens(const char *fuse_path, const struct timespec ts[2])
{
    char *path = prefix_path(fuse_path, root_path);

    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(path, tv);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int tcfs_open(const char *fuse_path, struct fuse_file_info *fi)
{
    char *path = prefix_path(fuse_path, root_path);
    int res;

    res = open(path, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static inline int file_size(FILE *file) {
    struct stat st;

    if (fstat(fileno(file), &st) == 0)
        return st.st_size;

    return -1;
}

static int tcfs_read(const char *fuse_path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    FILE *path_ptr, *tmpf;
    char *path;
    int res, action;

    //Retrieve the username
    char username_buf[1024];
    size_t username_buf_size = 1024;
    get_user_name(username_buf, username_buf_size);

    path = prefix_path(fuse_path, root_path);
    path_ptr = fopen(path, "r");
    tmpf = tmpfile();

    /* Either encrypt, or just move along. */
    action = DECRYPT;
    if (do_crypt(path_ptr, tmpf, action, password) == 0)
        return -errno;

    /* Something went terribly wrong if this is the case. */
    if (path_ptr == NULL || tmpf == NULL)
        return -errno;

    fflush(tmpf);
    fseek(tmpf, offset, SEEK_SET);

    /* Read our tmpfile into the buffer. */
    res = fread(buf, 1, file_size(tmpf), tmpf);
    if (res == -1)
        res = -errno;

    fclose(tmpf);
    fclose(path_ptr);

    return res;
}

static int tcfs_write(const char *fuse_path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Called write\n");

    FILE *path_ptr, *tmpf;
    char *path;
    int res, action;
    int tmpf_descriptor;

    //Retrieve the username
    char username_buf[1024];
    size_t username_buf_size = 1024;
    get_user_name(username_buf, username_buf_size);

    path = prefix_path(fuse_path, root_path);
    path_ptr = fopen(path, "r+");
    tmpf = tmpfile();
    tmpf_descriptor = fileno(tmpf);

    printf("TMP files created\n");

    /* Something went terribly wrong if this is the case. */
    if (path_ptr == NULL || tmpf == NULL) {
        fprintf(stderr, "Something went terrybly wrong, cannot create new files\n");
        return -errno;
    }

    /* if the file to write to exists, read it into the tempfile */
    if (tcfs_access(fuse_path, R_OK) == 0 && file_size(path_ptr) > 0) {
        action = DECRYPT;
        printf("CRYPT\n");
        if (do_crypt(path_ptr, tmpf, action, password) == 0) {
            perror("do_crypt: Cannot cypher file\n");
            return --errno;
        }

        rewind(path_ptr);
        rewind(tmpf);
        printf("Rewind OK\n");
    }

    /* Read our tmpfile into the buffer. */
    res = pwrite(tmpf_descriptor, buf, size, offset);
    printf("tmpfile read into buffer\n");
    if (res == -1){
        printf("%d\n", res);
        perror("pwrite: cannot read tmpfile into the buffer\n");
        res = -errno;
    }

    /* Either encrypt, or just move along. */
    action = ENCRYPT;

    printf("Calling do crypt 2\n");
    if (do_crypt(tmpf, path_ptr, action, password) == 0) {
        perror("do_crypt 2: cannot cypher file\n");
        return -errno;
    }
    printf("do_crypt ok\n");

    fclose(tmpf);
    fclose(path_ptr);
    printf("All ok, files closed\n");

    return res;
}

static int tcfs_statfs(const char *fuse_path, struct statvfs *stbuf)
{
    char *path = prefix_path(fuse_path, root_path);

    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_setxattr(const char *fuse_path, const char *name, const char *value, size_t size, int flags)
{
    char *path = prefix_path(fuse_path, root_path);
    int res = 1;
    printf("called tcfs_setxattr %s %s %s %lu %d\n", fuse_path, name, value, size, flags);
    if ((res = lsetxattr(path, name, value, size, flags)) == -1)
        perror("tcfs_lsetxattr");
    if (res == -1)
        return -errno;
    return 0;
}

static int tcfs_create(const char* fuse_path, mode_t mode, struct fuse_file_info* fi)
{
    (void) fi;
    (void) mode;

    FILE *res;
    res = fopen(prefix_path(fuse_path, root_path), "w");
    if(res == NULL)
        return -errno;

    if(fsetxattr(fileno(res), "user.encrypted", "true", 4, 0) != 0){
        fclose(res);
        return -errno;
    }
    fclose(res);

    return 0;
}


static int tcfs_release(const char *fuse_path, struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */
    char *path = prefix_path(fuse_path, root_path);

    (void) path;
    (void) fi;
    return 0;
}

static int tcfs_fsync(const char *fuse_path, int isdatasync,
                     struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */
    char *path = prefix_path(fuse_path, root_path);

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

static int tcfs_getxattr(const char *fuse_path, const char *name, char *value,
                        size_t size)
{
    char *path = prefix_path(fuse_path, root_path);

    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int tcfs_listxattr(const char *fuse_path, char *list, size_t size)
{
    char *path = prefix_path(fuse_path, root_path);

    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int tcfs_removexattr(const char *fuse_path, const char *name)
{
    char *path = prefix_path(fuse_path, root_path);

    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}

static struct fuse_operations tcfs_oper = {
        .opendir        = tcfs_opendir,
        .getattr	= tcfs_getattr,
        .access		= tcfs_access,
        .readlink	= tcfs_readlink,
        .readdir	= tcfs_readdir,
        .mknod		= tcfs_mknod,
        .mkdir		= tcfs_mkdir,
        .symlink	= tcfs_symlink,
        .unlink		= tcfs_unlink,
        .rmdir		= tcfs_rmdir,
        .rename		= tcfs_rename,
        .link		= tcfs_link,
        .chmod		= tcfs_chmod,
        .chown		= tcfs_chown,
        .truncate	= tcfs_truncate,
        #ifdef HAVE_UTIMENSAT
        .utimens	= tcfs_utimens,
        #endif
        .open		= tcfs_open,
        .read		= tcfs_read,
        .write		= tcfs_write,
        .statfs		= tcfs_statfs,
        .create		= tcfs_create,
        .release	= tcfs_release,
        .fsync		= tcfs_fsync,
        .setxattr	= tcfs_setxattr,
        .getxattr	= tcfs_getxattr,
        .listxattr	= tcfs_listxattr,
        .removexattr	= tcfs_removexattr,
};

const char *argp_program_version = "TCFS Alpha";
const char *argp_program_bug_address = "carloalbertogiordano@duck.com";

static char doc[] = "This is an implementation on TCFS\ntcfs -s <source_path> -d <dest_path> -p <password> [fuse arguments]";

static char args_doc[] = "";

static struct argp_option options[] = {
        {"source", 's', "SOURCE", 0, "Source file path", -1},
        {"destination", 'd', "DESTINATION", 0, "Destination file path", -1},
        {"password", 'p', "PASSWORD", 0, "Password", -1},
        {NULL}
};

struct arguments {
    char *source;
    char *destination;
    char *password;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 's':
            arguments->source = arg;
            break;
        case 'd':
            arguments->destination = arg;
            break;
        case 'p':
            arguments->password = arg;
            break;
        case ARGP_KEY_ARG:
            return ARGP_ERR_UNKNOWN;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, NULL, NULL};

int main(int argc, char *argv[])
{
    umask(0);

    struct arguments arguments;

    arguments.source = NULL;
    arguments.destination = NULL;
    arguments.password = NULL;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (arguments.source == NULL || arguments.destination == NULL || arguments.password == NULL) {
        printf("Err: You need to specify at least 3 arguments\n");
        return -1;
    }

    printf("Source: %s\n", arguments.source);
    printf("Destination: %s\n", arguments.destination);

    root_path = arguments.source;

    struct fuse_args args_fuse = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args_fuse, "./tcfs");
    fuse_opt_add_arg(&args_fuse, arguments.destination);
    fuse_opt_add_arg(&args_fuse, "-f"); //TODO: this is forced for now, but will be passed via options in the future

    //Print what we are passing to fuse TODO: This will be removed
    for (int i=0; i < args_fuse.argc; i++) {
        printf("%s ", args_fuse.argv[i]);
    }
    printf("\n");

    //Get username
    char buf[1024];
    size_t buf_size = 1024;
    get_user_name(buf, buf_size);

    password = arguments.password;

    return fuse_main(args_fuse.argc, args_fuse.argv, &tcfs_oper, NULL);
}
