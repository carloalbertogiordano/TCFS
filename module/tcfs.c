#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*#ifdef linux
#define _XOPEN_SOURCE 700 // Enable pread(), pwrite(), e utimensat()
#endif

#define _XOPEN_SOURCE*/
#if __STDC_VERSION__ >= 199901L //If C99
#define _XOPEN_SOURCE 600 //Enable X/Open UNIX V6
#else
#define _XOPEN_SOURCE 500 //Enable X/Open UNIX V5
#endif // __STDC_VERSION__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <fuse.h>

#define MAX_PATHLEN 255

#define MAX_PATHLEN 255

struct tcfs_dirp
{
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

/* root of the filesystem */
char *root;

//Sanitiza path and put new path in outpath
static inline void sanitize_path(const char* path, char *outpath)
{
    if (!path) {
        outpath = root;
    }
    else {
        snprintf(outpath, MAX_PATHLEN, "%s%s", root, path);
    }
    fprintf(stdout, "DEBUG sanitize_path: (%s)\n", outpath);
}


static int tcfs_access(const char *path, int mask)
{
    fprintf(stdout, "Called access on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = access(p, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_getattr(const char *path, struct stat *stbuf)
{
    fprintf(stdout, "Called getattr on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = lstat(p, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_readlink(const char *path, char *buf, size_t size)
{
    fprintf(stdout, "Called readlink on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = readlink(p, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int tcfs_opendir(const char *path, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called opendir on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    struct tcfs_dirp *dir = (struct tcfs_dirp*) malloc(sizeof(struct tcfs_dirp));
    if (dir == NULL)
        return -ENOMEM;

    dir->dp = opendir(p);
    if (dir->dp == NULL) {
        res = -errno;
        free(dir);
        return res;
    }
    dir->offset = 0;
    dir->entry = NULL;
    fi->fh = (unsigned long) dir;
    return 0;
}

static int tcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called readdir on %s\n", path);

    struct tcfs_dirp *d = (struct tcfs_dirp*) fi->fh;

    (void) path;
    if (offset != d->offset) {
        seekdir(d->dp, offset);
        d->entry = NULL;
        d->offset = offset;
    }

    while ((d->entry = readdir(d->dp)) != NULL) {
        struct stat st;
        off_t nextoff;
        memset(&st, 0, sizeof(st));
        st.st_ino = d->entry->d_ino;
        st.st_mode = d->entry->d_type << 12;
        nextoff = telldir(d->dp);
        if (filler(buf, d->entry->d_name, &st, nextoff)) {
            break;
        }
        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int tcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called releasedir on %s\n", path);

    struct tcfs_dirp *d = (struct tcfs_dirp*) fi->fh;
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

static int tcfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    fprintf(stdout, "Called mknod on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    // This could just be 'mknod(path, mode, rdev)' but this is more portable */
    if (S_ISREG(mode)) {
        res = open(p, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(p, mode);
    else
        res = mknod(p, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_mkdir(const char *path, mode_t mode)
{
    fprintf(stdout, "Called mkdir on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = mkdir(p, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_unlink(const char *path)
{
    fprintf(stdout, "Called unlink on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = unlink(p);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_rmdir(const char *path)
{
    fprintf(stdout, "Called rmdir on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = rmdir(p);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_symlink(const char *from, const char *to)
{
    fprintf(stdout, "Called symlink from %s to %s\n", from, to);

    int res;
    char f[MAX_PATHLEN];
    char t[MAX_PATHLEN];
    sanitize_path(from, f);
    sanitize_path(to, t);

    res = symlink(f, t);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_rename(const char *from, const char *to, unsigned int flags)
{
    fprintf(stdout, "Called rename from %s to %s\n", from, to);

    int res;
    char f[MAX_PATHLEN];
    char t[MAX_PATHLEN];
    sanitize_path(from, f);
    sanitize_path(to, t);

    if (flags)
        return -EINVAL;

    res = rename(f, t);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_link(const char *from, const char *to)
{
    fprintf(stdout, "Called link from %s to %s\n", from, to);

    int res;
    char f[MAX_PATHLEN];
    char t[MAX_PATHLEN];
    sanitize_path(from, f);
    sanitize_path(to, t);

    res = link(f, t);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_chmod(const char *path, mode_t mode)
{
    fprintf(stdout, "Called chmod on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = chmod(p, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_chown(const char *path, uid_t uid, gid_t gid)
{
    fprintf(stdout, "Called chown on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = lchown(p, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_truncate(const char *path, off_t size)
{
    fprintf(stdout, "Called truncate on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = truncate(p, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_ftruncate(const char* path, off_t size, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called frtuncate on %s\n", path);

    int res;
    (void) path;
    res = ftruncate(fi->fh, size);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT //Chenge time with nanosecond precision
static int tcfs_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    // utime/utimes follow symlinks so they cannot be used
    res = utimensat(0, p, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int tcfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called create on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = open(p, fi->flags, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int tcfs_open(const char *path, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called open on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = open(p, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int tcfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called read on %s\n", path);

    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int tcfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called write on %s\n", path);

    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int tcfs_statfs(const char *path, struct statvfs *stbuf)
{
    fprintf(stdout, "Called statfs on %s\n", path);

    int res;
    char p[MAX_PATHLEN];
    sanitize_path(path, p);

    res = statvfs(p, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_flush(const char* path, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called flush on %s\n", path);

    int res;
    (void) path;

    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

static int tcfs_release(const char *path, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called release on %s\n", path);

    (void) path;
    close(fi->fh);

    return 0;
}

static int tcfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called fsync on %s\n", path);

    int res;
    (void) path;
    (void) isdatasync;

    res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE //ensures that disk space is allocated for the file referred to by the descriptor fd for the bytes in the range starting at offset and continuing for len bytes
static int tcfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    fprintf(stdout, "Called posix_fallocate on %s\n", path);

    (void) path;

    if (mode)
        return -EOPNOTSUPP;

    res = -posix_fallocate(fi->fh, offset, length);
    return res;
}
#endif

// xattr operations are necessary for TCFS
static int tcfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    fprintf(stdout, "Called setxattr on %s\n", path);

    char p[MAX_PATHLEN];
    sanitize_path(path, p);
    int res = lsetxattr(p, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int tcfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    fprintf(stdout, "Called getxattr on %s\n", path);

    char p[MAX_PATHLEN];
    sanitize_path(path, p);
    int res = lgetxattr(p, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int tcfs_listxattr(const char *path, char *list, size_t size)
{
    fprintf(stdout, "Called listxattr on %s\n", path);

    char p[MAX_PATHLEN];
    sanitize_path(path, p);
    int res = llistxattr(p, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int tcfs_removexattr(const char *path, const char *name)
{
    fprintf(stdout, "Called removexattr on %s\n", path);

    char p[MAX_PATHLEN];
    sanitize_path(path, p);
    int res = lremovexattr(p, name);
    if (res == -1)
        return -errno;
    return 0;
}

static int tcfs_flock(const char* path, struct fuse_file_info *fi, int op)
{
    fprintf(stdout, "Called flock on %s\n", path);

    int res;
    (void) path;

    res = flock(fi->fh, op);
    if (res == -1)
        return -errno;

    return 0;
}


static struct fuse_operations tcfs_oper = {
        .getattr	= tcfs_getattr,
        .access		= tcfs_access,
        .readlink	= tcfs_readlink,
        .opendir    = tcfs_opendir,
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
        .ftruncate  = tcfs_ftruncate,
        .releasedir = tcfs_releasedir,
#ifdef HAVE_UTIMENSAT
        .utimens	= tcfs_utimens,
#endif
        .create     = tcfs_create,
        .open		= tcfs_open,
        .read		= tcfs_read,
        .write		= tcfs_write,
        .statfs		= tcfs_statfs,
        .flush      = tcfs_flush,
        .release	= tcfs_release,
        .fsync		= tcfs_fsync,
#ifdef HAVE_POSIX_FALLOCATE
        .fallocate	= tcfs_fallocate,
#endif
    .setxattr	    = tcfs_setxattr,
    .getxattr	    = tcfs_getxattr,
    .listxattr      = tcfs_listxattr,
    .removexattr    = tcfs_removexattr,
    .flock          = tcfs_flock,
};


struct tcfs_otcfs_struct {
    unsigned long val;
    char * str;
} tcfs_opts;


/*
 * option parsing callback
 * return -1 indicates an error
 * return 0 accepts the parameter
 * return 1 retain the parameter to fuse
 */
int tcfs_otcfs_proc(void *data, const char* arg, int key, struct fuse_args *outargs)
{
    (void) data;
    (void) outargs;

    switch(key)
    {
        case FUSE_OPT_KEY_NONOPT:
            if (!root) {
                root = NULL;
                root = realpath(arg, root);
                return 0;
            }
            return 1;
        default: /* else pass to fuse */
            return 1;
    }
}


int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int res;

    tcfs_opts.val = 0;
    tcfs_opts.str = NULL;

    if (fuse_opt_parse(&args, &tcfs_opts, NULL, tcfs_otcfs_proc) == -1) {
        perror("error on fuse_otcfs_parse");
        exit(1);
    }
    else {
        printf("arguments to fuse_main: ");
        for (int i=0; i < args.argc; i++) {
            printf("%s ", args.argv[i]);
        }
        printf("\n");
        printf("Demo parameters in tcfs_opts: val= %lu, str=", tcfs_opts.val);
        if (tcfs_opts.str) {
            printf(" %s\n", tcfs_opts.str);
        }
        else {
            printf(" NULL\n");
        }
        if (root) {
            printf("root: %s\n", root);
        }
        else {
            printf("no root!\n");
        }
    }

    umask(0);
    res = fuse_main(args.argc, args.argv, &tcfs_oper, NULL);

    fuse_opt_free_args(&args);
    if (root) {
        free(root);
    }

    return res;
}