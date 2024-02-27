DESTDIR = $(realpath ../build/fuse-module)
UTILS_DIR = utils
CC = gcc
CFLAGS = -Wall -Wno-unknown-pragmas -Wextra -std=c11 -pedantic -D_FILE_OFFSET_BITS=64 -D_DEFAULT_SOURCE
LDFLAGS = -lfuse3 -lz -ldl -lyaml -lkeyutils -lssl -lcrypto

.PHONY : all crypt_utils tcfs_utils yaml_loader debug_helper tcfs

all : crypt_utils tcfs_utils yaml_loader debug_helper key_utils tcfs
	$(CC) $(CFLAGS) ${DESTDIR}/tcfs_utils.o ${DESTDIR}/yaml_loader.o ${DESTDIR}/debug_helper.o ${DESTDIR}/key_utils.o ${DESTDIR}/tcfs.o -o ${DESTDIR}/tcfs  $(LDFLAGS) ${DESTDIR}/crypt_utils_lib.a

crypt_utils :
	make clean -C $(UTILS_DIR)/crypt-utils CRYPT_UTILS_OBJDIR=$(DESTDIR)
	make -C $(UTILS_DIR)/crypt-utils CRYPT_UTILS_OBJDIR=$(DESTDIR)

tcfs_utils :
	$(CC) -c $(UTILS_DIR)/tcfs_utils/tcfs_utils.c -o ${DESTDIR}/tcfs_utils.o

yaml_loader :
	$(CC) -c $(UTILS_DIR)/config_utils/yaml_loader.c -o ${DESTDIR}/yaml_loader.o

debug_helper :
	$(CC) -c $(UTILS_DIR)/debug_utils/debug_helper.c -o ${DESTDIR}/debug_helper.o

key_utils :
	$(CC) -c $(UTILS_DIR)/key_utils/key_utils.c -o ${DESTDIR}/key_utils.o

tcfs:
	$(CC) $(CFLAGS) -c tcfs.c -o ${DESTDIR}/tcfs.o

clean:
	rm -r ${DESTDIR}/*
