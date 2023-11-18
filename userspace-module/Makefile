DESTDIR = ../build/fuse-module
UTILS_DIR = utils
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -pedantic -D_FILE_OFFSET_BITS=64
LDFLAGS = -lfuse -lssl -lcrypto -lz -ldl

.PHONY : all password_manager crypt_utils tcfs_utils tcfs

all : password_manager crypt_utils tcfs_utils tcfs
	$(CC) $(CFLAGS) ${DESTDIR}/password_manager.o ${DESTDIR}/crypt_utils.o ${DESTDIR}/tcfs_utils.o ${DESTDIR}/tcfs.o -o ${DESTDIR}/tcfs  $(LDFLAGS)

password_manager :
	$(CC) -c $(UTILS_DIR)/password_manager/password_manager.c -o ${DESTDIR}/password_manager.o

crypt_utils :
	$(CC) $(CFLAGS) -c $(UTILS_DIR)/crypt-utils/crypt-utils.c -o ${DESTDIR}/crypt_utils.o

tcfs_utils :
	$(CC) -c $(UTILS_DIR)/tcfs_utils/tcfs_utils.c -o ${DESTDIR}/tcfs_utils.o

tcfs:
	$(CC) $(CFLAGS) -c tcfs.c -o ${DESTDIR}/tcfs.o

clean:
	rm -r ${DESTDIR}/*
