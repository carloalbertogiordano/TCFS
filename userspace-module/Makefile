DESTDIR = ../build/fuse-module
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -pedantic -D_FILE_OFFSET_BITS=64
LDFLAGS = -lfuse -lssl -lcrypto -lz -ldl

.PHONY : all password_manager

all : fuse-tcfs

fuse-tcfs : password_manager crypt_utils tcfs
	$(CC) $(CFLAGS) ${DESTDIR}/password_manager.o ${DESTDIR}/crypt_utils.o ${DESTDIR}/tcfs.o -o ${DESTDIR}/tcfs  $(LDFLAGS)

password_manager :
	$(CC) -c password_manager/password_manager.c -o ${DESTDIR}/password_manager.o

crypt_utils :
	$(CC) $(CFLAGS) -c crypt-utils/crypt-utils.c -o ${DESTDIR}/crypt_utils.o

tcfs:
	$(CC) $(CFLAGS) -c tcfs.c -o ${DESTDIR}/tcfs.o

clean:
	rm -r ${DESTDIR}/*
