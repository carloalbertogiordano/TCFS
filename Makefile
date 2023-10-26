DESTDIR = build-fs
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -pedantic -D_FILE_OFFSET_BITS=64
LDFLAGS = -lfuse -lssl -lcrypto -lz -ldl

all : fuse-tcfs

fuse-tcfs : hashmap password_manager crypt_utils tcfs
	$(CC) $(CFLAGS) ${DESTDIR}/hashmap.o ${DESTDIR}/password_manager.o ${DESTDIR}/crypt_utils.o ${DESTDIR}/tcfs.o -o ${DESTDIR}/tcfs  $(LDFLAGS)

hashmap :
	$(CC) -c module/password_manager/hashmap/hashmap.c -o ${DESTDIR}/hashmap.o

password_manager :
	$(CC) -c module/password_manager/password_manager.c -o ${DESTDIR}/password_manager.o

crypt_utils :
	$(CC) $(CFLAGS) -c module/crypt-utils/crypt-utils.c -o ${DESTDIR}/crypt_utils.o

tcfs:
	$(CC) $(CFLAGS) -c module/tcfs.c -o ${DESTDIR}/tcfs.o

clean:
	rm -r ${DESTDIR}/*
