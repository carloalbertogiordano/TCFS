DESTDIR = ../build/tcfs_helper
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lm -lcrypt

all: user-tcfs tcfs_helper_tools
	$(CC) $(CFLAGS) ${DESTDIR}/user_tcfs.o ${DESTDIR}/tcfs_helper_tools.o -o ${DESTDIR}/tcfs_helper ${LDFLAGS}

user-tcfs:
	$(CC) $(CFLAGS) -c user_tcfs.c -o ${DESTDIR}/user_tcfs.o

tcfs_helper_tools:
	$(CC) $(CFLAGS) -c tcfs_helper_tools.c -o ${DESTDIR}/tcfs_helper_tools.o

clean:
	rm ${DESTDIR}/*
