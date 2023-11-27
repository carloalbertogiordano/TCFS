DESTDIR = ../build/tcfs_daemon
UTILS_DIR = daemon_utils
CC = g++
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lz -ldl -lsystemd -lpthread -lc -lhiredis #-ljson

# Define the path where you want to install the daemon
INSTALL_PATH = /usr/local/bin

# Daemon configuration
DESCRIPTION = "TCFS Daemon"
EXEC_PATH := ${INSTALL_PATH}/tcfs_daemon
RESTART = "always"
WANTED_BY = "multi-user.target"
SERVICE_PATH = "/etc/systemd/system/tcfs.service"

.PHONY : tcfs_daemon tcfs_daemon_tools print_utils json_tools queue message_handler user_db

all: tcfs_daemon tcfs_daemon_tools print_utils json_tools queue message_handler user_db
	$(CC) $(CFLAGS) ${DESTDIR}/tcfs_daemon.o ${DESTDIR}/tcfs_daemon_tools.o ${DESTDIR}/queue.o ${DESTDIR}/print_utils.o ${DESTDIR}/message_handler.o ${DESTDIR}/json_tools.o ${DESTDIR}/user_db.o -o ${DESTDIR}/tcfs_daemon $(LDFLAGS)

tcfs_daemon:
	$(CC) -c tcfs_daemon.c -o ${DESTDIR}/tcfs_daemon.o

tcfs_daemon_tools:
	$(CC) -c ${UTILS_DIR}/daemon_tools/tcfs_daemon_tools.c -o ${DESTDIR}/tcfs_daemon_tools.o

print_utils:
	$(CC) -c ${UTILS_DIR}/common_utils/print/print_utils.c -o ${DESTDIR}/print_utils.o

json_tools:
	$(CC) -c ${UTILS_DIR}/common_utils/json/json_tools.cpp -o ${DESTDIR}/json_tools.o

queue:
	$(CC) -c ${UTILS_DIR}/queue/queue.c -o ${DESTDIR}/queue.o

message_handler:
	$(CC) -c ${UTILS_DIR}/message_handler/message_handler.c -o ${DESTDIR}/message_handler.o

user_db:
	$(CC) -c ${UTILS_DIR}/common_utils/db/user_db.c -o ${DESTDIR}/user_db.o

# Install the daemon and tcfs.service
install:
	./service_generator.sh ${DESCRIPTION} ${EXEC_PATH} ${RESTART} ${WANTED_BY} > ${DESTDIR}/tcfs.service
	sudo cp ${DESTDIR}/tcfs.service ${SERVICE_PATH}
	sudo cp ${DESTDIR}/tcfs_daemon $(INSTALL_PATH)
	sudo chmod +x $(INSTALL_PATH)/tcfs_daemon
	sudo systemctl daemon-reload
	sudo systemctl start tcfs.service

clean:
	rm -f ${DESTDIR}/*

unload_daemon:
	sudo systemctl disable tcfs.service
	sudo systemctl stop tcfs.service
	sudo systemctl daemon-reload
	sudo rm ${SERVICE_PATH}

