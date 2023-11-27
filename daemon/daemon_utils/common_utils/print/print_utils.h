#include <systemd/sd-journal.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

void print_err(const char *format, ...);
void print_msg(const char *format, ...);
void print_warn(const char *format, ...);
void print_debug(const char *format, ...);