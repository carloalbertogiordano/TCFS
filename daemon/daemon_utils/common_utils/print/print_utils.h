#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <systemd/sd-journal.h>

void print_err (const char *format, ...);
void print_msg (const char *format, ...);
void print_warn (const char *format, ...);
void print_debug (const char *format, ...);