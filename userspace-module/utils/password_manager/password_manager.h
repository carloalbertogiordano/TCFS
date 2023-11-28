#include <stddef.h>
#include <stdio.h>

/**
 * @internal
 * @def WITH_SYS_CALL \_def
 * @brief the system aims to be independent from the kernel module. The kernel
 * module is not beeing developed so this is useless
 * */
#define WITH_SYS_CALL 1
/**
 * @internal
 * @def WITHOUT_SYS_CALL \_def
 * @brief the system aims to be independent from the kernel module. The kernel
 * module is not beeing developed so this is useless
 * */
#define WITHOUT_SYS_CALL 0
/*
int insert_key(char* key, char* cert, int is_sys_call);
char *request_key(int is_sys_call);
int delete_key(int is_sys_call);*/