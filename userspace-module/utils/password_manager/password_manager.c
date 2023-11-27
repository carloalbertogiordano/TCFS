//TODO: This util will handle requesting keys to kernel

#include "password_manager.h"
#include "../crypt-utils/crypt-utils.h"
/*
char *true_key;

int insert_key(char* key, char* cert, int is_sys_call)
{
    if (is_sys_call == WITH_SYS_CALL)
    {
        fprintf(stderr, "The kernal module has not been implemented yet, saving key in userspace\n \
                        This will change in the future");
        insert_key(key, cert, WITHOUT_SYS_CALL);
    }
    return rebuild_key(key, cert, true_key);
}

char *request_key(int is_sys_call){
    return NULL;
}
int delete_key(int is_sys_call){
    return -1;
}*/