#include "../../common.h"

void print_all_keys ();

int init_context ();

qm_user *json_to_qm_user (char *json);

qm_user *get_user_by_pid (pid_t pid);

qm_user *get_user_by_name (const char *name);

int insert (qm_user *user);

int remove_by_pid (pid_t pid);

int remove_by_user (char *name);

void free_context ();