#ifndef TCFS_KEY_UTILS_H
#define TCFS_KEY_UTILS_H

void free_key (const char *key);
char *get_key (void );
extern bool set_key_id (const char *value);
#endif // TCFS_KEY_UTILS_H
