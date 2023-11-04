#include <sys/types.h>

typedef struct hashmap hashmap;

char *get_user_pass(hashmap **map, char *id_user);
int remove_user(hashmap **map, char *id_user);
int is_user_logged(hashmap **map, char *id_user);
int add_user(hashmap **map, char *id_user, char *pass_user);
void free_hashmap(hashmap **map);
int init_hashmap(hashmap **map);