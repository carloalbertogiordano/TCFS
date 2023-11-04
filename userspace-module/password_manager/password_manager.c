#include "password_manager.h"
#include <stdio.h>
#include <string.h>
#include "hashmap/hashmap.h"

// hashmap is an open addressed hash map using robinhood hashing.
struct hashmap {
    void *(*malloc)(size_t);
    void *(*realloc)(void *, size_t);
    void (*free)(void *);
    size_t elsize;
    size_t cap;
    uint64_t seed0;
    uint64_t seed1;
    uint64_t (*hash)(const void *item, uint64_t seed0, uint64_t seed1);
    int (*compare)(const void *a, const void *b, void *udata);
    void (*elfree)(void *item);
    void *udata;
    size_t bucketsz;
    size_t nbuckets;
    size_t count;
    size_t mask;
    size_t growat;
    size_t shrinkat;
    uint8_t growpower;
    bool oom;
    void *buckets;
    void *spare;
    void *edata;
};

struct user {
    char *id;
    char *pass;
};

int user_compare(const void *a, const void *b, void *udata) {
    const struct user *ua = a;
    const struct user *ub = b;
    return strcmp(ua->id, ub->id);
}

bool user_iter(const void *item, void *udata) {
    const struct user *user = item;
    printf("%s (pass=%s)\n", user->id, user->pass);
    return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct user *user = item;
    return hashmap_sip(user->id, strlen(user->id), seed0, seed1);
}

/*Create a new hashmap, if there is an error 1 is returned otherwise 0 is returned*/
int init_hashmap(hashmap **map){
    // create a new hash map where each item is a `struct user`. The second
    // argument is the initial capacity. The third and fourth arguments are
    // optional seeds that are passed to the following hash function.
     *map = hashmap_new(sizeof(struct user), 0, 0, 0, user_hash, user_compare, NULL, NULL);

    return map==NULL ? 0:1;
}

/*Free the hashmap*/
void free_hashmap(hashmap **map){
    hashmap_free(*map);
}

/*Inserts or replaces an item in the hash map. If an item is
replaced then it is returned 1 otherwise 0 is returned. This operation
may allocate memory. If the system is unable to allocate additional
memory then NULL is returned and hashmap_oom() returns true.*/
int add_user(hashmap **map, char *id_user, char *pass_user){
    return hashmap_set(*map, &(struct user){ .id=id_user, .pass=pass_user }) == NULL ? 0:1;
}

/*Check if a user is present in the hashmap. Returns 0 if user is found, else returns 1*/
int is_user_logged(hashmap **map, char *id_user){
    char *user =(char *) hashmap_get(*map, &(struct user){ .id=id_user });
    return user==NULL ? 0:1;
}

/*Remove a user from the hashmap. If an error occurs 1 is returned otherwise 0 is returned*/
int remove_user(hashmap **map, char *id_user){
    struct user *u = (struct user *) hashmap_delete(*map, &(struct user){.id=id_user});
    return u==NULL ? 0:1;
}

/*Fetch the password of the specified */
char *get_user_pass(hashmap **map, char *id_user){
    if(is_user_logged(map, id_user)){
        struct user *u =(struct user *) hashmap_get(*map, &(struct user){ .id=id_user });
        return u->pass;
    }
    return NULL;
}