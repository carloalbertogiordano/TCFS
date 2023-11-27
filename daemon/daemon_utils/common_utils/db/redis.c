/**
 * @internal \_file
 * @file redis.c
 * @brief All the function in this file should not be used directly, instead use the function defined by user_db
 * @see \\ref user_db.c
 * */

#include "redis.h"
#include "../print/print_utils.h"
#include "../json/json_tools.h"
#include <hiredis/hiredis.h>

/**
 * @internal \_var
 * @def HOST
 * @brief The host address of the redis DB
 * @todo This should be passed as a parameter to the daemon
 * */
const char HOST[] = "127.0.0.1";
/**
 * @internal \_def
 * @def PORT
 * @brief The port of the redis DB
 * @todo This should be passed as a parameter to the daemon
 * */
#define PORT 6380

/**
 * @internal \_var
 * @var redisContext *context
 * @brief Pointer to the context of Redis DB
 * */
redisContext *context;

/**
 * @internal \_func
 * @brief For debugging only. Prints all the keys in the database
 * @return void
 * */
void print_all_keys() {
    redisReply *keys_reply = (redisReply *)redisCommand(context, "KEYS *");
    if (keys_reply) {
        if (keys_reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < keys_reply->elements; ++i) {
                print_msg("\tKey: %s", keys_reply->element[i]->str);
            }
        } else {
            print_msg("Error retrieving keys: %s", keys_reply->str);
        }
        freeReplyObject(keys_reply);
    } else {
        print_msg("Error executing KEYS command");
    }
}
/**
 * @internal \_func
 * @brief initialize the context for the Redis DB
 * @return 1 if initialization was successful or the database was already initialized, 0 on failure
 * */
int init_context()
{
    //Do not reinit the context
    if (context != NULL)
        return 1;

    context = redisConnect(HOST, PORT);
    if (context->err) {
        print_err("Connection error: %s", context->errstr);
        return 0;
    }
    return 1;
}
/**
 * @internal \_func
 * @brief Free the hiredis context variable
 * @return void
 * */
void free_context()
{
    redisFree(context);
}
/**
 * @internal \_func
 * @brief Internal function to simplify the casting of a json to a qm_user struct
 * @param char *json    the json string representing the qm_user struct
 * @return \p_qmu
 * */
qm_user *json_to_qm_user(char *json)
{
    print_msg("DEBUG: Converting %s", json);
    qm_type type;
    //Redis return the value as json:{actual json} so we need to eliminate the json: from the string
    char *res = strchr(json, ':');
    res++; //Skip the : char
    qm_user *user = (qm_user *)string_to_struct(res, &type);
    return user;
}
/**
 * @internal \_func
 * @brief Fetch the user on the DB with key pid
 * @param pid_t pid     The key of the row
 * @return \p_qmu
 * */
qm_user *get_user_by_pid(pid_t pid) {
    qm_user *user = NULL;
    // Retrieve the JSON data from Redis hash
    print_msg("EXECUTING \"GET pid:%d\"", pid);
    redisReply *luaReply = (redisReply *)redisCommand(context, "GET pid:%d", pid);
    if (luaReply) {
        if (luaReply->type == REDIS_REPLY_STRING) {
            user = json_to_qm_user(luaReply->str);
            if (user) {
                print_msg("Successful retrieval! PID: %d, User: %s", user->pid, user->user);
            } else {
                print_err("Error converting JSON to struct");
            }
        } else {
            print_err("Reply type error %d -> executing HGET\n\tErrString: %s",
                      luaReply->type, luaReply->str,context->errstr);
        }
        freeReplyObject(luaReply);
    } else {
        print_err("Reply error executing HGET\n\tErrString: %s", context->errstr);
    }
    return user;
}
/**
* @internal \_func
* @brief Fetch the user on the DB with key name
* @param const char *name     The key of the row
* @return \p_qmu
* */
qm_user *get_user_by_name(const char *name) {
    qm_user *user = NULL;
    // Retrieve the JSON data from Redis hash
    print_msg("EXECUTING \"GET name:%d\"", name);
    redisReply *luaReply = (redisReply *)redisCommand(context, "GET name:%d", name);
    if (luaReply) {
        if (luaReply->type == REDIS_REPLY_STRING) {
            user = json_to_qm_user(luaReply->str);
            if (user) {
                print_msg("Successful retrieval! PID: %d, User: %s", user->pid, user->user);
            } else {
                print_err("Error converting JSON to struct");
            }
        } else {
            print_err("Reply type error %d -> executing HGET\n\tErrString: %s",
                      luaReply->type, luaReply->str,context->errstr);
        }
        freeReplyObject(luaReply);
    } else {
        print_err("Reply error executing HGET\n\tErrString: %s", context->errstr);
    }
    return user;
}
/**
 * @internal \_func
 * @brief Insert a new user in the DB.
 * @param \p_qmu
 * @return \ret
 * @note The user will be set 2 times, once with key user->pid and once with key user->name
 * @note If an error is thrown it will be printed by print_err() function
 * */
int insert(qm_user *user)
{
    // Convert the structure to JSON
    const char *json = struct_to_json(USER, user);
    if (!json)
    {
        print_err("Error converting qm_user to JSON");
        return 0;
    }
    // Save to Redis with key "pid_str"
    print_msg("\tDB: \"SET pid:%d json:%s\"", user->pid, json);
    redisReply *reply_pid =(redisReply *) redisCommand(context, "SET pid:%d json:%s", user->pid, json);
    if (!reply_pid)
    {
        print_err("Error saving to Redis (pid)");
        free((void *)json);
        return 0;
    }
    freeReplyObject(reply_pid);

    // Save to Redis with key "user"
    redisReply *reply_user =(redisReply *) redisCommand(context, "SET user:%s json:%s", user->user, json);
    if (!reply_user)
    {
        print_err("Error saving to Redis (user)");
        free((void *)json);
        return 0;
    }
    freeReplyObject(reply_user);
    // Free the allocated JSON memory
    free((void *)json); //Discard qualifier
    return 1;
}
/**
 * @internal \_func
 * @brief Remove a user from the DB using the PID as key
 * @param pid_t pid     The key
 * @return \ret
 * @note Will also remove the corresponding entry by name.
 * @note If an error is thrown it will be printed using the print_err() function
 * */
int remove_by_pid(pid_t pid)
{
    qm_user *user_tmp = get_user_by_pid(pid);
    // Remove the structure by PID
    print_msg("\tDB: \"DEL pid:%d\"", pid);
    redisReply *reply_pid =(redisReply *) redisCommand(context, "DEL pid:%d", pid);
    if (!reply_pid) {
        print_err("Error removing structure by PID");
        return 0;
    }
    freeReplyObject(reply_pid);
    // Also remove the corresponding key by name
    print_msg("\tDB: \"DEL user:%s\"", user_tmp->user);
    redisReply *reply_name =(redisReply *) redisCommand(context, "DEL user:%s", user_tmp->user);
    if (!reply_name) {
        print_err("Error removing key by name");
        return 0;
    }
    free(user_tmp);
    freeReplyObject(reply_name);
    return 1;
}
/**
 * @internal \_func
 * @brief Remove a user from the DB using the name as key
 * @param char *name     The key
 * @return \ret
 * @note Will also remove the corresponding entry by PID
 * @note If an error is thrown it will be printed using the print_err() function
 * */
int remove_by_user(char *name)
{
    qm_user *user_tmp = get_user_by_name(name);
    // Remove the structure by name
    char key_name[64]; // Adjust the size as needed
    snprintf(key_name, sizeof(key_name), "user:%s", name);
    redisReply *reply_name =(redisReply *) redisCommand(context, "DEL %s", key_name);
    if (!reply_name) {
        print_err("Error removing structure by name");
        return 0;
    }
    freeReplyObject(reply_name);
    // Also remove the corresponding key by PID
    redisReply *reply_pid =(redisReply *) redisCommand(context, "DEL %d", user_tmp->pid);
    if (!reply_pid) {
        print_err("Error removing key by PID");
        return 0;
    }
    freeReplyObject(reply_pid);
    return 1;
}