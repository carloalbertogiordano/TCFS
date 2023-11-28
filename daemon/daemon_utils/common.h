#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <mqueue.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/**
 * @file common.h
 * @brief This file contains some common definitions and structs used by the daemon
 * */

/**
 * @internal
 * @def MAX_QM_SIZE
 * @brief Maximum size of a message in bytes. \_def
 * */
#define MAX_QM_SIZE 512
/**
 * @internal
 * @def MAX_QM_N
 * @brief Maximum number of messages that can be stored on a queue. \_def
 * */
#define MAX_QM_N 100

#ifndef QUEUE_STRUCTS
#define QUEUE_STRUCTS

/**
 * @enum qm_type
 * @brief Describes the type of a given message. \n
 * USER refers to qm_user struct \n
 * SHARED refers to user_operation struct \n
 * BROADCAST refers to qm_broad struct \n
 * QM_TYPE_UNDEFINED is set if there was an error and we cannot determinate the type of the struct
 * */
typedef enum qm_type{
    USER = 0, /**< Refers to type qm_user */
    SHARED = 1, /**< Refers to type qm_shared */
    BROADCAST = 2, /**< Refers to type qm_broad */
    QM_TYPE_UNDEFINED = -1, /**< This is set in case of error, it means that the structure it is referring to is invalid */
} qm_type;

/**
 * @enum user_operation
 * @brief Describes the operation that a user can perform. \n
 * REGISTER means that the user wants to register to the system. \n
 * UNREGISTER means that the user wants to unregister from the system.
 * */
typedef enum user_operation{
    REGISTER = 0, /**< User wants to register */
    UNREGISTER = 1, /**< User wants to unregister */
} user_operation;

/**
 * @struct qm_user
 * @brief Represents a user message. \n
 * Contains information about the user's operation, process ID, username and public key. \n
 * */
typedef struct qm_user {
    user_operation user_op; /**< The operation that the user wants to perform. */
    pid_t pid; /**< The process ID of the user. */
    char *user; /**< The username of the user. */
    char *pubkey; /**< The public key of the user. */
} qm_user;

/**
 * @struct qm_shared
 * @brief Represents a shared message. \n
 * Contains information about the file descriptor ti which the TCFS module wants to access,\n
 * the user list to ask for keyparts and the key part of the caller. \n
 * @todo Handle creation of shared files and not only accessing them. This mey imply a new field
 * */
typedef struct qm_shared {
    int fd; /**< The file descriptor of the shared file. */
    char **userlist; /**< The list of users who created the shared file.\n @note This is really a matrix of chars*/
    char *keypart; /**< The part of the key given by the caller that is needed to decrypt the shared file. */
} qm_shared;

/**
 * @struct qm_broad
 * @brief Represents a broadcast message.
 * Contains the data that is broadcasted to all users.
 * */
typedef struct qm_broad {
    char *data; /**< The data that is broadcasted. */
} qm_broad;

#endif
