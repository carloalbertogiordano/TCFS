#include "daemon_utils/daemon_tools/tcfs_daemon_tools.h"

/**
 * @file tcfs_daemon.c
 * @brief This is the core of the daemon
 * @note Forking is disable at the moment, this meas it will run as a "normal" program
 * @note the main function spawns a thread to handle incoming messages on the queue
 * @todo: Enable forking
 * @todo Run the daemon via SystemD
 * */

/**
 * @var terminate
 * @brief If the spawned threads terminate abruptly they should set this to 1, so that the daemon can terminate
 * @todo: Implement logic to make this work
 * */
volatile int terminate = 0;
/**
 * @var terminate_mutex
 * @brief Mutex needed to set the var terminate to 1 safely
 * @todo: implement logic to make this work
 * */
pthread_mutex_t terminate_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @var MQUEUE
 * @brief the queue file location
 * */
const char MQUEUE[] = "/tcfs_queue";

/**
 * @brief Handle the termination if SIGTERM is received
 * @param int signum        Integer corresponding to SIGNUM
 * @todo: Implement remove_queue() to clear and delete the queue
 * */
void handle_termination(int signum) {
    print_msg("TCFS TERMINATED.\n");
    //remove_empty_queue(queue_id);
    exit(0);
}

/**
 * @brief main function of the daemon. This will daemonize the program, spawn a thread to handle messages and handle unexpected termination of the thread
 * @todo: The brief description is basically false advertisement. It only spawn a thread and hangs infinitely
 * @todo: Remove the thread that spawns handle_outgoing_messages. This must not make it into final release
 * */
int main() {
    signal(SIGTERM, handle_termination);

    print_msg("TCFS daemon is starting");

    /*pid_t pid;

    // Fork off the parent process
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // On success: The child process becomes session leader
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    // Catch, ignore and handle signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // Set new file permissions
    umask(0);

    // Change the working directory to the root directory
    // or another appropriated directory
    chdir("/");

    // Close all open file descriptors
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }*/

    pthread_t thread1, thread2;

    mqd_t queue_id = init_queue((char *)MQUEUE);
    printf("TEST %d", (int)queue_id);
    if (queue_id == 0)
    {
        print_err("Cannot open message queue in %s", (char *)MQUEUE);
        unlink(MQUEUE);
        return -errno;
    }

    if (pthread_create(&thread1, NULL, handle_incoming_messages, &queue_id) != 0) {
        print_err("Failed to create thread1");
        mq_close(queue_id);
        unlink(MQUEUE);
        return -errno;
    }

    if (pthread_create(&thread2, NULL, handle_outgoing_messages, &queue_id) != 0) {
        print_err("Failed to create thread1");
        mq_close(queue_id);
        unlink(MQUEUE);
        return -errno;
    }

    while (!terminate) {}

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    mq_close(queue_id);
    unlink(MQUEUE);


    print_err("TCFS daemon threads returned, this should have never happened");

    return -1;
}