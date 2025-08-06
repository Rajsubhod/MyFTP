#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <pthread.h>
#include <openssl/err.h>

#include "parser.h"

#define MAX_USERNAME_LEN 32
#define MAX_PATH_LEN 256

#define GRACEFUL_SHUTDOWN_TIMEOUT_S 10

typedef enum {
    FTP_TYPE_ASCII,
    FTP_TYPE_IMAGE,
} ftp_type;

typedef enum {
    FTP_MODE_STREAM,
} ftp_mode;

typedef enum {
    FTP_STRU_FILE,
} ftp_structure;

typedef enum {
    FTP_PROT_CLEAR,
    FTP_PROT_PRIVATE,
} ftp_plevel;

typedef enum {
    DATA_CONN_NONE,
    DATA_CONN_ACTIVE,
    DATA_CONN_PASSIVE,
} ftp_data_conn_state;

typedef struct {
    int server_socket;
    SSL_CTX* ssl_ctx;
    server_config_t config;
} ftp_server_state_t;

typedef struct {
    pthread_t thread_id;
    pthread_mutex_t mutex;

    int control_socket;
    SSL* ssl_control_channel;
    struct sockaddr_in client_addr;

    int data_socket;
    SSL* ssl_data_channel;
    int passive_socket;
    ftp_data_conn_state data_conn_state;

    char username[MAX_USERNAME_LEN];
    uid_t uid;
    gid_t gid;
    int is_authenticated;
    int ssl_enabled;
    SSL_CTX* ctx;

    char current_dir[MAX_PATH_LEN];
    int passive_mode;
    int data_port;
    ftp_type transfer_type;
    ftp_mode transfer_mode;
    ftp_structure transfer_structure;
    ftp_plevel protection_level;

    char rename_file_path[1024];
    int rename_ready;

} ftp_session_t;

typedef void (*ftp_command_handler_t)(ftp_session_t *session, char *arg);

typedef struct {
    const char *command;
    ftp_command_handler_t handler;
} ftp_command;

void* handle_client(void* arg);

#endif //SERVER_H