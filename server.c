#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "server.h"


typedef struct Ftp_Session {
    int control_socket;
    int data_socket;
    SSL* ssl_control_channel;
    SSL* ssl_data_channel;
    SSL_CTX* ssl_ctx;

    char user_name[32];
    int authenticated;
    int ssl_enabled;
    t_prot protection_level;

    int passive_socket;
    struct sockaddr_in client_addr;
    char current_dir[256];
    int passive_mode;
    int data_port;

    t_type type;
    t_mode mode;
    t_stru stru;

    size_t local_bits;

} ftp_session_t;

int main(void) {
    printf("Hello, World!\n");
    return 0;
}