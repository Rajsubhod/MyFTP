#define _GNU_SOURCE

#include "server.h"

#include <signal.h>
#include <time.h>
#include <errno.h>


#define CONFIG_FILE "../server.conf"

volatile sig_atomic_t running = 1;

int init_ssl_library() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 1;
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(
        ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    return ctx;
}

int configure_ssl_context(SSL_CTX *ctx, ftp_server_state_t *server_state) {
    if (SSL_CTX_use_certificate_file(ctx, server_state->config.CERT_FILE,SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Failed to load certificate from %s\n", server_state->config.CERT_FILE);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, server_state->config.KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Warning: failed to load private key from %s\n", server_state->config.KEY_FILE);
        return 0;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return 0;
    }

    return 1;
}

void handle_sigint(int sig) {
}

int main(void) {
    struct sockaddr_in server_addr, client_addr;

    server_config_t *server_config = load_config(CONFIG_FILE);

    init_ssl_library();

    ftp_server_state_t *server_state = malloc(sizeof(ftp_server_state_t));

    server_state->ssl_ctx = create_ssl_context();
    server_state->config = *server_config;

    if (!server_state->ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context.\n");
        exit(EXIT_FAILURE);
    }

    if (!configure_ssl_context(server_state->ssl_ctx, server_state)) {
        printf("Warning: SSL/TLS will not be available (certificate/key not found).\n");
        server_state->ssl_ctx = nullptr;
    } else {
        printf("SSL/TLS configured successfully.\n");
    }

    mkdir(server_state->config.FTP_ROOT, 0755);

    server_state->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_state->server_socket < 0) {
        log_error("Socket creation failed");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(server_state->server_socket, SOL_SOCKET, SO_RCVTIMEO | SO_REUSEADDR, (const char *) &tv, sizeof tv);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_state->config.PORT);

    if (bind(server_state->server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        log_error("Bind failed");
        perror("Bind failed");
        close(server_state->server_socket);
        exit(1);
    }

    if (listen(server_state->server_socket, server_state->config.MAX_CLIENTS)) {
        log_error("Listen failed");
        perror("Listen failed");
        close(server_state->server_socket);
        exit(1);
    }

    printf("FTP Server listening on port %d\n", server_state->config.PORT);
    printf("FTP root directory: %s\n", server_state->config.FTP_ROOT);
    printf("FTP Server listening of ip address: %s\n", inet_ntoa(server_addr.sin_addr));

    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    while (running) {
        int client_socket = accept(server_state->server_socket, (struct sockaddr *) &client_addr,
                                   &(socklen_t){sizeof(client_addr)});

        if (client_socket < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (errno == EINTR && !running) {
                break;
            }
            perror("Accept failed");
            continue;
        }

        if (!running) {
            close(client_socket);
            break;
        }

        printf("New client connected: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        ftp_session_t *ftp_session = malloc(sizeof(ftp_session_t));
        if (!ftp_session) {
            perror("Failed to allocate memory for FTP session");
            close(client_socket);
            continue;
        }
        ftp_session->control_socket = client_socket;
        ftp_session->ssl_control_channel = nullptr;
        ftp_session->client_addr = client_addr;

        ftp_session->data_socket = -1;
        ftp_session->ssl_data_channel = nullptr;
        ftp_session->passive_socket = -1;
        ftp_session->data_conn_state = DATA_CONN_NONE;

        memset(ftp_session->username, 0, sizeof(ftp_session->username));
        ftp_session->uid = -1;
        ftp_session->gid = -1;
        ftp_session->is_authenticated = 0;
        ftp_session->ssl_enabled = (server_state->ssl_ctx != NULL);

        strcpy(ftp_session->current_dir, "/tmp");
        ftp_session->transfer_type = FTP_TYPE_IMAGE;
        ftp_session->transfer_mode = FTP_MODE_STREAM;
        ftp_session->transfer_structure = FTP_STRU_FILE;
        ftp_session->protection_level = FTP_PROT_PRIVATE;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, ftp_session);
        pthread_detach(thread);
    }

    close(server_state->server_socket);
    printf("FTP Server has shut down.\n");
    free(server_state);
    free(server_config);
    return 0;
}


void *handle_client(void *arg) {
    ftp_session_t *session = arg;
}
