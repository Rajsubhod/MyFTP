#include "commands.h"
#include <pwd.h>
#include <shadow.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#include "logger.h"

int ssl_send(ftp_session_t* session, const void* data, size_t len)
{
    if (session->ssl_enabled && session->ssl_control_channel)
    {
        return SSL_write(session->ssl_control_channel, data, len);
    }
    return send(session->control_socket, data, len, 0);
}

int ssl_recv(ftp_session_t* session, void* data, size_t len)
{
    if (session->ssl_enabled && session->ssl_control_channel)
    {
        return SSL_read(session->ssl_control_channel, data, len);
    }
    return recv(session->control_socket, data, len, 0);
}

int ssl_data_send(ftp_session_t* session, const void* data, size_t len)
{
    if (session->protection_level != FTP_PROT_CLEAR && session->ssl_data_channel)
    {
        return SSL_write(session->ssl_data_channel, data, len);
    }
    return send(session->data_socket, data, len, 0);
}

int ssl_data_recv(ftp_session_t* session, void* data, size_t len)
{
    if (session->protection_level != FTP_PROT_CLEAR && session->ssl_data_channel)
    {
        return SSL_read(session->ssl_data_channel, data, len);
    }
    return recv(session->data_socket, data, len, 0);
}

int create_ssl_data_connection(ftp_session_t* session, int data_socket)
{
    if (session->protection_level == FTP_PROT_CLEAR)
    {
        return 1;
    }

    session->ssl_data_channel = SSL_new(session->ctx);
    if (!session->ssl_data_channel)
    {
        ERR_print_errors_fp(stderr);
        close(data_socket);
        return -1;
    }
    SSL_set_fd(session->ssl_data_channel, data_socket);
    if (SSL_accept(session->ssl_data_channel) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(session->ssl_data_channel);
        session->ssl_data_channel = NULL;
        close(data_socket);
        return -1;
    }

    printf("SSL/TLS enabled for data channel.\n");
    return data_socket;
}

void send_response(ftp_session_t* session, int code, const char* message)
{
    char response[255];
    snprintf(response, sizeof(response), "%d %s\r\n", code, message);
    ssl_send(session, response, strlen(response));
}

void handle_user(ftp_session_t* session, char* username)
{
    log_info("USER command received with username: %s", username);
    if (!username || strlen(username) == 0)
    {
        send_response(session, 501, "Syntax error in parameters or arguments.");
        return;
    }

    strncpy(session->username, username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    session->is_authenticated = 0;
    send_response(session, 331, "Username okay, need password.");
}

void handle_pass(ftp_session_t* session, char* password)
{
    log_info("PASS command received for user: %s", session->username);
    if (!session->username[0])
    {
        send_response(session, 503, "Login with USER first.");
        return;
    }

    if (!password || strlen(password) == 0)
    {
        send_response(session, 501, "Syntax error in parameters or arguments.");
        return;
    }

    struct passwd* pwd = getpwnam(session->username);
    if (!pwd)
    {
        log_info("User %s not found in system", session->username);
        send_response(session, 530, "Login incorrect.");
        return;
    }

    struct spwd* spwd = getspnam(session->username);
    char* encrypted_pass;
    if (spwd)
    {
        encrypted_pass = spwd->sp_pwdp;
    }
    else
    {
        encrypted_pass = pwd->pw_passwd;
    }

    char* result = crypt(encrypted_pass, password);
    if (!result)
    {
        log_info("Invalid Username or Password.");
        send_response(session, 530, "Login incorrect.");
    }

    session->uid = pwd->pw_uid;
    session->gid = pwd->pw_gid;
    strcpy(session->current_dir, pwd->pw_dir);
    session->is_authenticated = 1;
    log_info("User %s successfully authenticated", session->username);

    send_response(session, 230, "User logged in, proceed.");
}

void handle_auth(ftp_session_t* session, char* auth_type)
{
    if (!auth_type)
    {
        send_response(session, 501, "AUTH requires a parameter");
        return;
    }

    if (strcasecmp(auth_type, "TLS") == 0 || strcasecmp(auth_type, "SSL") == 0)
    {
        if (session->ssl_enabled)
        {
            send_response(session, 534, "SSL/TLS already enabled.");
            return;
        }

        send_response(session, 234, "Procede with SSL/TLS negotiation.");

        session->ssl_control_channel = SSL_new(session->ctx);
        if (!session->ssl_control_channel)
        {
            ERR_print_errors_fp(stderr);
            send_response(session, 431, "SSL/TLS negotiation failed.");
            return;
        }

        SSL_set_fd(session->ssl_control_channel, session->control_socket);

        if (SSL_accept(session->ssl_control_channel) <= 0)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(session->ssl_control_channel);
            session->ssl_control_channel = NULL;
            send_response(session, 431, "SSL/TLS negotiation failed.");
            return;
        }

        session->ssl_enabled = 1;
        printf("SSL/TLS enabled for control channel.\n");
    }
    else
    {
        send_response(session, 504, "AUTH) not supported.");
    }
}

void handle_pbsz(ftp_session_t* session, char* size)
{
    if (!session->ssl_enabled)
    {
        send_response(session, 503, "PBSZ not allowed on unsecured control connection");
        return;
    }

    if (size && strcmp(size, "0") == 0)
    {
        send_response(session, 200, "PBSZ set to 0");
    }
}

void handle_prot(ftp_session_t* session, char* level)
{
    if (!session->ssl_enabled)
    {
        send_response(session, 503, "PROT not allowed on unsecured control connection");
        return;
    }

    if (!level)
    {
        send_response(session, 501, "PROT requires a parameter");
        return;
    }

    switch (level[0])
    {
    case 'C':
    case 'c':
        session->protection_level = FTP_PROT_CLEAR;
        send_response(session, 200, "Protection level set to Clear");
        break;
    case 'P':
    case 'p':
        session->protection_level = FTP_PROT_PRIVATE;
        send_response(session, 200, "Protection level set to Private");
        break;
    default:
        send_response(session, 504, "Protection level not supported");
    }
}

void handle_ccc(ftp_session_t* session, char* args)
{
    (void)args;
    if (!session->ssl_enabled)
    {
        send_response(session, 533, "Control connection not protected");
        return;
    }

    send_response(session, 200, "Clearing control connection");

    if (session->ssl_data_channel)
    {
        SSL_shutdown(session->ssl_data_channel);
        SSL_free(session->ssl_data_channel);
        session->ssl_data_channel = NULL;
    }

    if (session->ssl_control_channel)
    {
        SSL_shutdown(session->ssl_control_channel);
        SSL_free(session->ssl_control_channel);
        session->ssl_control_channel = NULL;
    }

    session->ssl_enabled = 0;
    log_info("Control connection cleared of SSL/TLS\n");
}

void handle_type(ftp_session_t* session, char* type)
{
    if (strcasecmp(type, "A") == 0)
    {
        session->transfer_type = FTP_TYPE_IMAGE;
        send_response(session, 200, "Type set to ASCII.");
    }
    else if (strcasecmp(type, "I") == 0)
    {
        session->transfer_type = FTP_TYPE_IMAGE;
        send_response(session, 200, "Type set to Image.");
    }
    else
    {
        send_response(session, 504, "Invalid type specified.");
    }
}

void handle_mode(ftp_session_t* session, char* mode)
{
    if (strcasecmp(mode, "S") == 0)
    {
        session->transfer_mode = FTP_MODE_STREAM;
        send_response(session, 200, "Mode set to Stream.");
    }
    else
    {
        send_response(session, 504, "Invalid mode specified.");
    }
}

void handle_stru(ftp_session_t* session, char* stru)
{
    if (strcasecmp(stru, "F") == 0)
    {
        session->transfer_structure = FTP_STRU_FILE;
        send_response(session, 200, "Structure set to File.");
    }
    else
    {
        send_response(session, 504, "Invalid structure specified.");
    }
}

void handle_syst(ftp_session_t* session, char* args)
{
    (void)args;
    const char* response = "215 UNIX Type: L8\r\n";
    ssl_send(session, response, strlen(response));
}

void handle_feat(ftp_session_t* session, char* args)
{
    (void)args;
    char response[] = "211-Features supported:\r\n"
        " AUTH TLS\r\n"
        " PBSZ\r\n"
        " PROT\r\n"
        " UTF8\r\n"
        " CCC\r\n"
        " TYPE\r\n"
        " MODE\r\n"
        " STRU\r\n"
        " PWD\r\n"
        " CWD\r\n"
        " PASV\r\n"
        " LIST\r\n"
        "211 End\r\n";
    ssl_send(session, response, strlen(response));
}

void handle_opts(ftp_session_t* session, char* option)
{
    if (!option)
    {
        send_response(session, 501, "Syntax error in parameters");
        return;
    }

    char full_option[64];
    snprintf(full_option, sizeof(full_option), "%s", option);

    char* next_arg = strtok(NULL, "");
    if (next_arg)
    {
        strncat(full_option, " ", sizeof(full_option) - strlen(full_option) - 1);
        strncat(full_option, next_arg, sizeof(full_option) - strlen(full_option) - 1);
    }

    if (strcasecmp(full_option, "UTF8 ON") == 0)
    {
        send_response(session, 200, "UTF8 set to on");
    }
    else
    {
        send_response(session, 501, "Option not understood");
    }
}

void handle_pwd(ftp_session_t* session, char* args)
{
    (void)args;

    if (!session->is_authenticated)
    {
        send_response(session, 530, "Not logged in.");
        return;
    }

    char response[512];
    snprintf(response, sizeof(response), "\"%s\" is the current directory.\r\n", session->current_dir);
    send_response(session, 257, response);
}

void handle_cwd(ftp_session_t* session, char* path)
{
    if (!session->is_authenticated)
    {
        send_response(session, 530, "Not logged in.");
        return;
    }

    if (path == NULL || strcmp(path, "") == 0)
    {
        path = "/";
    }

    char full_path[512];
    if (path[0] == '/')
    {
        // Relative path
        snprintf(full_path, sizeof(full_path), "%s", path);
    }
    else
    {
        // Absolute path
        snprintf(full_path, sizeof(full_path), "%s/%s", session->current_dir, path);
    }

    struct stat st;
    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode))
    {
        strcpy(session->current_dir, full_path);
        log_info("%s\n", session->current_dir);
        send_response(session, 250, "Directory changed.");
    }
    else
    {
        send_response(session, 550, "Directory not found.");
    }
}

void handle_pasv(ftp_session_t* session, char* args)
{
    (void)args;
    if (session->passive_socket > 0)
    {
        close(session->passive_socket);
        session->passive_socket = -1;
    }

    session->passive_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (session->passive_socket < 0)
    {
        send_response(session, 425, "Can't open passive connection.");
        return;
    }

    int opt = 1;
    if (setsockopt(session->passive_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt SO_REUSEADDR failed");
    }

    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(session->control_socket, (struct sockaddr*)&server_addr, &addr_len) < 0)
    {
        perror("getsockname on control socket failed");
        send_response(session, 425, "Can't get server address.");
        close(session->passive_socket);
        session->passive_socket = -1;
        return;
    }

    struct sockaddr_in pasv_addr;
    memset(&pasv_addr, 0, sizeof(pasv_addr));
    pasv_addr.sin_family = AF_INET;
    pasv_addr.sin_addr = server_addr.sin_addr;
    pasv_addr.sin_port = 0;

    if (bind(session->passive_socket, (struct sockaddr*)&pasv_addr, sizeof(pasv_addr)) < 0)
    {
        perror("bind failed");
        send_response(session, 425, "Can't bind passive connection.");
        close(session->passive_socket);
        session->passive_socket = -1;
        return;
    }

    if (listen(session->passive_socket, 1) < 0)
    {
        perror("listen failed");
        send_response(session, 425, "Can't listen on passive connection.");
        close(session->passive_socket);
        session->passive_socket = -1;
        return;
    }

    addr_len = sizeof(pasv_addr);
    if (getsockname(session->passive_socket, (struct sockaddr*)&pasv_addr, &addr_len) < 0)
    {
        perror("getsockname failed");
        send_response(session, 425, "Can't get passive connection info.");
        close(session->passive_socket);
        session->passive_socket = -1;
        return;
    }
    session->passive_mode = 1;
    session->data_port = ntohs(pasv_addr.sin_port);

    uint32_t ip = ntohl(pasv_addr.sin_addr.s_addr);
    char response[2048];
    snprintf(response, sizeof(response), "Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF,
             session->data_port / 256,
             session->data_port % 256);

    printf("PASV: Listening on %s:%d\n", inet_ntoa(pasv_addr.sin_addr), session->data_port);
    send_response(session, 227, response);

    log_info("PASV: Response sent, waiting for client command...\n");
}

void handle_list(ftp_session_t* session, char* args)
{
    (void)args;
    if (!session->is_authenticated)
    {
        send_response(session, 530, "Not logged in.");
        return;
    }

    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s", session->current_dir);

    // printf("%s\n", full_path);

    DIR* dir = opendir(full_path);
    if (!dir)
    {
        send_response(session, 550, "Failed to open directory.");
        return;
    }

    send_response(session, 150, "Opening data connection for directory listing.");

    printf("LIST: Waiting for data connection on passive socket %d...\n", session->passive_socket);

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(session->passive_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int data_sock = accept(session->passive_socket, NULL, NULL);
    if (data_sock < 0)
    {
        perror("accept failed for LIST");
        send_response(session, 425, "Can't open data connection.");
        closedir(dir);
        return;
    }

    // printf("LIST: Data connection established successfully!\n");

    session->data_socket = data_sock;
    if (create_ssl_data_connection(session, data_sock) < 0)
    {
        send_response(session, 425, "Can't open data connection.");
        closedir(dir);
        return;
    }

    struct dirent* entry;
    char list_item[1024];

    time_t now = time(NULL);
    struct tm* now_tm = localtime(&now);

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        char item_path[1024];
        size_t path_len = strlen(full_path);
        size_t name_len = strlen(entry->d_name);

        if (path_len + 1 + name_len >= sizeof(item_path))
        {
            fprintf(stderr, "Skipping too-long path: %s/%s\n", full_path, entry->d_name);
            continue;
        }
        snprintf(item_path, sizeof(item_path), "%s/%s", full_path, entry->d_name);

        struct stat st;
        if (stat(item_path, &st) == 0)
        {
            char permissions[11];
            snprintf(permissions, sizeof(permissions), "%c%c%c%c%c%c%c%c%c%c",
                     (S_ISDIR(st.st_mode) ? 'd' : '-'),
                     (st.st_mode & S_IRUSR) ? 'r' : '-',
                     (st.st_mode & S_IWUSR) ? 'w' : '-',
                     (st.st_mode & S_IXUSR) ? 'x' : '-',
                     (st.st_mode & S_IRGRP) ? 'r' : '-',
                     (st.st_mode & S_IWGRP) ? 'w' : '-',
                     (st.st_mode & S_IXGRP) ? 'x' : '-',
                     (st.st_mode & S_IROTH) ? 'r' : '-',
                     (st.st_mode & S_IWOTH) ? 'w' : '-',
                     (st.st_mode & S_IXOTH) ? 'x' : '-');

            char time_str[32];

            time_t file_time = st.st_mtime;
            struct tm* tm_info = localtime(&file_time);

            if (tm_info == NULL) {
                snprintf(time_str, sizeof(time_str), "Jan  1  1970");
            } else {
                double time_diff = difftime(now, file_time);

                // If file is less than 6 months old, show time; otherwise show year
                if (time_diff >= 0 && time_diff < (6 * 30 * 24 * 3600)) { // ~6 months in seconds
                    strftime(time_str, sizeof(time_str), "%b %d %H:%M", tm_info);
                } else {
                    strftime(time_str, sizeof(time_str), "%b %d  %Y", tm_info);
                }
            }

            snprintf(list_item, sizeof(list_item),
                     "%s   1 ftp      ftp      %8ld %s %s\r\n",
                     permissions, (long)st.st_size, time_str, entry->d_name);

            if (ssl_data_send(session, list_item, strlen(list_item)) < 0)
            {
                perror("send failed");
                break;
            }
        }
    }

    closedir(dir);

    if (session->ssl_data_channel)
    {
        SSL_shutdown(session->ssl_data_channel);
        SSL_free(session->ssl_data_channel);
        session->ssl_data_channel = NULL;
    }

    close(data_sock);

    if (session->passive_socket > 0)
    {
        close(session->passive_socket);
        session->passive_socket = -1;
    }
    session->passive_mode = 0;

    send_response(session, 226, "Transfer complete.");
}