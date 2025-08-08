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
