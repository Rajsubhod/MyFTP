
#ifndef COMMANDS_H
#define COMMANDS_H

#include <stddef.h>

#include "server.h"


int ssl_send(ftp_session_t *session, const void* data, size_t len);

int ssl_recv(ftp_session_t *session, void* data, size_t len);

void send_response(ftp_session_t *session, int code, const char *message);

void handle_user(ftp_session_t *session, char *username);

void handle_pass(ftp_session_t *session, char *password);

void handle_auth(ftp_session_t *session, char *auth_type);

void handle_pbsz(ftp_session_t *session, char *size);

void handle_prot(ftp_session_t *session, char *protection_level);

void handle_ccc(ftp_session_t *session, char *args);

void handle_type(ftp_session_t *session, char *type);

void handle_mode(ftp_session_t *session, char *mode);

void handle_stru(ftp_session_t *session, char *stru);

void handle_syst(ftp_session_t *session, char *args);

void handle_feat(ftp_session_t *session, char *args);

void handle_opts(ftp_session_t *session, char *options);

void handle_pwd(ftp_session_t *session,  char *args);

void handle_cwd(ftp_session_t *session, char *path);

void handle_rmd(ftp_session_t *session, char *path);

void handle_mkd(ftp_session_t *session, char *path);

void handle_port(ftp_session_t *session, char *port_str);

void handle_pasv(ftp_session_t *session, char *args);

void handle_noop(ftp_session_t *session, char *args);

void handle_list(ftp_session_t *session, char *args);

void handle_retr(ftp_session_t *session, char *filename);

void handle_stor(ftp_session_t *session, char *filename);

void handle_rest(ftp_session_t *session, char *offset);

void handle_dele(ftp_session_t *session, char *filename);

void handle_rnfr(ftp_session_t *session, char *oldname);

void handle_rnto(ftp_session_t *session, char *newname);

void handle_quit(ftp_session_t *session, char *args);

#endif //COMMANDS_H
