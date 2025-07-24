
#ifndef COMMANDS_H
#define COMMANDS_H
#include "server.h"

void handle_user(ftp_session_t *session, char *username);

void handle_pass(ftp_session_t *session, char *password);

void handle_auth(ftp_session_t *session, char *auth_type);

void handle_type(ftp_session_t *session, char *type);

void handle_mode(ftp_session_t *session, char *mode);

void handle_stru(ftp_session_t *session, char *stru);

void handle_syst(ftp_session_t *session);

void handle_feat(ftp_session_t *session);

void handle_opts(ftp_session_t *session, char *options);

void handle_pwd(ftp_session_t *session);

void handle_cwd(ftp_session_t *session, char *path);

void handle_rmd(ftp_session_t *session, char *path);

void handle_mkd(ftp_session_t *session, char *path);

void handle_port(ftp_session_t *session, char *port_str);

void handle_pasv(ftp_session_t *session);

void handle_noop(ftp_session_t *session);

void handle_list(ftp_session_t *session);

void handle_retr(ftp_session_t *session, char *filename);

void handle_stor(ftp_session_t *session, char *filename);

void handle_rest(ftp_session_t *session, char *offset);

void handle_dele(ftp_session_t *session, char *filename);

void handle_rnfr(ftp_session_t *session, char *oldname);

void handle_rnto(ftp_session_t *session, char *newname);

void handle_quit(ftp_session_t *session);

#endif //COMMANDS_H
