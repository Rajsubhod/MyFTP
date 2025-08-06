#ifndef PARSER_H
#define PARSER_H

#define CONFIG_FILE "/etc/my_ftp_server/server.conf"


typedef struct {
    int PORT;
    int BUFFER_SIZE;
    int MAX_CLIENTS;
    char FTP_ROOT[256];
    char CERT_FILE[256];
    char KEY_FILE[256];
    int CLIENT_TIMEOUT;
    int DATA_TIMEOUT;
} server_config_t;

server_config_t* load_config();
void free_config(server_config_t* config);
void print_config(const server_config_t* config);

#endif // PARSER_H