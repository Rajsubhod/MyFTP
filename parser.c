#include "parser.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logger.h"

server_config_t* load_config() {
    server_config_t* config = malloc(sizeof(server_config_t));
    if (!config) {
        perror("Failed to allocate memory for config");
        return NULL;
    }

    config->PORT = 21;
    config->BUFFER_SIZE = 1024;
    config->MAX_CLIENTS = 10;
    strcpy(config->FTP_ROOT, "/tmp/myftp_root");
    strcpy(config->CERT_FILE, "/etc/ssl/certs/myftp.crt");
    strcpy(config->KEY_FILE, "/etc/ssl/private/myftp.key");
    config->CLIENT_TIMEOUT = 100;
    config->DATA_TIMEOUT = 60;

    const char* paths_to_try[] = {
        getenv("MY_FTP_CONFIG"),
        CONFIG_FILE,
        "../server.conf"
    };

    FILE* file = NULL;
    for (int i = 0; i < 3; ++i) {
        if (paths_to_try[i]) {
            file = fopen(paths_to_try[i], "r");
            if (file) {
                log_info("Loaded config from: %s\n", paths_to_try[i]);
                break;
            }
        }
    }

    if (!file) {
        log_info("Warning: No config file found, using default values\n");
        return config;
    }


    char line[512];
    int line_num = 0;

    while (fgets(line, sizeof(line), file)) {
        line_num++;

        char* newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        char* trimmed = line;
        while (isspace(*trimmed)) trimmed++;
        if (*trimmed == '\0' || *trimmed == '#') continue;

        char* equals = strchr(trimmed, '=');
        if (!equals) {
            log_info("Warning: Invalid config line %d: %s\n", line_num, trimmed);
            continue;
        }

        *equals = '\0';
        char* key = trimmed;
        char* value = equals + 1;

        while (isspace(*key)) key++;
        char* key_end = key + strlen(key) - 1;
        while (key_end > key && isspace(*key_end)) *key_end-- = '\0';

        while (isspace(*value)) value++;
        char* value_end = value + strlen(value) - 1;
        while (value_end > value && isspace(*value_end)) *value_end-- = '\0';

        // Parse configuration values
        if (strcmp(key, "port") == 0) {
            config->PORT = atoi(value);
            if (config->PORT <= 0 || config->PORT > 65535) {
                log_info("Warning: Invalid port %s, using default\n", value);
                config->PORT = 21;
            }
        } else if (strcmp(key, "buffer_size") == 0) {
            config->BUFFER_SIZE = atoi(value);
            if (config->BUFFER_SIZE <= 0) {
                log_info("Warning: Invalid buffer_size %s, using default\n", value);
                config->BUFFER_SIZE = 5120;
            }
        } else if (strcmp(key, "max_clients") == 0) {
            config->MAX_CLIENTS = atoi(value);
            if (config->MAX_CLIENTS <= 0) {
                log_info("Warning: Invalid max_clients %s, using default\n", value);
                config->MAX_CLIENTS = 10;
            }
        } else if (strcmp(key, "ftp_root") == 0) {
            strncpy(config->FTP_ROOT, value, sizeof(config->FTP_ROOT) - 1);
            config->FTP_ROOT[sizeof(config->FTP_ROOT) - 1] = '\0';
        } else if (strcmp(key, "cert_file") == 0) {
            strncpy(config->CERT_FILE, value, sizeof(config->CERT_FILE) - 1);
            config->CERT_FILE[sizeof(config->CERT_FILE) - 1] = '\0';
        } else if (strcmp(key, "key_file") == 0) {
            strncpy(config->KEY_FILE, value, sizeof(config->KEY_FILE) - 1);
            config->KEY_FILE[sizeof(config->KEY_FILE) - 1] = '\0';
        } else if (strcmp(key, "client_timeout") == 0) {
            config->CLIENT_TIMEOUT = atoi(value);
            if (config->CLIENT_TIMEOUT <= 0) {
                log_info("Warning: Invalid client_timeout %s, using default\n", value);
                config->CLIENT_TIMEOUT = 300;
            }
        } else if (strcmp(key, "data_timeout") == 0) {
            config->DATA_TIMEOUT = atoi(value);
            if (config->DATA_TIMEOUT <= 0) {
                log_info("Warning: Invalid data_timeout %s, using default\n", value);
                config->DATA_TIMEOUT = 60;
            }
        } else {
            log_info("Warning: Unknown config key '%s' on line %d\n", key, line_num);
        }
    }

    fclose(file);
    return config;
}

void free_config(server_config_t* config) {
    if (config) {
        free(config);
    }
}


void print_config(const server_config_t* config) {
    if (!config) return;

    printf("FTP Server Configuration:\n");
    printf("  Port: %d\n", config->PORT);
    printf("  Buffer Size: %d\n", config->BUFFER_SIZE);
    printf("  Max Clients: %d\n", config->MAX_CLIENTS);
    printf("  FTP Root: %s\n", config->FTP_ROOT);
    printf("  Certificate: %s\n", config->CERT_FILE);
    printf("  Private Key: %s\n", config->KEY_FILE);
    printf("  Client Timeout: %d seconds\n", config->CLIENT_TIMEOUT);
    printf("  Data Timeout: %d seconds\n", config->DATA_TIMEOUT);
}