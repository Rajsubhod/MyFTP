#ifndef LOGGER_H
#define LOGGER_H

#define LOG_FILE "ftp_server.log"

// These functions now accept a format string and variable arguments, like printf.
// The __attribute__ provides compile-time checking of the format string and arguments.
void log_info(const char* format, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char* format, ...) __attribute__((format(printf, 1, 2)));
void log_debug(const char* format, ...) __attribute__((format(printf, 1, 2)));

#endif //LOGGER_H