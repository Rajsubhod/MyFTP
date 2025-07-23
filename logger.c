#include "logger.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

static void vlog_message(const char* level, const char* format, va_list args) {
    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now_t = time(NULL);
    struct tm now_tm;
    localtime_r(&now_t, &now_tm); // Using thread-safe localtime_r
    char time_buf[26];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &now_tm);

    fprintf(log_file, "[%s] [%s] ", time_buf, level);

    vfprintf(log_file, format, args);

    fprintf(log_file, "\n");

    fclose(log_file);
}

void log_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vlog_message("INFO", format, args);
    va_end(args);
}

void log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vlog_message("ERROR", format, args);
    va_end(args);
}

void log_debug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vlog_message("DEBUG", format, args);
    va_end(args);
}
