#include <stdio.h>
#include <time.h>
#include <errno.h>

#define LOG_FILE "/var/ossec/logs/network_ops.log"

void log_function(const char *function_name, const char *format, ...)
{
    time_t now = time(NULL);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        fprintf(log_file, "message run | %s | %s", timestamp, function_name);

        if (format)
        {
            va_list args;
            va_start(args, format);
            fprintf(log_file, " | ");
            vfprintf(log_file, format, args);
            va_end(args);
        }

        fprintf(log_file, "\n");
        fclose(log_file);
    }
}
