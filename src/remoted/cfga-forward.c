#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

// Define log file path
#define LOG_FILE_SCFGA "/var/ossec/logs/scfga_forward.log"

// Mutex for logging to ensure thread safety
static pthread_mutex_t log_mutex_scfga = PTHREAD_MUTEX_INITIALIZER;

// Logging functions
static void log_error_scfga(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    pthread_mutex_lock(&log_mutex_scfga);
    FILE *log_fp = fopen(LOG_FILE_SCFGA, "a");
    if (log_fp)
    {
        fprintf(log_fp, "[ERROR] ");
        vfprintf(log_fp, format, args);
        fprintf(log_fp, "\n");
        fclose(log_fp);
    }
    else
    {
        fprintf(stderr, "Failed to open log file %s: %s\n", LOG_FILE_SCFGA, strerror(errno));
    }
    pthread_mutex_unlock(&log_mutex_scfga);

    va_end(args);
}

static void log_warning_scfga(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    pthread_mutex_lock(&log_mutex_scfga);
    FILE *log_fp = fopen(LOG_FILE_SCFGA, "a");
    if (log_fp)
    {
        fprintf(log_fp, "[WARNING] ");
        vfprintf(log_fp, format, args);
        fprintf(log_fp, "\n");
        fclose(log_fp);
    }
    else
    {
        fprintf(stderr, "Failed to open log file %s: %s\n", LOG_FILE_SCFGA, strerror(errno));
    }
    pthread_mutex_unlock(&log_mutex_scfga);

    va_end(args);
}

static void log_debug_scfga(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    pthread_mutex_lock(&log_mutex_scfga);
    FILE *log_fp = fopen(LOG_FILE_SCFGA, "a");
    if (log_fp)
    {
        fprintf(log_fp, "[DEBUG] ");
        vfprintf(log_fp, format, args);
        fprintf(log_fp, "\n");
        fclose(log_fp);
    }
    else
    {
        fprintf(stderr, "Failed to open log file %s: %s\n", LOG_FILE_SCFGA, strerror(errno));
    }
    pthread_mutex_unlock(&log_mutex_scfga);

    va_end(args);
}

// Start of a new thread. Only returns on unrecoverable errors.
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    int cfgarq = 0;
    char *agent_id;
    const char *path = CFGARQUEUE;

    char msg[OS_SIZE_4096 + 1];

    // Create the unix queue
    if ((cfgarq = StartMQ(path, READ, 0)) < 0)
    {
        log_error_scfga("Failed to start MQ at path %s: %s", path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    memset(msg, '\0', OS_SIZE_4096 + 1);

    // Daemon loop
    while (1)
    {
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg))
        {
            log_debug_scfga("Message received: %s", msg);

            agent_id = msg;

            char *msg_dump = strchr(msg, ':');

            if (msg_dump)
            {
                *msg_dump++ = '\0';
            }
            else
            {
                log_warning_scfga("Message format invalid: %s", msg);
                continue;
            }

            if (strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0)
            {
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                if (send_msg(agent_id, final_msg, -1) >= 0)
                {
                    rem_inc_send_cfga(agent_id);
                }
            }
            else
            {
                log_warning_scfga("Message does not match expected format: %s", msg);
            }
        }
    }
}
