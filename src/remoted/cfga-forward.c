/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

#define LOG_FILE "/var/ossec/logs/scfga_forward_detailed.log"
#define MAX_LOG_LENGTH 4096

typedef enum
{
    CLOG_DEBUG,
    CLOG_INFO,
    CLOG_WARNING,
    CLOG_ERROR,
    CLOG_CRITICAL
} LogLevel;

pthread_mutex_t CFGAlog_mutex = PTHREAD_MUTEX_INITIALIZER;

void CFGAdeep_log(LogLevel level, const char *function_name, int line, const char *format, ...)
{
    static const char *level_strings[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};

    time_t now;
    struct tm *local_time;
    char timestamp[26];
    char log_message[MAX_LOG_LENGTH];
    va_list args;

    time(&now);
    local_time = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);

    va_start(args, format);
    vsnprintf(log_message, sizeof(log_message), format, args);
    va_end(args);

    pthread_mutex_lock(&CFGAlog_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        fprintf(log_file, "[%s] [%s] [%s:%d] %s\n",
                timestamp, level_strings[level], function_name, line, log_message);
        fclose(log_file);
    }

    pthread_mutex_unlock(&CFGAlog_mutex);
}

#define CLOG_DEBUG(...) CFGAdeep_log(CLOG_DEBUG, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_INFO(...) CFGAdeep_log(CLOG_INFO, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_WARNING(...) CFGAdeep_log(CLOG_WARNING, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_ERROR(...) CFGAdeep_log(CLOG_ERROR, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_CRITICAL(...) CFGAdeep_log(CLOG_CRITICAL, __FUNCTION__, __LINE__, __VA_ARGS__)

/* Start of a new thread. Only returns on unrecoverable errors. */
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    CLOG_INFO("Thread started");

    int cfgarq = 0;
    char *agent_id;
    const char *path = CFGARQUEUE;

    char msg[OS_SIZE_4096 + 1];

    /* Create the unix queue */
    if ((cfgarq = StartMQ(path, READ, 0)) < 0)
    {
        CLOG_CRITICAL("Failed to create unix queue: %s. Path: %s", strerror(errno), path);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    CLOG_INFO("Unix queue created successfully. Path: %s", path);

    memset(msg, '\0', OS_SIZE_4096 + 1);

    /* Daemon loop */
    while (1)
    {
        CLOG_DEBUG("Waiting for message on queue");
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg))
        {
            CLOG_DEBUG("Message received: %s", msg);

            agent_id = msg;

            char *msg_dump = strchr(msg, ':');

            if (msg_dump)
            {
                *msg_dump++ = '\0';
                CLOG_DEBUG("Agent ID: %s, Message: %s", agent_id, msg_dump);
            }
            else
            {
                CLOG_WARNING("Invalid message format (missing ':'): %s", msg);
                continue;
            }

            if (strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0)
            {
                CLOG_DEBUG("CFGA_DB_DUMP message detected");
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                CLOG_DEBUG("Final message prepared: %s", final_msg);

                if (send_msg(agent_id, final_msg, -1) >= 0)
                {
                    CLOG_INFO("Message sent successfully to agent: %s", agent_id);
                    rem_inc_send_cfga(agent_id);
                }
                else
                {
                    CLOG_ERROR("Failed to send message to agent: %s", agent_id);
                }
            }
            else
            {
                CLOG_WARNING("Unexpected message type: %s", msg_dump);
            }
        }
        else
        {
            CLOG_DEBUG("No message received from queue");
        }

        // Reset msg buffer for next iteration
        memset(msg, '\0', OS_SIZE_4096 + 1);
    }

    // This point should never be reached
    CLOG_CRITICAL("Thread exiting unexpectedly");
    return NULL;
}