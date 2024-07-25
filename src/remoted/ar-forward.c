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

#define LOG_FILE "/var/ossec/logs/ar_forward_detailed.log"
#define MAX_LOG_LENGTH 4096

typedef enum
{
    CLOG_DEBUG,
    CLOG_INFO,
    CLOG_WARNING,
    CLOG_ERROR,
    CLOG_CRITICAL
} LogLevel;

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void deep_log(LogLevel level, const char *function_name, int line, const char *format, ...)
{
    static const char *level_strings[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};

    time_t now;
    struct tm *local_time;
    char timestamp[26];
    char log_message[MAX_LOG_LENGTH];
    va_list args;

    // Get current time
    time(&now);
    local_time = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);

    // Format the log message
    va_start(args, format);
    vsnprintf(log_message, sizeof(log_message), format, args);
    va_end(args);

    // Thread-safe logging
    pthread_mutex_lock(&log_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        fprintf(log_file, "[%s] [%s] [%s:%d] %s\n",
                timestamp, level_strings[level], function_name, line, log_message);
        fclose(log_file);
    }

    pthread_mutex_unlock(&log_mutex);
}

#define CLOG_DEBUG(...) deep_log(CLOG_DEBUG, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_INFO(...) deep_log(CLOG_INFO, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_WARNING(...) deep_log(CLOG_WARNING, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_ERROR(...) deep_log(CLOG_ERROR, __FUNCTION__, __LINE__, __VA_ARGS__)
#define CLOG_CRITICAL(...) deep_log(CLOG_CRITICAL, __FUNCTION__, __LINE__, __VA_ARGS__)

/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    CLOG_INFO("Thread started");

    int arq = 0;
    int ar_location = 0;
    const char *path = ARQUEUE;
    char *msg_to_send;
    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    char *msg;
    os_calloc(OS_MAXSTR, sizeof(char), msg);
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

    /* Create the unix queue */
    if ((arq = StartMQ(path, READ, 0)) < 0)
    {
        CLOG_CRITICAL("Failed to create unix queue: %s. Path: %s", strerror(errno), path);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    CLOG_INFO("Unix queue created successfully. Path: %s", path);

    /* Daemon loop */
    while (1)
    {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg) <= 0)
        {
            CLOG_DEBUG("No message received from queue");
            continue;
        }

        CLOG_DEBUG("Active response request received: %s", msg);

        /* Always zero the location */
        ar_location = 0;

        /* Location */
        tmp_str = strchr(msg, ')');
        if (!tmp_str)
        {
            mwarn(EXECD_INV_MSG, msg);
            continue;
        }
        tmp_str += 2;

        /* Source IP */
        tmp_str = strchr(tmp_str, ']');
        if (!tmp_str)
        {
            mwarn(EXECD_INV_MSG, msg);
            continue;
        }
        tmp_str += 2;

        /* AR location */
        if (*tmp_str == ALL_AGENTS_C)
        {
            ar_location |= ALL_AGENTS;
        }
        tmp_str++;
        if (*tmp_str == REMOTE_AGENT_C)
        {
            ar_location |= REMOTE_AGENT;
        }
        else if (*tmp_str == NO_AR_C)
        {
            ar_location |= NO_AR_MSG;
        }
        tmp_str++;
        if (*tmp_str == SPECIFIC_AGENT_C)
        {
            ar_location |= SPECIFIC_AGENT;
        }
        tmp_str += 2;

        /* Extract the agent id */
        ar_agent_id = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        if (!tmp_str)
        {
            mwarn(EXECD_INV_MSG, msg);
            continue;
        }
        *tmp_str = '\0';
        tmp_str++;

        /* Create the new message */
        if (ar_location & NO_AR_MSG)
        {
            snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                     CONTROL_HEADER,
                     tmp_str);
        }
        else
        {
            snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                     CONTROL_HEADER,
                     EXECD_HEADER,
                     tmp_str);
        }

        CLOG_DEBUG("Active response message prepared: %s", msg_to_send);

        /* Send to ALL agents */
        if (ar_location & ALL_AGENTS)
        {
            char agent_id[KEYSIZE + 1] = "";

            /* Lock use of keys */
            key_lock_read();

            CLOG_INFO("Sending message to ALL agents");

            for (unsigned int i = 0; i < keys.keysize; i++)
            {
                if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time))
                {
                    strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                    key_unlock();
                    if (send_msg(agent_id, msg_to_send, -1) >= 0)
                    {
                        rem_inc_send_ar(agent_id);
                    }
                    else
                    {
                    }
                    if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg) <= 0)
                    {
                        CLOG_DEBUG("No message received from queue");
                        continue;
                    }
                    key_lock_read();
                }
            }

            key_unlock();
        }

        /* Send to the remote agent that generated the event or to a pre-defined agent */
        else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT))
        {
            CLOG_INFO("Sending message to specific agent: %s", ar_agent_id);
            if (send_msg(ar_agent_id, msg_to_send, -1) >= 0)
            {
                rem_inc_send_ar(ar_agent_id);
                CLOG_INFO("Message sent successfully to specific agent: %s", ar_agent_id);
            }
            else
            {
                CLOG_ERROR("Failed to send message to specific agent: %s", ar_agent_id);
            }
        }
    }

    // This point should never be reached
    CLOG_CRITICAL("Thread exiting unexpectedly");
    free(msg_to_send);
    free(msg);
    return NULL;
}