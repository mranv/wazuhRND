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
<<<<<<< HEAD
#include <stdio.h>
#include <time.h>
=======
>>>>>>> v4.7.5

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

<<<<<<< HEAD
#define AR_FILE "/var/ossec/logs/arforwarder.log"

// Custom arger function
void ar_message(const char *level, const char *message)
{
    char timestamp[128];
    struct tm *local_time;
    time_t t;

    t = time(NULL);
    local_time = localtime(&t);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);

    FILE *ar_file = fopen(AR_FILE, "a");
    if (ar_file)
    {
        fprintf(ar_file, "[%s] %s: %s\n", timestamp, level, message);
        fclose(ar_file);
    }
    else
    {
        fprintf(stderr, "Error opening ar file: %s\n", AR_FILE);
    }
}

#define AR_DEBUG(msg, ...)                                          \
    do                                                              \
    {                                                               \
        char ar_buffer[OS_MAXSTR];                                  \
        snprintf(ar_buffer, sizeof(ar_buffer), msg, ##__VA_ARGS__); \
        ar_message("DEBUG", ar_buffer);                             \
    } while (0)

#define AR_INFO(msg, ...)                                           \
    do                                                              \
    {                                                               \
        char ar_buffer[OS_MAXSTR];                                  \
        snprintf(ar_buffer, sizeof(ar_buffer), msg, ##__VA_ARGS__); \
        ar_message("INFO", ar_buffer);                              \
    } while (0)

#define AR_WARN(msg, ...)                                           \
    do                                                              \
    {                                                               \
        char ar_buffer[OS_MAXSTR];                                  \
        snprintf(ar_buffer, sizeof(ar_buffer), msg, ##__VA_ARGS__); \
        ar_message("WARN", ar_buffer);                              \
    } while (0)

#define AR_ERROR(msg, ...)                                          \
    do                                                              \
    {                                                               \
        char ar_buffer[OS_MAXSTR];                                  \
        snprintf(ar_buffer, sizeof(ar_buffer), msg, ##__VA_ARGS__); \
        ar_message("ERROR", ar_buffer);                             \
    } while (0)
=======
>>>>>>> v4.7.5

/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    int arq = 0;
    int ar_location = 0;
<<<<<<< HEAD
    const char *path = ARQUEUE;
=======
    const char * path = ARQUEUE;
>>>>>>> v4.7.5
    char *msg_to_send;
    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    char *msg;
    os_calloc(OS_MAXSTR, sizeof(char), msg);
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

<<<<<<< HEAD
    AR_INFO("Starting AR_Forward thread");

    /* Create the unix queue */
    if ((arq = StartMQ(path, READ, 0)) < 0)
    {
        AR_ERROR("Could not start queue: %s", strerror(errno));
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    AR_INFO("Unix queue created successfully");

    /* Daemon loop */
    while (1)
    {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg))
        {
            AR_DEBUG("Active response request received: %s", msg);
=======
    /* Create the unix queue */
    if ((arq = StartMQ(path, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    /* Daemon loop */
    while (1) {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg)) {

            mdebug2("Active response request received: %s", msg);
>>>>>>> v4.7.5

            /* Always zero the location */
            ar_location = 0;

            /* Location */
            tmp_str = strchr(msg, ')');
<<<<<<< HEAD
            if (!tmp_str)
            {
                AR_WARN("Invalid message received: %s", msg);
=======
            if (!tmp_str) {
>>>>>>> v4.7.5
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;

            /* Source IP */
            tmp_str = strchr(tmp_str, ']');
<<<<<<< HEAD
            if (!tmp_str)
            {
                AR_WARN("Invalid message received: %s", msg);
=======
            if (!tmp_str) {
>>>>>>> v4.7.5
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;

            /* AR location */
<<<<<<< HEAD
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
=======
            if (*tmp_str == ALL_AGENTS_C) {
                ar_location |= ALL_AGENTS;
            }
            tmp_str++;
            if (*tmp_str == REMOTE_AGENT_C) {
                ar_location |= REMOTE_AGENT;
            } else if (*tmp_str == NO_AR_C) {
                ar_location |= NO_AR_MSG;
            }
            tmp_str++;
            if (*tmp_str == SPECIFIC_AGENT_C) {
>>>>>>> v4.7.5
                ar_location |= SPECIFIC_AGENT;
            }
            tmp_str += 2;

            /* Extract the agent id */
            ar_agent_id = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
<<<<<<< HEAD
            if (!tmp_str)
            {
                AR_WARN("Invalid message received: %s", msg);
=======
            if (!tmp_str) {
>>>>>>> v4.7.5
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

            /* Create the new message */
<<<<<<< HEAD
            if (ar_location & NO_AR_MSG)
            {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                         CONTROL_HEADER,
                         tmp_str);
            }
            else
            {
=======
            if (ar_location & NO_AR_MSG) {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                         CONTROL_HEADER,
                         tmp_str);
            } else {
>>>>>>> v4.7.5
                snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                         CONTROL_HEADER,
                         EXECD_HEADER,
                         tmp_str);
            }

<<<<<<< HEAD
            AR_DEBUG("Active response prepared: %s", msg_to_send);

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS)
            {
=======
            mdebug2("Active response sent: %s", msg_to_send);

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
>>>>>>> v4.7.5
                char agent_id[KEYSIZE + 1] = "";

                /* Lock use of keys */
                key_lock_read();

<<<<<<< HEAD
                for (unsigned int i = 0; i < keys.keysize; i++)
                {
                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time))
                    {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        if (send_msg(agent_id, msg_to_send, -1) >= 0)
                        {
                            rem_inc_send_ar(agent_id);
                            AR_INFO("Active response sent to agent: %s", agent_id);
                        }
                        else
                        {
                            AR_WARN("Failed to send active response to agent: %s", agent_id);
=======
                for (unsigned int i = 0; i < keys.keysize; i++) {
                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        if (send_msg(agent_id, msg_to_send, -1) >= 0) {
                            rem_inc_send_ar(agent_id);
>>>>>>> v4.7.5
                        }
                        key_lock_read();
                    }
                }

                key_unlock();
            }

            /* Send to the remote agent that generated the event or to a pre-defined agent */
<<<<<<< HEAD
            else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT))
            {
                if (send_msg(ar_agent_id, msg_to_send, -1) >= 0)
                {
                    rem_inc_send_ar(ar_agent_id);
                    AR_INFO("Active response sent to agent: %s", ar_agent_id);
                }
                else
                {
                    AR_WARN("Failed to send active response to agent: %s", ar_agent_id);
=======
            else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
                if (send_msg(ar_agent_id, msg_to_send, -1) >= 0) {
                    rem_inc_send_ar(ar_agent_id);
>>>>>>> v4.7.5
                }
            }
        }
    }
<<<<<<< HEAD
}
=======
}
>>>>>>> v4.7.5
