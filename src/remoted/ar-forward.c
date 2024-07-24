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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

#define LOG_FILE "/var/ossec/logs/ar_forward.log"

// Enhanced logger function with precise timestamp
void log_message(const char *function, const char *message) {
    struct timeval tv;
    struct tm *tm_info;
    char timestamp[64];
    int log_fd;

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%03ld", tv.tv_usec / 1000);

    log_fd = open(LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (log_fd >= 0) {
        dprintf(log_fd, "[%s] [%s] %s\n", timestamp, function, message);
        close(log_fd);
    } else {
        merror("Unable to open log file: %s", LOG_FILE);
    }
}

void *AR_Forward(__attribute__((unused)) void *arg)
{
    log_message("AR_Forward", "Function entered");

    int arq = 0;
    int ar_location = 0;
    const char * path = ARQUEUE;
    char *msg_to_send;
    char *msg;
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;
    char log_buffer[OS_MAXSTR];

    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    log_message("AR_Forward", "msg_to_send allocated");

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    log_message("AR_Forward", "msg allocated");

    log_message("AR_Forward", "Variables initialized");

    /* Create the unix queue */
    snprintf(log_buffer, OS_MAXSTR, "Attempting to create unix queue at path: %s", path);
    log_message("AR_Forward", log_buffer);

    if ((arq = StartMQ(path, READ, 0)) < 0) {
        snprintf(log_buffer, OS_MAXSTR, "Error creating unix queue: %s", strerror(errno));
        log_message("AR_Forward", log_buffer);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }
    
    snprintf(log_buffer, OS_MAXSTR, "Unix queue created successfully. arq = %d", arq);
    log_message("AR_Forward", log_buffer);

    /* Daemon loop */
    log_message("AR_Forward", "Entering daemon loop");
    while (1) {
        log_message("AR_Forward", "Waiting for message on unix queue");
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg)) {
            snprintf(log_buffer, OS_MAXSTR, "Received message: %s", msg);
            log_message("AR_Forward", log_buffer);

            /* Always zero the location */
            ar_location = 0;
            log_message("AR_Forward", "ar_location set to 0");

            /* Location */
            tmp_str = strchr(msg, ')');
            if (!tmp_str) {
                log_message("AR_Forward", "Invalid message format: missing ')' character");
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;
            snprintf(log_buffer, OS_MAXSTR, "Location parsed. tmp_str now points to: %s", tmp_str);
            log_message("AR_Forward", log_buffer);

            /* Source IP */
            tmp_str = strchr(tmp_str, ']');
            if (!tmp_str) {
                log_message("AR_Forward", "Invalid message format: missing ']' character");
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;
            snprintf(log_buffer, OS_MAXSTR, "Source IP parsed. tmp_str now points to: %s", tmp_str);
            log_message("AR_Forward", log_buffer);

            /* AR location */
            if (*tmp_str == ALL_AGENTS_C) {
                ar_location |= ALL_AGENTS;
                log_message("AR_Forward", "AR location: ALL_AGENTS");
            }
            tmp_str++;
            if (*tmp_str == REMOTE_AGENT_C) {
                ar_location |= REMOTE_AGENT;
                log_message("AR_Forward", "AR location: REMOTE_AGENT");
            } else if (*tmp_str == NO_AR_C) {
                ar_location |= NO_AR_MSG;
                log_message("AR_Forward", "AR location: NO_AR_MSG");
            }
            tmp_str++;
            if (*tmp_str == SPECIFIC_AGENT_C) {
                ar_location |= SPECIFIC_AGENT;
                log_message("AR_Forward", "AR location: SPECIFIC_AGENT");
            }
            tmp_str += 2;

            snprintf(log_buffer, OS_MAXSTR, "AR location parsed. ar_location = %d", ar_location);
            log_message("AR_Forward", log_buffer);

            /* Extract the agent id */
            ar_agent_id = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                log_message("AR_Forward", "Invalid message format: missing space after agent ID");
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

            snprintf(log_buffer, OS_MAXSTR, "Extracted agent ID: %s", ar_agent_id);
            log_message("AR_Forward", log_buffer);

            /* Create the new message */
            if (ar_location & NO_AR_MSG) {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s",
                         CONTROL_HEADER,
                         tmp_str);
                log_message("AR_Forward", "Created NO_AR_MSG message");
            } else {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s%s",
                         CONTROL_HEADER,
                         EXECD_HEADER,
                         tmp_str);
                log_message("AR_Forward", "Created normal AR message");
            }

            snprintf(log_buffer, OS_MAXSTR, "Message to send: %s", msg_to_send);
            log_message("AR_Forward", log_buffer);

            /* Send to ALL agents */
            if (ar_location & ALL_AGENTS) {
                char agent_id[KEYSIZE + 1] = "";

                log_message("AR_Forward", "Sending message to ALL agents");
                /* Lock use of keys */
                key_lock_read();
                log_message("AR_Forward", "Key read lock acquired");

                for (unsigned int i = 0; i < keys.keysize; i++) {
                    snprintf(log_buffer, OS_MAXSTR, "Checking agent %u of %u", i+1, keys.keysize);
                    log_message("AR_Forward", log_buffer);

                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        log_message("AR_Forward", "Key read lock released temporarily");

                        snprintf(log_buffer, OS_MAXSTR, "Attempting to send message to agent: %s", agent_id);
                        log_message("AR_Forward", log_buffer);

                        if (send_msg(agent_id, msg_to_send, -1) >= 0) {
                            rem_inc_send_ar(agent_id);
                            snprintf(log_buffer, OS_MAXSTR, "Message sent successfully to agent: %s", agent_id);
                            log_message("AR_Forward", log_buffer);
                        } else {
                            snprintf(log_buffer, OS_MAXSTR, "Failed to send message to agent: %s", agent_id);
                            log_message("AR_Forward", log_buffer);
                        }

                        key_lock_read();
                        log_message("AR_Forward", "Key read lock re-acquired");
                    } else {
                        snprintf(log_buffer, OS_MAXSTR, "Agent %s is disconnected, skipping", keys.keyentries[i]->id);
                        log_message("AR_Forward", log_buffer);
                    }
                }

                key_unlock();
                log_message("AR_Forward", "Key read lock released finally");
            }

            /* Send to the remote agent that generated the event or to a pre-defined agent */
            else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
                snprintf(log_buffer, OS_MAXSTR, "Sending message to specific agent: %s", ar_agent_id);
                log_message("AR_Forward", log_buffer);

                if (send_msg(ar_agent_id, msg_to_send, -1) >= 0) {
                    rem_inc_send_ar(ar_agent_id);
                    log_message("AR_Forward", "Message sent successfully");
                } else {
                    log_message("AR_Forward", "Failed to send message");
                }
            }

            log_message("AR_Forward", "Message processing completed");
        } else {
            log_message("AR_Forward", "No message received or error in OS_RecvUnix");
        }
    }

    // This part will never be reached due to the infinite loop, but including for completeness
    os_free(msg_to_send);
    os_free(msg);
    log_message("AR_Forward", "Memory freed and function exiting");
    return NULL;
}