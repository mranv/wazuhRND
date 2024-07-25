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
#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "wazuh_modules/log_function.h"
#include "os_net/os_net.h"

/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    ar_log_function(__FUNCTION__, "Thread started");

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
        ar_log_function(__FUNCTION__, "Failed to create unix queue: %s. Path: %s", strerror(errno), path);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    ar_log_function(__FUNCTION__, "Unix queue created successfully. Path: %s", path);

    /* Daemon loop */
    while (1)
    {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg) <= 0)
        {
            continue;
        }

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

        /* Send to ALL agents */
        if (ar_location & ALL_AGENTS)
        {
            char agent_id[KEYSIZE + 1] = "";

            /* Lock use of keys */
            key_lock_read();

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
                    if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg) <= 0)
                    {
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
            if (send_msg(ar_agent_id, msg_to_send, -1) >= 0)
            {
                rem_inc_send_ar(ar_agent_id);
            }
        }
    }

    // This point should never be reached
    free(msg_to_send);
    free(msg);
    return NULL;
}
