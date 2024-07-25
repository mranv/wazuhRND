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
#include "wazuh_modules/log_function.h"
#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

/* Start of a new thread. Only returns on unrecoverable errors. */
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    scfga_log_function(__func__, "Thread started");

    int cfgarq = 0;
    char *agent_id;
    const char *path = CFGARQUEUE;

    char msg[OS_SIZE_4096 + 1];

    /* Create the unix queue */
    if ((cfgarq = StartMQ(path, READ, 0)) < 0)
    {
        scfga_log_function(__func__, "Failed to create unix queue: %s. Path: %s", strerror(errno), path);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    scfga_log_function(__func__, "Unix queue created successfully. Path: %s", path);

    memset(msg, '\0', OS_SIZE_4096 + 1);

    /* Daemon loop */
    while (1)
    {
        scfga_log_function(__func__, "Waiting for message on queue");
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg))
        {
            scfga_log_function(__func__, "Message received: %s", msg);

            agent_id = msg;

            char *msg_dump = strchr(msg, ':');

            if (msg_dump)
            {
                *msg_dump++ = '\0';
                scfga_log_function(__func__, "Agent ID: %s, Message: %s", agent_id, msg_dump);
            }
            else
            {
                scfga_log_function(__func__, "Invalid message format (missing ':'): %s", msg);
                continue;
            }

            if (strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0)
            {
                scfga_log_function(__func__, "CFGA_DB_DUMP message detected");
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                scfga_log_function(__func__, "Final message prepared: %s", final_msg);

                if (send_msg(agent_id, final_msg, -1) >= 0)
                {
                    scfga_log_function(__func__, "Message sent successfully to agent: %s", agent_id);
                    rem_inc_send_cfga(agent_id);
                }
                else
                {
                    scfga_log_function(__func__, "Failed to send message to agent: %s", agent_id);
                }
            }
            else
            {
                scfga_log_function(__func__, "Unexpected message type: %s", msg_dump);
            }
        }
        else
        {
            scfga_log_function(__func__, "No message received from queue");
        }

        // Reset msg buffer for next iteration
        memset(msg, '\0', OS_SIZE_4096 + 1);
    }

    // This point should never be reached
    scfga_log_function(__func__, "Thread exiting unexpectedly");
    return NULL;
}
