#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdio.h> // Include for log_function
#include "shared.h"
#include "remoted.h"
#include "wazuh_modules/wmodules.h"
#include "state.h"
#include "os_net/os_net.h"

// Define the path to the log file for this component
#define CFGA_FORWARD_LOG_PATH "/var/ossec/logs/cfga_forward.log"

/* Start of a new thread. Only returns on unrecoverable errors. */
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Starting thread.");

    int cfgarq = 0;
    char *agent_id;
    const char *path = CFGARQUEUE;
    char msg[OS_SIZE_4096 + 1];

    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Creating the unix queue with path: %s", path);

    /* Create the unix queue */
    if ((cfgarq = StartMQ(path, READ, 0)) < 0)
    {
        log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_ERROR, "Failed to start message queue. Error: %s", strerror(errno));
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Message queue started successfully.");

    memset(msg, '\0', OS_SIZE_4096 + 1);

    /* Daemon loop */
    while (1)
    {
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg))
        {
            log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Message received: %s", msg);

            agent_id = msg;

            char *msg_dump = strchr(msg, ':');

            if (msg_dump)
            {
                *msg_dump++ = '\0';
            }
            else
            {
                log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_WARN, "Invalid message format: %s", msg);
                continue;
            }

            if (strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0)
            {
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                if (send_msg(agent_id, final_msg, -1) >= 0)
                {
                    rem_inc_send_cfga(agent_id);
                    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Message sent to agent %s: %s", agent_id, final_msg);
                }
                else
                {
                    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_ERROR, "Failed to send message to agent %s", agent_id);
                }
            }
            else
            {
                log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_WARN, "Message does not match CFGA_DB_DUMP criteria: %s", msg_dump);
            }
        }
    }

    log_function(CFGA_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Thread exiting.");
    return NULL;
}
