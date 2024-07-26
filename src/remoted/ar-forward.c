#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdio.h> // Include for log_function
#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"

// Define the path to the log file for this component
#define AR_FORWARD_LOG_PATH "/var/ossec/logs/ar_forward.log"

/* Start of a new thread. Only returns on unrecoverable errors. */
void *AR_Forward(__attribute__((unused)) void *arg)
{
    log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Starting thread.");

    int arq = 0;
    int ar_location = 0;
    const char *path = ARQUEUE;
    char *msg_to_send;
    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    char *msg;
    os_calloc(OS_MAXSTR, sizeof(char), msg);
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

    log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Creating the unix queue with path: %s", path);

    /* Create the unix queue */
    if ((arq = StartMQ(path, READ, 0)) < 0)
    {
        log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_ERROR, "Failed to start message queue. Error: %s", strerror(errno));
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Message queue started successfully.");

    /* Daemon loop */
    while (1)
    {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg))
        {
            log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Active response request received: %s", msg);

            /* Always zero the location */
            ar_location = 0;

            /* Location */
            tmp_str = strchr(msg, ')');
            if (!tmp_str)
            {
                log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_WARN, "Invalid message format: %s", msg);
                mwarn(EXECD_INV_MSG, msg);
                continue;
            }
            tmp_str += 2;

            /* Source IP */
            tmp_str = strchr(tmp_str, ']');
            if (!tmp_str)
            {
                log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_WARN, "Invalid message format: %s", msg);
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
                log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_WARN, "Invalid message format: %s", msg);
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

            log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Active response sent: %s", msg_to_send);

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
    }

    log_function(AR_FORWARD_LOG_PATH, __func__, LOG_LEVEL_INFO, "Thread exiting.");
    return NULL;
}
