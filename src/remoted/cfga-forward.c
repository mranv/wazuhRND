#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "os_net/os_net.h"

#define LOG_FILE "/var/ossec/logs/scfga_forward.log"

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

/* Start of a new thread. Only returns on unrecoverable errors. */
void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    log_message("SCFGA_Forward", "Function entered");

    int cfgarq = 0;
    char *agent_id;
    const char * path = CFGARQUEUE;
    char msg[OS_SIZE_4096 + 1];
    char log_buffer[OS_SIZE_4096 + 1];

    log_message("SCFGA_Forward", "Variables initialized");

    /* Create the unix queue */
    snprintf(log_buffer, OS_SIZE_4096, "Attempting to create unix queue at path: %s", path);
    log_message("SCFGA_Forward", log_buffer);

    if ((cfgarq = StartMQ(path, READ, 0)) < 0) {
        snprintf(log_buffer, OS_SIZE_4096, "Error creating unix queue: %s", strerror(errno));
        log_message("SCFGA_Forward", log_buffer);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    snprintf(log_buffer, OS_SIZE_4096, "Unix queue created successfully. cfgarq = %d", cfgarq);
    log_message("SCFGA_Forward", log_buffer);

    memset(msg, '\0', OS_SIZE_4096 + 1);
    log_message("SCFGA_Forward", "Message buffer initialized");

    /* Daemon loop */
    log_message("SCFGA_Forward", "Entering daemon loop");
    while (1) {
        log_message("SCFGA_Forward", "Waiting for message on unix queue");
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg)) {
            snprintf(log_buffer, OS_SIZE_4096, "Received message: %s", msg);
            log_message("SCFGA_Forward", log_buffer);

            agent_id = msg;
            log_message("SCFGA_Forward", "Agent ID extracted from message");

            char *msg_dump = strchr(msg,':');

            if(msg_dump) {
                *msg_dump++ = '\0';
                snprintf(log_buffer, OS_SIZE_4096, "Message content after colon: %s", msg_dump);
                log_message("SCFGA_Forward", log_buffer);
            } else {
                log_message("SCFGA_Forward", "No colon found in message, skipping this message");
                continue;
            }

            if(strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0) {
                log_message("SCFGA_Forward", "Message identified as CFGA_DB_DUMP");
                
                char final_msg[OS_SIZE_4096 + 1] = {0};

                snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);
                snprintf(log_buffer, OS_SIZE_4096, "Final message prepared: %s", final_msg);
                log_message("SCFGA_Forward", log_buffer);

                snprintf(log_buffer, OS_SIZE_4096, "Attempting to send message to agent: %s", agent_id);
                log_message("SCFGA_Forward", log_buffer);

                if (send_msg(agent_id, final_msg, -1) >= 0) {
                    rem_inc_send_cfga(agent_id);
                    snprintf(log_buffer, OS_SIZE_4096, "Message sent successfully to agent: %s", agent_id);
                    log_message("SCFGA_Forward", log_buffer);
                } else {
                    snprintf(log_buffer, OS_SIZE_4096, "Failed to send message to agent: %s", agent_id);
                    log_message("SCFGA_Forward", log_buffer);
                }
            } else {
                log_message("SCFGA_Forward", "Message is not a CFGA_DB_DUMP, skipping");
            }
        } else {
            log_message("SCFGA_Forward", "No message received or error in OS_RecvUnix");
        }

        log_message("SCFGA_Forward", "Message processing completed");
    }

    // This part will never be reached due to the infinite loop, but including for completeness
    log_message("SCFGA_Forward", "Function exiting (This should never happen)");
    return NULL;
}