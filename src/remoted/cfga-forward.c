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
#define LOG_BUFFER_SIZE 2048

static FILE *log_fp = NULL;
static char log_buffer[LOG_BUFFER_SIZE];

// Efficient logger function
static void log_message(const char *message) {
    struct timeval tv;
    struct tm *tm_info;

    if (!log_fp) {
        log_fp = fopen(LOG_FILE, "a");
        if (!log_fp) {
            merror("Unable to open log file: %s", LOG_FILE);
            return;
        }
        setbuf(log_fp, NULL);  // Disable buffering
    }

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    fprintf(log_fp, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] %s\n",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
            tv.tv_usec / 1000, message);
}

void *SCFGA_Forward(__attribute__((unused)) void *arg)
{
    int cfgarq = 0;
    char *agent_id;
    const char *path = CFGARQUEUE;
    char msg[OS_SIZE_4096 + 1];

    if ((cfgarq = StartMQ(path, READ, 0)) < 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error creating unix queue: %s", strerror(errno));
        log_message(log_buffer);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    log_message("SCFGA_Forward started");

    while (1) {
        if (OS_RecvUnix(cfgarq, OS_SIZE_4096, msg)) {
            agent_id = msg;
            char *msg_dump = strchr(msg, ':');

            if (msg_dump) {
                *msg_dump++ = '\0';

                if (strncmp(msg_dump, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0) {
                    char final_msg[OS_SIZE_4096 + 1] = {0};
                    snprintf(final_msg, OS_SIZE_4096, "%s%s", CONTROL_HEADER, msg_dump);

                    if (send_msg(agent_id, final_msg, -1) >= 0) {
                        rem_inc_send_cfga(agent_id);
                        snprintf(log_buffer, LOG_BUFFER_SIZE, "Message sent to agent %s", agent_id);
                        log_message(log_buffer);
                    } else {
                        snprintf(log_buffer, LOG_BUFFER_SIZE, "Failed to send message to agent %s", agent_id);
                        log_message(log_buffer);
                    }
                }
            }
        }
    }

    // This part will never be reached
    if (log_fp) {
        fclose(log_fp);
    }
    return NULL;
}