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

void *AR_Forward(__attribute__((unused)) void *arg)
{
    int arq = 0;
    int ar_location = 0;
    const char *path = ARQUEUE;
    char *msg_to_send;
    char *msg;
    char *ar_agent_id = NULL;
    char *tmp_str = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg_to_send);
    os_calloc(OS_MAXSTR, sizeof(char), msg);

    if ((arq = StartMQ(path, READ, 0)) < 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error creating unix queue: %s", strerror(errno));
        log_message(log_buffer);
        merror_exit(QUEUE_ERROR, path, strerror(errno));
    }

    log_message("AR_Forward started");

    while (1) {
        if (OS_RecvUnix(arq, OS_MAXSTR - 1, msg)) {
            ar_location = 0;

            tmp_str = strchr(msg, ')');
            if (!tmp_str) {
                log_message("Invalid message format: missing ')'");
                continue;
            }
            tmp_str += 2;

            tmp_str = strchr(tmp_str, ']');
            if (!tmp_str) {
                log_message("Invalid message format: missing ']'");
                continue;
            }
            tmp_str += 2;

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
                ar_location |= SPECIFIC_AGENT;
            }
            tmp_str += 2;

            ar_agent_id = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if (!tmp_str) {
                log_message("Invalid message format: missing space after agent ID");
                continue;
            }
            *tmp_str = '\0';
            tmp_str++;

            if (ar_location & NO_AR_MSG) {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s", CONTROL_HEADER, tmp_str);
            } else {
                snprintf(msg_to_send, OS_MAXSTR, "%s%s%s", CONTROL_HEADER, EXECD_HEADER, tmp_str);
            }

            if (ar_location & ALL_AGENTS) {
                char agent_id[KEYSIZE + 1] = "";
                key_lock_read();

                for (unsigned int i = 0; i < keys.keysize; i++) {
                    if (keys.keyentries[i]->rcvd >= (time(0) - logr.global.agents_disconnection_time)) {
                        strncpy(agent_id, keys.keyentries[i]->id, KEYSIZE);
                        key_unlock();
                        if (send_msg(agent_id, msg_to_send, -1) >= 0) {
                            rem_inc_send_ar(agent_id);
                            snprintf(log_buffer, LOG_BUFFER_SIZE, "AR sent to agent %s", agent_id);
                            log_message(log_buffer);
                        } else {
                            snprintf(log_buffer, LOG_BUFFER_SIZE, "Failed to send AR to agent %s", agent_id);
                            log_message(log_buffer);
                        }
                        key_lock_read();
                    }
                }

                key_unlock();
            } else if (ar_location & (REMOTE_AGENT | SPECIFIC_AGENT)) {
                if (send_msg(ar_agent_id, msg_to_send, -1) >= 0) {
                    rem_inc_send_ar(ar_agent_id);
                    snprintf(log_buffer, LOG_BUFFER_SIZE, "AR sent to agent %s", ar_agent_id);
                    log_message(log_buffer);
                } else {
                    snprintf(log_buffer, LOG_BUFFER_SIZE, "Failed to send AR to agent %s", ar_agent_id);
                    log_message(log_buffer);
                }
            }
        }
    }

    // This part will never be reached
    os_free(msg_to_send);
    os_free(msg);
    if (log_fp) {
        fclose(log_fp);
    }
    return NULL;
}