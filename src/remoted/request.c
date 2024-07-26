#include <pthread.h>
#include <shared.h>
#include <os_net/os_net.h>
#include <request_op.h>
#include <stdio.h>
#include <stdlib.h>
#include "remoted.h"
#include "state.h"
#include "wazuh_modules/wmodules.h"

#define COUNTER_LENGTH 64
#define LOG_FILE "/var/ossec/logs/requestcfile.log"
#define LOG_MSG(format, ...)                                                                \
    do                                                                                      \
    {                                                                                       \
        FILE *log_fp = fopen(LOG_FILE, "a");                                                \
        if (log_fp)                                                                         \
        {                                                                                   \
            fprintf(log_fp, "[%s:%d] " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            fclose(log_fp);                                                                 \
        }                                                                                   \
    } while (0)

// Dispatcher threads entry point
static void *req_dispatch(req_node_t *node);

// Increment request pool
static void req_pool_post();

// Wait for available pool. Returns 1 on success or 0 on error
static int req_pool_wait();

static const char *WR_INTERNAL_ERROR = "err Internal error";
static const char *WR_SEND_ERROR = "err Cannot send request";
static const char *WR_ATTEMPT_ERROR = "err Maximum attempts exceeded";
static const char *WR_TIMEOUT_ERROR = "err Response timeout";

static OSHash *req_table;
static pthread_mutex_t mutex_table = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_pool = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_available = PTHREAD_COND_INITIALIZER;

int rto_sec;
int rto_msec;
int max_attempts;
int request_pool;
int request_timeout;
int response_timeout;
int guess_agent_group;

// Initialize request module
void req_init()
{
    LOG_MSG("Initializing request module");

    // Get values from internal options
    request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);
    guess_agent_group = getDefine_Int("remoted", "guess_agent_group", 0, 1);

    LOG_MSG("Configuration: request_pool=%d, request_timeout=%d, response_timeout=%d, rto_sec=%d, rto_msec=%d, max_attempts=%d, guess_agent_group=%d",
            request_pool, request_timeout, response_timeout, rto_sec, rto_msec, max_attempts, guess_agent_group);

    if (guess_agent_group && logr.worker_node)
    {
        mwarn("The internal option guess_agent_group must be configured on the master node.");
    }

    // Create hash table
    if (req_table = OSHash_Create(), !req_table)
    {
        LOG_MSG("Failed to create hash table");
        merror_exit("At OSHash_Create()");
    }
    OSHash_SetFreeDataPointer(req_table, (void (*)(void *))req_free);
}

// Request sender
void req_sender(int peer, char *buffer, ssize_t length)
{
    LOG_MSG("Sending request: peer=%d, length=%zd", peer, length);
    int error;
    unsigned int counter = (unsigned int)os_random();
    char counter_s[COUNTER_LENGTH];
    req_node_t *node;
    const char *target = "";

    // Set counter, create node and insert into hash table
    snprintf(counter_s, COUNTER_LENGTH, "%x", counter++);
    node = req_create(peer, counter_s, target, buffer, length);

    w_mutex_lock(&mutex_table);
    error = OSHash_Add(req_table, counter_s, node);
    w_mutex_unlock(&mutex_table);

    LOG_MSG("Request added to hash table: counter=%s, error=%d", counter_s, error);

    switch (error)
    {
    case 0:
        merror("At OSHash_Add()");
        req_free(node);
        break;

    case 1:
        merror("At OSHash_Add(): Duplicated counter.");
        req_free(node);
        break;

    case 2:
        // Wait for thread pool
        if (!req_pool_wait())
        {
            break;
        }

        // Run thread
        w_create_thread(req_dispatch, node);

        // Do not close peer
        return;
    }

    // If we reached here, there was an error
    OS_SendSecureTCP(peer, strlen(WR_INTERNAL_ERROR), WR_INTERNAL_ERROR);
    close(peer);

    return;
}

// Dispatcher threads entry point
void *req_dispatch(req_node_t *node)
{
    LOG_MSG("Dispatching request: counter=%s", node->counter);
    int attempts;
    int ploff;
    long nsec;
    size_t ldata;
    char *agentid = NULL;
    char *payload = NULL;
    char *_payload;
    char response[REQ_RESPONSE_LENGTH];
    struct timespec timeout;
    struct timeval now = {0, 0};
    int protocol = -1;

    mdebug2("Running request dispatcher thread. Counter=%s", node->counter);

    w_mutex_lock(&node->mutex);

    // Get agent ID and payload
    if (_payload = strchr(node->buffer, ' '), !_payload)
    {
        merror("Request has no agent id.");
        goto cleanup;
    }

    *_payload = '\0';
    _payload++;

    os_strdup(node->buffer, agentid);
    ldata = strlen(CONTROL_HEADER) + strlen(HC_REQUEST) + strlen(node->counter) + 1 + node->length - (_payload - node->buffer);
    os_malloc(ldata + 1, payload);
    ploff = snprintf(payload, ldata, CONTROL_HEADER HC_REQUEST "%s ", node->counter);
    memcpy(payload + ploff, _payload, ldata - ploff);
    payload[ldata] = '\0';

    // Drain payload
    os_free(node->buffer);
    node->length = 0;

    mdebug2("Sending request: '%s'", payload);

    // The following code is used to get the protocol that the client is using in order to answer accordingly
    key_lock_read();
    protocol = w_get_agent_net_protocol_from_keystore(&keys, agentid);
    key_unlock();
    if (protocol < 0)
    {
        merror(AR_NOAGENT_ERROR, agentid);
        goto cleanup;
    }

    for (attempts = 0; attempts < max_attempts; attempts++)
    {
        // Try to send message
        if (send_msg(agentid, payload, ldata) < 0)
        {
            merror("Cannot send request to agent '%s'", agentid);
            OS_SendSecureTCP(node->sock, strlen(WR_SEND_ERROR), WR_SEND_ERROR);
            goto cleanup;
        }
        else
        {
            rem_inc_send_request(agentid);
        }

        // Wait for ACK or response, only in UDP mode
        if (protocol == REMOTED_NET_PROTOCOL_UDP)
        {
            gettimeofday(&now, NULL);
            nsec = now.tv_usec * 1000 + rto_msec * 1000000;
            timeout.tv_sec = now.tv_sec + rto_sec + nsec / 1000000000;
            timeout.tv_nsec = nsec % 1000000000;

            if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0 && node->buffer)
            {
                break;
            }
        }
        else
        {
            // TCP handles ACK by itself
            break;
        }

        mdebug2("Timeout for waiting ACK from agent '%s', resending.", agentid);
    }

    if (attempts == max_attempts)
    {
        merror("Couldn't send request to agent '%s': number of attempts exceeded.", agentid);
        OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR);
        goto cleanup;
    }

    // If buffer is ACK, wait for response
    for (attempts = 0; attempts < max_attempts && (!node->buffer || IS_ACK(node->buffer)); attempts++)
    {
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + response_timeout;
        timeout.tv_nsec = now.tv_usec * 1000;

        if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0)
        {
            continue;
        }
        else
        {
            merror("Response timeout for request counter '%s'", node->counter);
            OS_SendSecureTCP(node->sock, strlen(WR_TIMEOUT_ERROR), WR_TIMEOUT_ERROR);
            goto cleanup;
        }
    }

    if (attempts == max_attempts)
    {
        merror("Couldn't get response from agent '%s': number of attempts exceeded.", agentid);
        OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR);
        goto cleanup;
    }

    // Send ACK, only in UDP mode
    if (protocol == REMOTED_NET_PROTOCOL_UDP)
    {
        // Example: #!-req 16 ack
        mdebug2("Sending ack (%s).", node->counter);
        snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", node->counter);
        if (send_msg(agentid, response, -1) >= 0)
        {
            rem_inc_send_request(agentid);
        }
    }

    // Send response to local peer
    if (node->buffer)
    {
        mdebug2("Sending response: '%s'", node->buffer);
    }

    if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0)
    {
        mwarn("At OS_SendSecureTCP(): %s", strerror(errno));
    }

cleanup:
    w_mutex_unlock(&node->mutex);

    w_mutex_lock(&mutex_table);

    if (!OSHash_Delete(req_table, node->counter))
    {
        merror("At OSHash_Delete(): no such key.");
    }

    w_mutex_unlock(&mutex_table);

    req_free(node);
    os_free(agentid);
    os_free(payload);
    req_pool_post();

    return NULL;
}

// Save request data (ack or response). Return 0 on success or -1 on error.
int req_save(const char *counter, const char *buffer, size_t length)
{
    LOG_MSG("Saving request: counter=%s, buffer=%s, length=%zu", counter, buffer, length);
    req_node_t *node;
    int retval = 0;

    mdebug2("Saving '%s:%s'", counter, buffer);

    w_mutex_lock(&mutex_table);

    if (node = OSHash_Get(req_table, counter), node)
    {
        req_update(node, buffer, length);
    }
    else
    {
        mdebug1("Request counter (%s) not found. Duplicated message?", counter);
        retval = -1;
    }

    w_mutex_unlock(&mutex_table);

    return retval;
}

// Increment request pool
void req_pool_post()
{
    LOG_MSG("Posting request pool: current pool=%d", request_pool);
    w_mutex_lock(&mutex_pool);
    request_pool++;
    w_cond_signal(&pool_available);
    w_mutex_unlock(&mutex_pool);
}

// Wait for available pool. Returns 1 on success or 0 on error
int req_pool_wait()
{
    LOG_MSG("Waiting for request pool: current pool=%d", request_pool);
    struct timespec timeout;
    struct timeval now = {0, 0};
    int wait_ok = 1;

    w_mutex_lock(&mutex_pool);

    while (!request_pool && wait_ok)
    {
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + request_timeout;
        timeout.tv_nsec = now.tv_usec * 1000;

        switch (pthread_cond_timedwait(&pool_available, &mutex_pool, &timeout))
        {
        case 0:
            break;

        case ETIMEDOUT:
            merror("Request pool is full. Rejecting request.");
            wait_ok = 0;
            break;

        default:
            merror("At w_cond_timedwait(): %s", strerror(errno));
            wait_ok = 0;
            break;
        }
    }

    if (request_pool)
    {
        request_pool--;
    }

    w_mutex_unlock(&mutex_pool);

    return wait_ok;
}
