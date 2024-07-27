/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * May 31, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <pthread.h>
#include <shared.h>
#include <os_net/os_net.h>
#include <request_op.h>
#include "remoted.h"
#include "state.h"
#include "wazuh_modules/wmodules.h"

#define COUNTER_LENGTH 64

// Dispatcher theads entry point
<<<<<<< HEAD
static void *req_dispatch(req_node_t *node);
=======
static void * req_dispatch(req_node_t * node);
>>>>>>> v4.7.5

// Increment request pool
static void req_pool_post();

// Wait for available pool. Returns 1 on success or 0 on error
static int req_pool_wait();

<<<<<<< HEAD
static const char *WR_INTERNAL_ERROR = "err Internal error";
static const char *WR_SEND_ERROR = "err Cannot send request";
static const char *WR_ATTEMPT_ERROR = "err Maximum attempts exceeded";
static const char *WR_TIMEOUT_ERROR = "err Response timeout";

static OSHash *req_table;
=======
static const char * WR_INTERNAL_ERROR = "err Internal error";
static const char * WR_SEND_ERROR = "err Cannot send request";
static const char * WR_ATTEMPT_ERROR = "err Maximum attempts exceeded";
static const char * WR_TIMEOUT_ERROR = "err Response timeout";

static OSHash * req_table;
>>>>>>> v4.7.5
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
<<<<<<< HEAD
void req_init()
{
=======
void req_init() {
>>>>>>> v4.7.5
    // Get values from internal options
    request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);
    guess_agent_group = getDefine_Int("remoted", "guess_agent_group", 0, 1);

<<<<<<< HEAD
    if (guess_agent_group && logr.worker_node)
    {
=======
    if (guess_agent_group && logr.worker_node) {
>>>>>>> v4.7.5
        mwarn("The internal option guess_agent_group must be configured on the master node.");
    }

    // Create hash table
<<<<<<< HEAD
    if (req_table = OSHash_Create(), !req_table)
    {
=======
    if (req_table = OSHash_Create(), !req_table) {
>>>>>>> v4.7.5
        merror_exit("At OSHash_Create()");
    }
    OSHash_SetFreeDataPointer(req_table, (void (*)(void *))req_free);
}

// Request sender
<<<<<<< HEAD
void req_sender(int peer, char *buffer, ssize_t length)
{
    int error;
    unsigned int counter = (unsigned int)os_random();
    char counter_s[COUNTER_LENGTH];
    req_node_t *node;
    const char *target = "";
=======
void req_sender(int peer, char *buffer, ssize_t length) {
    int error;
    unsigned int counter = (unsigned int)os_random();
    char counter_s[COUNTER_LENGTH];
    req_node_t * node;
    const char* target = "";
>>>>>>> v4.7.5

    // Set counter, create node and insert into hash table
    snprintf(counter_s, COUNTER_LENGTH, "%x", counter++);
    node = req_create(peer, counter_s, target, buffer, length);

    w_mutex_lock(&mutex_table);
    error = OSHash_Add(req_table, counter_s, node);
    w_mutex_unlock(&mutex_table);

<<<<<<< HEAD
    switch (error)
    {
=======
    switch (error) {
>>>>>>> v4.7.5
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
<<<<<<< HEAD
        if (!req_pool_wait())
        {
=======
        if (!req_pool_wait()) {
>>>>>>> v4.7.5
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

// Dispatcher theads entry point
<<<<<<< HEAD
void *req_dispatch(req_node_t *node)
{
=======
void * req_dispatch(req_node_t * node) {
>>>>>>> v4.7.5
    int attempts;
    int ploff;
    long nsec;
    size_t ldata;
<<<<<<< HEAD
    char *agentid = NULL;
    char *payload = NULL;
    char *_payload;
    char response[REQ_RESPONSE_LENGTH];
    struct timespec timeout;
    struct timeval now = {0, 0};
=======
    char * agentid = NULL;
    char * payload = NULL;
    char * _payload;
    char response[REQ_RESPONSE_LENGTH];
    struct timespec timeout;
    struct timeval now = { 0, 0 };
>>>>>>> v4.7.5
    int protocol = -1;

    mdebug2("Running request dispatcher thread. Counter=%s", node->counter);

    w_mutex_lock(&node->mutex);

    // Get agent ID and payload
<<<<<<< HEAD
    if (_payload = strchr(node->buffer, ' '), !_payload)
    {
=======
    if (_payload = strchr(node->buffer, ' '), !_payload) {
>>>>>>> v4.7.5
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
<<<<<<< HEAD
    if (protocol < 0)
    {
=======
    if (protocol < 0) {
>>>>>>> v4.7.5
        merror(AR_NOAGENT_ERROR, agentid);
        goto cleanup;
    }

<<<<<<< HEAD
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
=======
    for (attempts = 0; attempts < max_attempts; attempts++) {
        // Try to send message
        if (send_msg(agentid, payload, ldata) < 0) {
            merror("Cannot send request to agent '%s'", agentid);
            OS_SendSecureTCP(node->sock, strlen(WR_SEND_ERROR), WR_SEND_ERROR);
            goto cleanup;
        } else {
>>>>>>> v4.7.5
            rem_inc_send_request(agentid);
        }

        // Wait for ACK or response, only in UDP mode
<<<<<<< HEAD
        if (protocol == REMOTED_NET_PROTOCOL_UDP)
        {
=======
        if (protocol == REMOTED_NET_PROTOCOL_UDP) {
>>>>>>> v4.7.5
            gettimeofday(&now, NULL);
            nsec = now.tv_usec * 1000 + rto_msec * 1000000;
            timeout.tv_sec = now.tv_sec + rto_sec + nsec / 1000000000;
            timeout.tv_nsec = nsec % 1000000000;

<<<<<<< HEAD
            if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0 && node->buffer)
            {
                break;
            }
        }
        else
        {
=======
            if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0 && node->buffer) {
                break;
            }
        } else {
>>>>>>> v4.7.5
            // TCP handles ACK by itself
            break;
        }

        mdebug2("Timeout for waiting ACK from agent '%s', resending.", agentid);
    }

<<<<<<< HEAD
    if (attempts == max_attempts)
    {
=======
    if (attempts == max_attempts) {
>>>>>>> v4.7.5
        merror("Couldn't send request to agent '%s': number of attempts exceeded.", agentid);
        OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR);
        goto cleanup;
    }

    // If buffer is ACK, wait for response
<<<<<<< HEAD
    for (attempts = 0; attempts < max_attempts && (!node->buffer || IS_ACK(node->buffer)); attempts++)
    {
=======
    for (attempts = 0; attempts < max_attempts && (!node->buffer || IS_ACK(node->buffer)); attempts++) {
>>>>>>> v4.7.5
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + response_timeout;
        timeout.tv_nsec = now.tv_usec * 1000;

<<<<<<< HEAD
        if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0)
        {
            continue;
        }
        else
        {
=======
        if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0) {
            continue;
        } else {
>>>>>>> v4.7.5
            merror("Response timeout for request counter '%s'", node->counter);
            OS_SendSecureTCP(node->sock, strlen(WR_TIMEOUT_ERROR), WR_TIMEOUT_ERROR);
            goto cleanup;
        }
    }

<<<<<<< HEAD
    if (attempts == max_attempts)
    {
=======
    if (attempts == max_attempts) {
>>>>>>> v4.7.5
        merror("Couldn't get response from agent '%s': number of attempts exceeded.", agentid);
        OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR);
        goto cleanup;
    }

    // Send ACK, only in UDP mode
<<<<<<< HEAD
    if (protocol == REMOTED_NET_PROTOCOL_UDP)
    {
        // Example: #!-req 16 ack
        mdebug2("Sending ack (%s).", node->counter);
        snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", node->counter);
        if (send_msg(agentid, response, -1) >= 0)
        {
=======
    if (protocol == REMOTED_NET_PROTOCOL_UDP) {
        // Example: #!-req 16 ack
        mdebug2("Sending ack (%s).", node->counter);
        snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", node->counter);
        if (send_msg(agentid, response, -1) >= 0) {
>>>>>>> v4.7.5
            rem_inc_send_request(agentid);
        }
    }

    // Send response to local peer
<<<<<<< HEAD
    if (node->buffer)
    {
        mdebug2("Sending response: '%s'", node->buffer);
    }

    if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0)
    {
=======
    if (node->buffer) {
        mdebug2("Sending response: '%s'", node->buffer);
    }

    if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0) {
>>>>>>> v4.7.5
        mwarn("At OS_SendSecureTCP(): %s", strerror(errno));
    }

cleanup:
    w_mutex_unlock(&node->mutex);

    w_mutex_lock(&mutex_table);

<<<<<<< HEAD
    if (!OSHash_Delete(req_table, node->counter))
    {
=======
    if (!OSHash_Delete(req_table, node->counter)) {
>>>>>>> v4.7.5
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
<<<<<<< HEAD
int req_save(const char *counter, const char *buffer, size_t length)
{
    req_node_t *node;
=======
int req_save(const char * counter, const char * buffer, size_t length) {
    req_node_t * node;
>>>>>>> v4.7.5
    int retval = 0;

    mdebug2("Saving '%s:%s'", counter, buffer);

    w_mutex_lock(&mutex_table);

<<<<<<< HEAD
    if (node = OSHash_Get(req_table, counter), node)
    {
        req_update(node, buffer, length);
    }
    else
    {
=======
    if (node = OSHash_Get(req_table, counter), node) {
        req_update(node, buffer, length);
    } else {
>>>>>>> v4.7.5
        mdebug1("Request counter (%s) not found. Duplicated message?", counter);
        retval = -1;
    }

    w_mutex_unlock(&mutex_table);

    return retval;
}

// Increment request pool
<<<<<<< HEAD
void req_pool_post()
{
=======
void req_pool_post() {
>>>>>>> v4.7.5
    w_mutex_lock(&mutex_pool);
    request_pool++;
    w_cond_signal(&pool_available);
    w_mutex_unlock(&mutex_pool);
}

// Wait for available pool. Returns 1 on success or 0 on error
<<<<<<< HEAD
int req_pool_wait()
{
    struct timespec timeout;
    struct timeval now = {0, 0};
=======
int req_pool_wait() {
    struct timespec timeout;
    struct timeval now = { 0, 0 };
>>>>>>> v4.7.5
    int wait_ok = 1;

    w_mutex_lock(&mutex_pool);

<<<<<<< HEAD
    while (!request_pool && wait_ok)
    {
=======
    while (!request_pool && wait_ok) {
>>>>>>> v4.7.5
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + request_timeout;
        timeout.tv_nsec = now.tv_usec * 1000;

<<<<<<< HEAD
        switch (pthread_cond_timedwait(&pool_available, &mutex_pool, &timeout))
        {
=======
        switch (pthread_cond_timedwait(&pool_available, &mutex_pool, &timeout)) {
>>>>>>> v4.7.5
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

<<<<<<< HEAD
    if (request_pool)
    {
=======
    if (request_pool) {
>>>>>>> v4.7.5
        request_pool--;
    }

    w_mutex_unlock(&mutex_pool);

    return wait_ok;
<<<<<<< HEAD
}
=======
}
>>>>>>> v4.7.5
