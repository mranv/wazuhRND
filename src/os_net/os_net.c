/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library
 * APIs for many network operations
 */
<<<<<<< HEAD
#include <stdio.h>
#include <time.h>
=======

>>>>>>> v4.7.5
#include <errno.h>
#include "shared.h"
#include "os_net.h"
#include "wazuh_modules/wmodules.h"
<<<<<<< HEAD
#include <stdarg.h>
=======
>>>>>>> v4.7.5

#ifdef WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

#ifdef __MACH__
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

<<<<<<< HEAD
#define LOG_FILE "/var/ossec/logs/network_ops.log"

void log_function(const char *function_name, const char *format, ...)
{
    time_t now = time(NULL);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        fprintf(log_file, "message run | %s | %s", timestamp, function_name);

        if (format)
        {
            va_list args;
            va_start(args, format);
            fprintf(log_file, " | ");
            vfprintf(log_file, format, args);
            va_end(args);
        }

        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

=======
>>>>>>> v4.7.5
/* Prototypes */
static int OS_Bindport(u_int16_t _port, unsigned int _proto, const char *_ip, int ipv6);
static int OS_Connect(u_int16_t _port, unsigned int protocol, const char *_ip, int ipv6, uint32_t network_interface);

/* Unix socket -- not for windows */
#ifndef WIN32

/* UNIX SOCKET */
#ifndef SUN_LEN
<<<<<<< HEAD
#define SUN_LEN(ptr) ((size_t)(((struct sockaddr_un *)0)->sun_path) + strlen((ptr)->sun_path))
=======
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
                     + strlen ((ptr)->sun_path))
>>>>>>> v4.7.5
#endif /* Sun_LEN */

#else /* WIN32 */
/*int ENOBUFS = 0;*/
#ifndef ENOBUFS
#define ENOBUFS 0
#endif

#endif /* WIN32*/

#define RECV_SOCK 0
#define SEND_SOCK 1

<<<<<<< HEAD
/* Bind a specific port */
static int OS_Bindport(u_int16_t _port, unsigned int _proto, const char *_ip, int ipv6)
{
    log_function("OS_Bindport", "port: %u, proto: %u, ip: %s, ipv6: %d", _port, _proto, _ip ? _ip : "NULL", ipv6);
=======

/* Bind a specific port */
static int OS_Bindport(u_int16_t _port, unsigned int _proto, const char *_ip, int ipv6)
{
>>>>>>> v4.7.5
    int ossock;
    struct sockaddr_in server;
    struct sockaddr_in6 server6;

<<<<<<< HEAD
    if (_proto == IPPROTO_UDP)
    {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        {
            return OS_SOCKTERR;
        }
    }
    else if (_proto == IPPROTO_TCP)
    {
        int flag = 1;

        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
=======
    if (_proto == IPPROTO_UDP) {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            return OS_SOCKTERR;
        }
    } else if (_proto == IPPROTO_TCP) {
        int flag = 1;

        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
>>>>>>> v4.7.5
            return (int)(OS_SOCKTERR);
        }

        if (setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR,
<<<<<<< HEAD
                       (char *)&flag, sizeof(flag)) < 0)
        {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }
    else
    {
        return (OS_INVALID);
    }

    if (ipv6)
    {
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons(_port);

        if ((_ip == NULL) || (_ip[0] == '\0'))
        {
            server6.sin6_addr = in6addr_any;
        }
        else
        {
            get_ipv6_numeric(_ip, &server6.sin6_addr);
        }

        if (bind(ossock, (struct sockaddr *)&server6, sizeof(server6)) < 0)
        {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }
    else
    {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(_port);

        if ((_ip == NULL) || (_ip[0] == '\0'))
        {
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else
        {
            get_ipv4_numeric(_ip, &server.sin_addr);
        }

        if (bind(ossock, (struct sockaddr *)&server, sizeof(server)) < 0)
        {
=======
                       (char *)&flag,  sizeof(flag)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    } else {
        return (OS_INVALID);
    }

    if (ipv6) {
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );

        if ((_ip == NULL) || (_ip[0] == '\0')) {
            server6.sin6_addr = in6addr_any;
        } else {
            get_ipv6_numeric(_ip, &server6.sin6_addr);
        }

        if (bind(ossock, (struct sockaddr *) &server6, sizeof(server6)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    } else {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );

        if ((_ip == NULL) || (_ip[0] == '\0')) {
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            get_ipv4_numeric(_ip, &server.sin_addr);
        }

        if (bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0) {
>>>>>>> v4.7.5
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

<<<<<<< HEAD
    if (_proto == IPPROTO_TCP)
    {
        if (listen(ossock, BACKLOG) < 0)
        {
=======
    if (_proto == IPPROTO_TCP) {
        if (listen(ossock, BACKLOG) < 0) {
>>>>>>> v4.7.5
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

    return (ossock);
}

/* Bind a TCP port, using the OS_Bindport */
int OS_Bindporttcp(u_int16_t _port, const char *_ip, int ipv6)
{
<<<<<<< HEAD
    log_function("OS_Bindporttcp", "port: %u, ip: %s, ipv6: %d", _port, _ip ? _ip : "NULL", ipv6);
=======
>>>>>>> v4.7.5
    return (OS_Bindport(_port, IPPROTO_TCP, _ip, ipv6));
}

/* Bind a UDP port, using the OS_Bindport */
int OS_Bindportudp(u_int16_t _port, const char *_ip, int ipv6)
{
<<<<<<< HEAD
    log_function("OS_Bindportudp", NULL);
=======
>>>>>>> v4.7.5
    return (OS_Bindport(_port, IPPROTO_UDP, _ip, ipv6));
}

#ifndef WIN32
/* Bind to a Unix domain, DGRAM sockets while allowing the caller to specify owner and permission bits. */
int OS_BindUnixDomainWithPerms(const char *path, int type, int max_msg_size, uid_t uid, gid_t gid, mode_t mode)
{
<<<<<<< HEAD
    log_function("OS_BindUnixDomainWithPerms", NULL);
=======
>>>>>>> v4.7.5
    struct sockaddr_un n_us;
    int ossock = 0;

    /* Make sure the path isn't there */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

<<<<<<< HEAD
    if ((ossock = socket(AF_UNIX, type, 0)) < 0)
    {
        return (OS_SOCKTERR);
    }

    if (bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0)
    {
=======
    if ((ossock = socket(AF_UNIX, type, 0)) < 0) {
        return (OS_SOCKTERR);
    }

    if (bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Change permissions */
<<<<<<< HEAD
    if (chmod(path, mode) < 0)
    {
=======
    if (chmod(path, mode) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Change owner */
<<<<<<< HEAD
    if (chown(path, uid, gid) < 0)
    {
=======
    if (chown(path, uid, gid) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

<<<<<<< HEAD
    if (type == SOCK_STREAM && listen(ossock, 128) < 0)
    {
=======
    if (type == SOCK_STREAM && listen(ossock, 128) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set socket maximum size
<<<<<<< HEAD
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0)
    {
=======
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set close-on-exec
<<<<<<< HEAD
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1)
    {
=======
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1) {
>>>>>>> v4.7.5
        mwarn("Cannot set close-on-exec flag to socket: %s (%d)", strerror(errno), errno);
    }

    return (ossock);
}

/* Bind to a Unix domain, using DGRAM sockets */
int OS_BindUnixDomain(const char *path, int type, int max_msg_size)
{
<<<<<<< HEAD
    log_function("OS_BindUnixDomain", NULL);
=======
>>>>>>> v4.7.5
    return OS_BindUnixDomainWithPerms(path, type, max_msg_size, getuid(), getgid(), 0660);
}

/* Open a client Unix domain socket
 * ("/tmp/lala-socket",0666));
 */
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size)
{
<<<<<<< HEAD
    log_function("OS_ConnectUnixDomain", NULL);
=======
>>>>>>> v4.7.5
    struct sockaddr_un n_us;

    int ossock = 0;

    memset(&n_us, 0, sizeof(n_us));

    n_us.sun_family = AF_UNIX;

    /* Set up path */
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

<<<<<<< HEAD
    if ((ossock = socket(AF_UNIX, type, 0)) < 0)
    {
=======
    if ((ossock = socket(AF_UNIX, type, 0)) < 0) {
>>>>>>> v4.7.5
        return (OS_SOCKTERR);
    }

    /* Connect to the UNIX domain */
<<<<<<< HEAD
    if (connect(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0)
    {
=======
    if (connect(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set socket maximum size
<<<<<<< HEAD
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0)
    {
=======
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    // Set close-on-exec
<<<<<<< HEAD
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1)
    {
=======
    if (fcntl(ossock, F_SETFD, FD_CLOEXEC) == -1) {
>>>>>>> v4.7.5
        mwarn("Cannot set close-on-exec flag to socket: %s (%d)", strerror(errno), errno);
    }

    return (ossock);
}

int OS_getsocketsize(int ossock)
{
<<<<<<< HEAD
    log_function("OS_getsocketsize", NULL);
=======
>>>>>>> v4.7.5
    int len = 0;
    socklen_t optlen = sizeof(len);

    /* Get current maximum size */
<<<<<<< HEAD
    if (getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1)
    {
=======
    if (getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1) {
>>>>>>> v4.7.5
        return (OS_SOCKTERR);
    }

    return (len);
}

#endif

/* Open a TCP/UDP client socket */
static int OS_Connect(u_int16_t _port, unsigned int protocol, const char *_ip, int ipv6, uint32_t network_interface)
{
<<<<<<< HEAD
    log_function("OS_Connect", NULL);
=======
>>>>>>> v4.7.5
    int ossock;
    int max_msg_size = OS_MAXSTR + 512;
    struct sockaddr_in server;
    struct sockaddr_in6 server6;

<<<<<<< HEAD
    if (protocol == IPPROTO_TCP)
    {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            return (OS_SOCKTERR);
        }
    }
    else if (protocol == IPPROTO_UDP)
    {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        {
            return (OS_SOCKTERR);
        }
    }
    else
    {
        return (OS_INVALID);
    }

    if ((_ip == NULL) || (_ip[0] == '\0'))
    {
=======
    if (protocol == IPPROTO_TCP) {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            return (OS_SOCKTERR);
        }
    } else if (protocol == IPPROTO_UDP) {
        if ((ossock = socket(ipv6 == 1 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            return (OS_SOCKTERR);
        }
    } else {
        return (OS_INVALID);
    }

    if ((_ip == NULL) || (_ip[0] == '\0')) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_INVALID);
    }

<<<<<<< HEAD
    if (ipv6 == 1)
    {
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons(_port);

        if (strncmp(_ip, IPV6_LINK_LOCAL_PREFIX, 20) == 0)
        {
            if (network_interface <= 0)
            {
                minfo("No network interface provided to use with link-local IPv6 address.");
            }
            else
            {
=======
    if (ipv6 == 1) {
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons( _port );

        if (strncmp(_ip, IPV6_LINK_LOCAL_PREFIX, 20) == 0) {
            if (network_interface <= 0) {
                minfo("No network interface provided to use with link-local IPv6 address.");
            } else {
>>>>>>> v4.7.5
                server6.sin6_scope_id = network_interface;
            }
        }

        get_ipv6_numeric(_ip, &server6.sin6_addr);

<<<<<<< HEAD
        if (connect(ossock, (struct sockaddr *)&server6, sizeof(server6)) < 0)
        {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }
    else
    {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(_port);
        get_ipv4_numeric(_ip, &server.sin_addr);

        if (connect(ossock, (struct sockaddr *)&server, sizeof(server)) < 0)
        {
=======
        if (connect(ossock, (struct sockaddr *)&server6, sizeof(server6)) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    } else {
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons( _port );
        get_ipv4_numeric(_ip, &server.sin_addr);

        if (connect(ossock, (struct sockaddr *)&server, sizeof(server)) < 0) {
>>>>>>> v4.7.5
#ifdef WIN32
            int error = WSAGetLastError();
#endif
            OS_CloseSocket(ossock);
#ifdef WIN32
            WSASetLastError(error);
#endif
            return (OS_SOCKTERR);
        }
    }

    // Set socket maximum size
<<<<<<< HEAD
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0)
    {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0)
    {
=======
    if (OS_SetSocketSize(ossock, RECV_SOCK, max_msg_size) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }
    if (OS_SetSocketSize(ossock, SEND_SOCK, max_msg_size) < 0) {
>>>>>>> v4.7.5
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    return (ossock);
}

/* Open a TCP socket */
int OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6, uint32_t network_interface)
{
<<<<<<< HEAD
    int result = OS_Connect(_port, IPPROTO_TCP, _ip, ipv6, network_interface);
    log_function("OS_ConnectTCP", "Result: %d", result);
    return result;
=======
    return (OS_Connect(_port, IPPROTO_TCP, _ip, ipv6, network_interface));
>>>>>>> v4.7.5
}

/* Open a UDP socket */
int OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6, uint32_t network_interface)
{
<<<<<<< HEAD
    log_function("OS_ConnectUDP", NULL);
    int sock = OS_Connect(_port, IPPROTO_UDP, _ip, ipv6, network_interface);

#ifdef HPUX
    if (sock >= 0)
    {
=======
    int sock = OS_Connect(_port, IPPROTO_UDP, _ip, ipv6, network_interface);

#ifdef HPUX
    if (sock >= 0) {
>>>>>>> v4.7.5
        int flags;
        flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    return sock;
}

/* Send a TCP packet (through an open socket) */
int OS_SendTCP(int socket, const char *msg)
{
<<<<<<< HEAD
    size_t msg_length = strlen(msg);
    log_function("OS_SendTCP", "socket: %d, msg length: %zu", socket, msg_length);
    if ((send(socket, msg, msg_length, 0)) <= 0)
    {
=======
    if ((send(socket, msg, strlen(msg), 0)) <= 0) {
>>>>>>> v4.7.5
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a TCP packet of a specific size (through a open socket) */
int OS_SendTCPbySize(int socket, int size, const char *msg)
{
<<<<<<< HEAD
    log_function("OS_SendTCPbySize", "socket: %d, msg length: %d", socket, size);
    if ((send(socket, msg, size, 0)) < size)
    {
=======
    if ((send(socket, msg, size, 0)) < size) {
>>>>>>> v4.7.5
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a UDP packet of a specific size (through an open socket) */
int OS_SendUDPbySize(int socket, int size, const char *msg)
{
<<<<<<< HEAD
    log_function("OS_SendUDPbySize", "socket: %d, msg length: %d", socket, size);
    unsigned int i = 0;

    while ((send(socket, msg, size, 0)) < 0)
    {
        if ((errno != ENOBUFS) || (i >= 5))
        {
=======
    unsigned int i = 0;

    /* Maximum attempts is 5 */
    while ((send(socket, msg, size, 0)) < 0) {
        if ((errno != ENOBUFS) || (i >= 5)) {
>>>>>>> v4.7.5
            return (OS_SOCKTERR);
        }

        i++;
        minfo("Remote socket busy, waiting %d s.", i);
        sleep(i);
    }

    return (0);
}

/* Accept a TCP connection */
int OS_AcceptTCP(int socket, char *srcip, size_t addrsize)
{
<<<<<<< HEAD
    log_function("OS_AcceptTCP", NULL);
=======
>>>>>>> v4.7.5
    int clientsocket;
    struct sockaddr_storage _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

<<<<<<< HEAD
    if ((clientsocket = accept(socket, (struct sockaddr *)&_nc,
                               &_ncl)) < 0)
    {
        return (-1);
    }

    switch (_nc.ss_family)
    {
=======
    if ((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                               &_ncl)) < 0) {
        return (-1);
    }

    switch (_nc.ss_family) {
>>>>>>> v4.7.5
    case AF_INET:
        get_ipv4_string(((struct sockaddr_in *)&_nc)->sin_addr, srcip, addrsize - 1);
        break;
    case AF_INET6:
        get_ipv6_string(((struct sockaddr_in6 *)&_nc)->sin6_addr, srcip, addrsize - 1);
        break;
    default:
        close(clientsocket);
        return (-1);
    }

    return (clientsocket);
}

/* Receive a TCP packet (from an open socket) */
char *OS_RecvTCP(int socket, int sizet)
{
    char *ret;

<<<<<<< HEAD
    ret = (char *)calloc((sizet), sizeof(char));
    if (ret == NULL)
    {
        log_function("OS_RecvTCP", "Result: NULL (memory allocation failed)");
        return NULL;
    }

    int recv_size = recv(socket, ret, sizet - 1, 0);
    log_function("OS_RecvTCP", "socket: %d, received length: %d", socket, recv_size);

    if (recv_size <= 0)
    {
        free(ret);
        log_function("OS_RecvTCP", "Result: NULL (recv failed or connection closed)");
        return NULL;
    }

    log_function("OS_RecvTCP", "Result: Success, received %d bytes", recv_size);
    return ret;
=======
    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
        return (NULL);
    }

    if (recv(socket, ret, sizet - 1, 0) <= 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
>>>>>>> v4.7.5
}

/* Receive a TCP packet (from an open socket)
   Returns the number of bytes received,
   or -1 if an error occurred */
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet)
{
    int retsize;

<<<<<<< HEAD
    if ((retsize = recv(socket, buffer, sizet - 1, 0)) > 0)
    {
        buffer[retsize] = '\0';
    }
    log_function("OS_RecvTCPBuffer", "socket: %d, received length: %d", socket, retsize);
=======
    if ((retsize = recv(socket, buffer, sizet - 1, 0)) > 0) {
        buffer[retsize] = '\0';
    }
>>>>>>> v4.7.5
    return (retsize);
}

/* Receive a UDP packet */
char *OS_RecvUDP(int socket, int sizet)
{
    char *ret;
    int recv_b;

<<<<<<< HEAD
    ret = (char *)calloc((sizet), sizeof(char));
    if (ret == NULL)
    {
=======
    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
>>>>>>> v4.7.5
        return (NULL);
    }

    recv_b = recv(socket, ret, sizet - 1, 0);
<<<<<<< HEAD
    log_function("OS_RecvUDP", "socket: %d, received length: %d", socket, recv_b);

    if (recv_b < 0)
    {
=======
    if (recv_b < 0) {
>>>>>>> v4.7.5
        free(ret);
        return (NULL);
    }

    return (ret);
}

/* Receives a message from a connected UDP socket */
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size)
{
    int recv_b;

    buffer[buffer_size] = '\0';

    recv_b = recv(socket, buffer, buffer_size, 0);
<<<<<<< HEAD
    log_function("OS_RecvConnUDP", "socket: %d, received length: %d", socket, recv_b);

    if (recv_b < 0)
    {
=======
    if (recv_b < 0) {
>>>>>>> v4.7.5
        return (0);
    }

    buffer[recv_b] = '\0';

    return (recv_b);
}

#ifndef WIN32
/* Receive a message from a Unix socket */
int OS_RecvUnix(int socket, int sizet, char *ret)
{
    struct sockaddr_un n_us;
    socklen_t us_l = sizeof(n_us);
    ssize_t recvd;
    ret[sizet] = '\0';

    if ((recvd = recvfrom(socket, ret, sizet - 1, 0,
<<<<<<< HEAD
                          (struct sockaddr *)&n_us, &us_l)) < 0)
    {
=======
                          (struct sockaddr *)&n_us, &us_l)) < 0) {
>>>>>>> v4.7.5
        return (0);
    }

    ret[recvd] = '\0';
<<<<<<< HEAD
    log_function("OS_RecvUnix", "socket: %d, received length: %zd", socket, recvd);
=======
>>>>>>> v4.7.5
    return ((int)recvd);
}

/* Send a message using a Unix socket
 * Returns the OS_SOCKETERR if it fails
 */
int OS_SendUnix(int socket, const char *msg, int size)
{
<<<<<<< HEAD
    // Set correct size if not present.
    if (size == 0)
    {
        size = strlen(msg) + 1;
    }

    log_function("OS_SendUnix", "socket: %d, msg length: %d", socket, size);

    int sentBytes = send(socket, msg, size, 0);

    log_function("OS_SendUnix", "socket: %d, msg length: %d, sent bytes: %d, errno: %d", socket, size, sentBytes, errno);

    // Check sent bytes with size to be sent
    if (sentBytes < size)
    {

        if (errno == ENOBUFS)
        {
=======
    if (size == 0) {
        size = strlen(msg) + 1;
    }

    if (send(socket, msg, size, 0) < size) {
        if (errno == ENOBUFS) {
>>>>>>> v4.7.5
            return (OS_SOCKBUSY);
        }

        return (OS_SOCKTERR);
    }

    return (OS_SUCCESS);
}
<<<<<<< HEAD

=======
>>>>>>> v4.7.5
#endif

/*
 * Retrieve the IP of a host
 */
char *OS_GetHost(const char *host, unsigned int attempts)
{
<<<<<<< HEAD
    log_function("OS_GetHost", NULL);
=======
>>>>>>> v4.7.5
    unsigned int i = 0;
    int status = 0;
    char *ip = NULL;
    struct addrinfo *addr, *p;

<<<<<<< HEAD
    if (host == NULL)
    {
        return (NULL);
    }

    while (i <= attempts)
    {
        if (status = getaddrinfo(host, NULL, NULL, &addr), status)
        {
=======
    if (host == NULL) {
        return (NULL);
    }

    while (i <= attempts) {
        if (status = getaddrinfo(host, NULL, NULL, &addr), status) {
>>>>>>> v4.7.5
            sleep(1);
            i++;
            continue;
        }

<<<<<<< HEAD
        for (p = addr; p != NULL; p = p->ai_next)
        {
            if (p->ai_family == AF_INET)
            {
                os_calloc(IPSIZE + 1, sizeof(char), ip);
                get_ipv4_string(((struct sockaddr_in *)p->ai_addr)->sin_addr, ip, IPSIZE);
                break;
            }
            else if (p->ai_family == AF_INET6)
            {
=======
        for(p = addr; p != NULL; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                os_calloc(IPSIZE + 1, sizeof(char), ip);
                get_ipv4_string(((struct sockaddr_in *)p->ai_addr)->sin_addr, ip, IPSIZE);
                break;
            } else if (p->ai_family == AF_INET6) {
>>>>>>> v4.7.5
                os_calloc(IPSIZE + 1, sizeof(char), ip);
                get_ipv6_string(((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, ip, IPSIZE);
                break;
            }
        }

        freeaddrinfo(addr);

        return ip;
    }

    return NULL;
}

int OS_CloseSocket(int socket)
{
<<<<<<< HEAD
    log_function("OS_CloseSocket", NULL);
=======
>>>>>>> v4.7.5
#ifdef WIN32
    return (closesocket(socket));
#else
    return (close(socket));
#endif /* WIN32 */
}

int OS_SetKeepalive(int socket)
{
<<<<<<< HEAD
    log_function("OS_SetKeepalive", NULL);
=======
>>>>>>> v4.7.5
    int keepalive = 1;
    return setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
}

// Set keepalive parameters for a socket
void OS_SetKeepalive_Options(__attribute__((unused)) int socket, int idle, int intvl, int cnt)
{
<<<<<<< HEAD
    log_function("OS_SetKeepalive_Options", NULL);
    if (cnt > 0)
    {
#if !defined(sun) && !defined(WIN32) && !defined(OpenBSD)
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, (void *)&cnt, sizeof(cnt)) < 0)
        {
=======
    if (cnt > 0) {
#if !defined(sun) && !defined(WIN32) && !defined(OpenBSD)
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, (void *)&cnt, sizeof(cnt)) < 0) {
>>>>>>> v4.7.5
            merror("OS_SetKeepalive_Options(TCP_KEEPCNT) failed with error '%s'", strerror(errno));
        }
#else
        mwarn("Cannot set up keepalive count parameter: unsupported platform.");
#endif
    }

<<<<<<< HEAD
    if (idle > 0)
    {
=======
    if (idle > 0) {
>>>>>>> v4.7.5
#ifdef sun
#ifdef TCP_KEEPALIVE_THRESHOLD
        idle *= 1000;

<<<<<<< HEAD
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD, (void *)&idle, sizeof(idle)) < 0)
        {
=======
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD, (void *)&idle, sizeof(idle)) < 0) {
>>>>>>> v4.7.5
            merror("OS_SetKeepalive_Options(TCP_KEEPALIVE_THRESHOLD) failed with error '%s'", strerror(errno));
        }
#else
        mwarn("Cannot set up keepalive idle parameter: unsupported platform.");
#endif
#elif !defined(WIN32) && !defined(OpenBSD)
<<<<<<< HEAD
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(idle)) < 0)
        {
=======
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(idle)) < 0) {
>>>>>>> v4.7.5
            merror("OS_SetKeepalive_Options(SO_KEEPIDLE) failed with error '%s'", strerror(errno));
        }
#else
        mwarn("Cannot set up keepalive idle parameter: unsupported platform.");
#endif
    }

<<<<<<< HEAD
    if (intvl > 0)
    {
=======
    if (intvl > 0) {
>>>>>>> v4.7.5
#ifdef sun
#ifdef TCP_KEEPALIVE_ABORT_THRESHOLD
        intvl *= 1000;

<<<<<<< HEAD
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD, (void *)&intvl, sizeof(intvl)) < 0)
        {
=======
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD, (void *)&intvl, sizeof(intvl)) < 0) {
>>>>>>> v4.7.5
            merror("OS_SetKeepalive_Options(TCP_KEEPALIVE_ABORT_THRESHOLD) failed with error '%s'", strerror(errno));
        }
#else
        mwarn("Cannot set up keepalive interval parameter: unsupported platform.");
#endif
#elif !defined(WIN32) && !defined(OpenBSD)
<<<<<<< HEAD
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&intvl, sizeof(intvl)) < 0)
        {
=======
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&intvl, sizeof(intvl)) < 0) {
>>>>>>> v4.7.5
            merror("OS_SetKeepalive_Options(TCP_KEEPINTVL) failed with error '%s'", strerror(errno));
        }
#else
        mwarn("Cannot set up keepalive interval parameter: unsupported platform.");
#endif
    }
}

int OS_SetRecvTimeout(int socket, long seconds, long useconds)
{
<<<<<<< HEAD
    log_function("OS_SetRecvTimeout", NULL);
=======
>>>>>>> v4.7.5
#ifdef WIN32
    DWORD ms = seconds * 1000 + useconds / 1000;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const void *)&ms, sizeof(ms));
#else
<<<<<<< HEAD
    struct timeval tv = {seconds, useconds};
=======
    struct timeval tv = { seconds, useconds };
>>>>>>> v4.7.5
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv));
#endif
}

int OS_SetSendTimeout(int socket, int seconds)
{
<<<<<<< HEAD
    log_function("OS_SetSendTimeout", NULL);
=======
>>>>>>> v4.7.5
#ifdef WIN32
    DWORD ms = seconds * 1000;
    return setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const void *)&ms, sizeof(ms));
#else
<<<<<<< HEAD
    struct timeval tv = {seconds, 0};
=======
    struct timeval tv = { seconds, 0 };
>>>>>>> v4.7.5
    return setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(tv));
#endif
}

// Send secure TCP message

<<<<<<< HEAD
int OS_SendSecureTCP(int sock, uint32_t size, const void *msg)
{
    log_function("OS_SendSecureTCP", "socket: %d, msg length: %u", sock, size);
    int retval = OS_SOCKTERR;
    void *buffer = NULL;
    size_t bufsz = size + sizeof(uint32_t);

    if (sock < 0)
    {
        log_function("OS_SendSecureTCP", "Result: %d (Invalid socket)", retval);
=======
int OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    int retval = OS_SOCKTERR;
    void* buffer = NULL;
    size_t bufsz = size + sizeof(uint32_t);

    if (sock < 0) {
>>>>>>> v4.7.5
        return retval;
    }

    os_malloc(bufsz, buffer);
    *(uint32_t *)buffer = wnet_order(size);
    memcpy(buffer + sizeof(uint32_t), msg, size);
    errno = 0;
    retval = send(sock, buffer, bufsz, 0) == (ssize_t)bufsz ? 0 : OS_SOCKTERR;
<<<<<<< HEAD

    if (retval == OS_SOCKTERR)
    {
        log_function("OS_SendSecureTCP", "Result: %d (Send failed, errno: %d)", retval, errno);
    }
    else
    {
        log_function("OS_SendSecureTCP", "Result: %d (Success)", retval);
    }

=======
>>>>>>> v4.7.5
    free(buffer);
    return retval;
}

<<<<<<< HEAD
=======

>>>>>>> v4.7.5
/* Receive secure TCP message
 * This function reads a header containing message size as 4-byte little-endian unsigned integer.
 * Return recvval on success or OS_SOCKTERR on error.
 */
<<<<<<< HEAD
int OS_RecvSecureTCP(int sock, char *ret, uint32_t size)
{
=======
int OS_RecvSecureTCP(int sock, char * ret, uint32_t size) {
>>>>>>> v4.7.5
    ssize_t recvval, recvb;
    uint32_t msgsize;

    /* Get header */
    recvval = os_recv_waitall(sock, &msgsize, sizeof(msgsize));

<<<<<<< HEAD
    switch (recvval)
    {
    case -1:
        return recvval;
        break;

    case 0:
        return recvval;
        break;
=======
    switch(recvval) {
        case -1:
            return recvval;
            break;

        case 0:
            return recvval;
            break;
>>>>>>> v4.7.5
    }

    msgsize = wnet_order(msgsize);

<<<<<<< HEAD
    if (msgsize > size)
    {
=======
    if(msgsize > size){
>>>>>>> v4.7.5
        /* Error: the payload length is too long */
        return OS_SOCKTERR;
    }

    /* Get payload */
    recvb = os_recv_waitall(sock, ret, msgsize);

    /* Terminate string if there is space left */
<<<<<<< HEAD
    if (recvb == (int32_t)msgsize && msgsize < size)
    {
        ret[msgsize] = '\0';
    }

    log_function("OS_RecvSecureTCP", "socket: %d, received length: %zd", sock, recvb);
=======

    if (recvb == (int32_t) msgsize && msgsize < size) {
        ret[msgsize] = '\0';
    }

>>>>>>> v4.7.5
    return recvb;
}

// Byte ordering

<<<<<<< HEAD
uint32_t wnet_order(uint32_t value)
{
    log_function("wnet_order", NULL);
=======
uint32_t wnet_order(uint32_t value) {
>>>>>>> v4.7.5
#if defined(__sparc__) || defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(OS_BIG_ENDIAN)
    return (value >> 24) | (value << 24) | ((value & 0xFF0000) >> 8) | ((value & 0xFF00) << 8);
#else
    return value;
#endif
}

<<<<<<< HEAD
uint32_t wnet_order_big(uint32_t value)
{
    log_function("wnet_order_big", NULL);
=======

uint32_t wnet_order_big(uint32_t value) {
>>>>>>> v4.7.5
#if defined(__sparc__) || defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(OS_BIG_ENDIAN)
    return value;
#else
    return (value >> 24) | (value << 24) | ((value & 0xFF0000) >> 8) | ((value & 0xFF00) << 8);
#endif
}

/* Set the maximum buffer size for the socket */
<<<<<<< HEAD
int OS_SetSocketSize(int sock, int mode, int max_msg_size)
{
    log_function("OS_SetSocketSize", "sock: %d, mode: %d, max_msg_size: %d", sock, mode, max_msg_size);
    int len;
    socklen_t optlen = sizeof(len);

    if (mode == RECV_SOCK)
    {
        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void *)&len, &optlen) == -1)
        {
=======
int OS_SetSocketSize(int sock, int mode, int max_msg_size) {

    int len;
    socklen_t optlen = sizeof(len);

    if (mode == RECV_SOCK) {

        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void *)&len, &optlen) == -1) {
>>>>>>> v4.7.5
            len = 0;
        }

        /* Set maximum message size */
<<<<<<< HEAD
        if (len < max_msg_size)
        {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const void *)&len, optlen) < 0)
            {
                log_function("OS_SetSocketSize", "Result: -1 (setsockopt failed for RECV_SOCK)");
                return -1;
            }
        }
    }
    else if (mode == SEND_SOCK)
    {
        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (void *)&len, &optlen) == -1)
        {
=======
        if (len < max_msg_size) {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const void *)&len, optlen) < 0) {
                return -1;
            }
        }

    } else if (mode == SEND_SOCK) {

        /* Get current maximum size */
        if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (void *)&len, &optlen) == -1) {
>>>>>>> v4.7.5
            len = 0;
        }

        /* Set maximum message size */
<<<<<<< HEAD
        if (len < max_msg_size)
        {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const void *)&len, optlen) < 0)
            {
                log_function("OS_SetSocketSize", "Result: -1 (setsockopt failed for SEND_SOCK)");
=======
        if (len < max_msg_size) {
            len = max_msg_size;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const void *)&len, optlen) < 0) {
>>>>>>> v4.7.5
                return -1;
            }
        }
    }

<<<<<<< HEAD
    log_function("OS_SetSocketSize", "Result: 0 (Success)");
    return 0;
}

/* Send secure TCP Cluster message */
int OS_SendSecureTCPCluster(int sock, const void *command, const void *payload, size_t length)
{
    log_function("OS_SendSecureTCPCluster", "socket: %d, command length: %zu, payload length: %zu", sock, strlen(command), length);
    const unsigned COMMAND_SIZE = 12;
    const unsigned HEADER_SIZE = 8;
    const unsigned MAX_PAYLOAD_SIZE = 1000000;
    int retval;
    char *buffer = NULL;
=======
    return 0;
}


/* Send secure TCP Cluster message */
int OS_SendSecureTCPCluster(int sock, const void * command, const void * payload, size_t length) {
    const unsigned COMMAND_SIZE = 12;
    const unsigned HEADER_SIZE =  8;
    const unsigned MAX_PAYLOAD_SIZE = 1000000;
    int retval;
    char * buffer = NULL;
>>>>>>> v4.7.5
    uint32_t counter = (uint32_t)os_random();
    size_t cmd_length = 0;
    size_t buffer_size = 0;

<<<<<<< HEAD
    if (!command)
    {
=======
    if(!command){
>>>>>>> v4.7.5
        merror("Empty command, not sending message to cluster");
        return -1;
    }

<<<<<<< HEAD
    if (length > MAX_PAYLOAD_SIZE)
    {
=======
    if (length > MAX_PAYLOAD_SIZE) {
>>>>>>> v4.7.5
        merror("Data of length %u exceeds maximum allowed %u", (unsigned)length, MAX_PAYLOAD_SIZE);
        return -1;
    }

    cmd_length = strlen(command);

<<<<<<< HEAD
    if (cmd_length > COMMAND_SIZE)
    {
=======
    if(cmd_length > COMMAND_SIZE){
>>>>>>> v4.7.5
        merror("Command of length %u exceeds maximum allowed %u", (unsigned)cmd_length, COMMAND_SIZE);
        return -1;
    }

<<<<<<< HEAD
=======
    // Cluster message: [counter:4][length:4][command:12][payload]
>>>>>>> v4.7.5
    buffer_size = HEADER_SIZE + COMMAND_SIZE + length;
    os_malloc(buffer_size, buffer);
    *(uint32_t *)buffer = wnet_order_big(counter);
    *(uint32_t *)(buffer + 4) = wnet_order_big(length);
    memcpy(buffer + HEADER_SIZE, command, cmd_length);
    buffer[HEADER_SIZE + cmd_length] = ' ';
    memset(buffer + HEADER_SIZE + cmd_length + 1, '-', COMMAND_SIZE - cmd_length - 1);
    memcpy(buffer + HEADER_SIZE + COMMAND_SIZE, payload, length);

    retval = send(sock, buffer, buffer_size, 0) == (ssize_t)buffer_size ? 0 : OS_SOCKTERR;

    free(buffer);
    return retval;
}

<<<<<<< HEAD
/* Receive secure TCP Cluster message */
int OS_RecvSecureClusterTCP(int sock, char *ret, size_t length)
{
=======

/* Receive secure TCP Cluster message */
int OS_RecvSecureClusterTCP(int sock, char * ret, size_t length) {
>>>>>>> v4.7.5
    int recvval;
    const unsigned CMD_SIZE = 12;
    const uint32_t HEADER_SIZE = 8 + CMD_SIZE;
    uint32_t size = 0;
    char buffer[HEADER_SIZE];

    recvval = os_recv_waitall(sock, buffer, HEADER_SIZE);

<<<<<<< HEAD
    switch (recvval)
    {
    case -1:
        return recvval;

    case 0:
        return recvval;

    default:
        if ((uint32_t)recvval != HEADER_SIZE)
        {
            return -1;
        }
    }

    size = wnet_order_big(*(uint32_t *)(buffer + 4));
    if (size > length)
    {
=======
    switch(recvval){
        case -1:
            return recvval;

        case 0:
            return recvval;

        default:
            if ((uint32_t)recvval != HEADER_SIZE) {
                return -1;
            }
    }

    size = wnet_order_big(*(uint32_t*)(buffer + 4));
    if (size > length) {
>>>>>>> v4.7.5
        mwarn("Cluster message size (%u) exceeds buffer length (%u)", (unsigned)size, (unsigned)length);
        return -1;
    }

    /* Read the payload */
    int recv_size = os_recv_waitall(sock, ret, size);

<<<<<<< HEAD
    log_function("OS_RecvSecureClusterTCP", "socket: %d, received length: %d", sock, recv_size);

    if (strncmp(buffer + 8, "err --------", CMD_SIZE) == 0)
    {
=======
    if (strncmp(buffer+8, "err --------", CMD_SIZE) == 0) {
>>>>>>> v4.7.5
        return -2;
    }

    return recv_size;
}

/* Receive a message from a stream socket, full message (MSG_WAITALL)
 * Returns size on success.
 * Returns -1 on socket error.
 * Returns 0 on socket disconnected or timeout.
 */
<<<<<<< HEAD
ssize_t os_recv_waitall(int sock, void *buf, size_t size)
{
    size_t offset;
    ssize_t recvb;

    for (offset = 0; offset < size; offset += recvb)
    {
        recvb = recv(sock, buf + offset, size - offset, 0);

        if (recvb <= 0)
        {
=======
ssize_t os_recv_waitall(int sock, void * buf, size_t size) {
    size_t offset;
    ssize_t recvb;

    for (offset = 0; offset < size; offset += recvb) {
        recvb = recv(sock, buf + offset, size - offset, 0);

        if (recvb <= 0) {
>>>>>>> v4.7.5
            return recvb;
        }
    }

<<<<<<< HEAD
    log_function("os_recv_waitall", "socket: %d, received length: %zu", sock, offset);
=======
>>>>>>> v4.7.5
    return offset;
}

// Wrapper for select()
<<<<<<< HEAD
int wnet_select(int sock, int timeout)
{
    log_function("wnet_select", NULL);
    fd_set fdset;
    struct timeval fdtimeout = {timeout, 0};
=======
int wnet_select(int sock, int timeout) {
    fd_set fdset;
    struct timeval fdtimeout = { timeout, 0 };
>>>>>>> v4.7.5

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    return select(sock + 1, &fdset, NULL, NULL, &fdtimeout);
}

<<<<<<< HEAD
void resolve_hostname(char **hostname, int attempts)
{
    log_function("resolve_hostname", NULL);
=======
void resolve_hostname(char **hostname, int attempts) {
>>>>>>> v4.7.5
    char *tmp_str;
    char *f_ip;

    assert(hostname != NULL);
<<<<<<< HEAD
    if (OS_IsValidIP(*hostname, NULL) == 1)
    {
=======
    if (OS_IsValidIP(*hostname, NULL) == 1) {
>>>>>>> v4.7.5
        return;
    }

    tmp_str = strchr(*hostname, '/');
<<<<<<< HEAD
    if (tmp_str)
    {
        *tmp_str = '\0'; // LCOV_EXCL_LINE
=======
    if (tmp_str) {
        *tmp_str = '\0';   // LCOV_EXCL_LINE
>>>>>>> v4.7.5
    }

    f_ip = OS_GetHost(*hostname, attempts);

    char ip_str[128] = {0};
<<<<<<< HEAD
    if (f_ip)
    {
        snprintf(ip_str, 127, "%s/%s", *hostname, f_ip);
        free(f_ip);
    }
    else
    {
=======
    if (f_ip) {
        snprintf(ip_str, 127, "%s/%s", *hostname, f_ip);
        free(f_ip);
    } else {
>>>>>>> v4.7.5
        snprintf(ip_str, 127, "%s/", *hostname);
    }
    free(*hostname);
    os_strdup(ip_str, *hostname);
}

<<<<<<< HEAD
const char *get_ip_from_resolved_hostname(const char *resolved_hostname)
{
    log_function("get_ip_from_resolved_hostname", NULL);
=======
const char *get_ip_from_resolved_hostname(const char *resolved_hostname){
>>>>>>> v4.7.5
    char *tmp_str;
    assert(resolved_hostname != NULL);

    /* Check if we have a resolved_hostname or an IP */
    tmp_str = strchr(resolved_hostname, '/');

    return tmp_str ? ++tmp_str : resolved_hostname;
}

<<<<<<< HEAD
int external_socket_connect(char *socket_path, int response_timeout)
{
    log_function("external_socket_connect", NULL);
#ifndef WIN32
    int sock = OS_ConnectUnixDomain(socket_path, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0)
    {
        return sock;
    }

    if (OS_SetSendTimeout(sock, 5) < 0)
    {
=======
int external_socket_connect(char *socket_path, int response_timeout) {
#ifndef WIN32
    int sock =  OS_ConnectUnixDomain(socket_path, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        return sock;
    }

    if(OS_SetSendTimeout(sock, 5) < 0) {
>>>>>>> v4.7.5
        close(sock);
        return -1;
    }

<<<<<<< HEAD
    if (OS_SetRecvTimeout(sock, response_timeout, 0) < 0)
    {
=======
    if(OS_SetRecvTimeout(sock, response_timeout, 0) < 0) {
>>>>>>> v4.7.5
        close(sock);
        return -1;
    }

    return sock;
#else
    return -1;
#endif
}

<<<<<<< HEAD
int get_ipv4_numeric(const char *address, struct in_addr *addr)
{
    log_function("get_ipv4_numeric", NULL);
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista())
    {
        typedef INT(WINAPI * inet_pton_t)(INT, PCSTR, PVOID);
        inet_pton_t InetPton = (inet_pton_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_pton");

        if (NULL != InetPton)
        {
            if (InetPton(AF_INET, address, addr) == 1)
            {
                ret = OS_SUCCESS;
            }
        }
        else
        {
            mwarn("It was not possible to convert IPv4 address");
        }
    }
    else
    {
        if ((addr->s_addr = inet_addr(address)) > 0)
        {
=======
int get_ipv4_numeric(const char *address, struct in_addr *addr) {
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista()) {
        typedef INT (WINAPI * inet_pton_t)(INT, PCSTR, PVOID);
        inet_pton_t InetPton = (inet_pton_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_pton");

        if (NULL != InetPton) {
            if (InetPton(AF_INET, address, addr) == 1) {
                ret = OS_SUCCESS;
            }
        } else {
            mwarn("It was not possible to convert IPv4 address");
        }
    } else {
        if ((addr->s_addr = inet_addr(address)) > 0) {
>>>>>>> v4.7.5
            ret = OS_SUCCESS;
        }
    }
#else
<<<<<<< HEAD
    if (inet_pton(AF_INET, address, addr) == 1)
    {
=======
    if (inet_pton(AF_INET, address, addr) == 1) {
>>>>>>> v4.7.5
        ret = OS_SUCCESS;
    }
#endif

    return ret;
}

<<<<<<< HEAD
int get_ipv6_numeric(const char *address, struct in6_addr *addr6)
{
    log_function("get_ipv6_numeric", NULL);
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista())
    {
        typedef INT(WINAPI * inet_pton_t)(INT, PCSTR, PVOID);
        inet_pton_t InetPton = (inet_pton_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_pton");

        if (NULL != InetPton)
        {
            if (InetPton(AF_INET6, address, addr6) == 1)
            {
                ret = OS_SUCCESS;
            }
        }
        else
        {
            mwarn("It was not possible to convert IPv6 address");
        }
    }
    else
    {
        mwarn("IPv6 in Windows XP is not supported");
    }
#else
    if (inet_pton(AF_INET6, address, addr6) == 1)
    {
=======
int get_ipv6_numeric(const char *address, struct in6_addr *addr6) {
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista()) {
        typedef INT (WINAPI * inet_pton_t)(INT, PCSTR, PVOID);
        inet_pton_t InetPton = (inet_pton_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_pton");

        if (NULL != InetPton) {
            if (InetPton(AF_INET6, address, addr6) == 1) {
                ret = OS_SUCCESS;
            }
        } else {
            mwarn("It was not possible to convert IPv6 address");
        }
    } else {
        mwarn("IPv6 in Windows XP is not supported");
    }
#else
    if (inet_pton(AF_INET6, address, addr6) == 1) {
>>>>>>> v4.7.5
        ret = OS_SUCCESS;
    }
#endif

    return ret;
}

<<<<<<< HEAD
int get_ipv4_string(struct in_addr addr, char *address, size_t address_size)
{
    log_function("get_ipv4_string", NULL);
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista())
    {
        typedef PCSTR(WINAPI * inet_ntop_t)(INT, PVOID, PSTR, size_t);
        inet_ntop_t InetNtop = (inet_ntop_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_ntop");

        if (NULL != InetNtop)
        {
            if (InetNtop(AF_INET, &addr, address, address_size))
            {
                ret = OS_SUCCESS;
            }
        }
        else
        {
            mwarn("It was not possible to convert IPv4 address");
        }
    }
    else
    {
        char *aux = inet_ntoa(addr);
        if (aux)
        {
=======
int get_ipv4_string(struct in_addr addr, char *address, size_t address_size) {
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista()) {
        typedef PCSTR (WINAPI * inet_ntop_t)(INT, PVOID, PSTR, size_t);
        inet_ntop_t InetNtop = (inet_ntop_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_ntop");

        if (NULL != InetNtop) {
            if (InetNtop(AF_INET, &addr, address, address_size)) {
                ret = OS_SUCCESS;
            }
        } else {
            mwarn("It was not possible to convert IPv4 address");
        }
    } else {
        char *aux = inet_ntoa(addr);
        if (aux) {
>>>>>>> v4.7.5
            strncpy(address, aux, address_size);
            ret = OS_SUCCESS;
        }
    }
#else
<<<<<<< HEAD
    if (inet_ntop(AF_INET, &addr, address, address_size))
    {
=======
    if (inet_ntop(AF_INET, &addr, address, address_size)) {
>>>>>>> v4.7.5
        ret = OS_SUCCESS;
    }
#endif

    return ret;
}

<<<<<<< HEAD
int get_ipv6_string(struct in6_addr addr6, char *address, size_t address_size)
{
    log_function("get_ipv6_string", NULL);
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista())
    {
        typedef PCSTR(WINAPI * inet_ntop_t)(INT, PVOID, PSTR, size_t);
        inet_ntop_t InetNtop = (inet_ntop_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_ntop");

        if (NULL != InetNtop)
        {
            if (InetNtop(AF_INET6, &addr6, address, address_size))
            {
                ret = OS_SUCCESS;
            }
        }
        else
        {
            mwarn("It was not possible to convert IPv6 address");
        }
    }
    else
    {
        mwarn("IPv6 in Windows XP is not supported");
    }
#else
    if (inet_ntop(AF_INET6, &addr6, address, address_size))
    {
=======
int get_ipv6_string(struct in6_addr addr6, char *address, size_t address_size) {
    int ret = OS_INVALID;

#ifdef WIN32
    if (checkVista()) {
        typedef PCSTR (WINAPI * inet_ntop_t)(INT, PVOID, PSTR, size_t);
        inet_ntop_t InetNtop = (inet_ntop_t)GetProcAddress(GetModuleHandle("ws2_32.dll"), "inet_ntop");

        if (NULL != InetNtop) {
            if (InetNtop(AF_INET6, &addr6, address, address_size)) {
                ret = OS_SUCCESS;
            }
        } else {
            mwarn("It was not possible to convert IPv6 address");
        }
    } else {
        mwarn("IPv6 in Windows XP is not supported");
    }
#else
    if (inet_ntop(AF_INET6, &addr6, address, address_size)) {
>>>>>>> v4.7.5
        ret = OS_SUCCESS;
    }
#endif

<<<<<<< HEAD
    if ((ret == OS_SUCCESS) && !OS_GetIPv4FromIPv6(address, IPSIZE))
    {
=======
    if ((ret == OS_SUCCESS) && !OS_GetIPv4FromIPv6(address, IPSIZE)) {
>>>>>>> v4.7.5
        OS_ExpandIPv6(address, IPSIZE);
    }

    return ret;
}

#ifdef WIN32
#pragma GCC diagnostic pop
<<<<<<< HEAD
#endif
=======
#endif
>>>>>>> v4.7.5
