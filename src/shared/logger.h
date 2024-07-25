#ifndef SHARED_LOGGER
#define SHARED_LOGGER

#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

#define LOG_FILE "/var/ossec/logs/network_ops.log"

void log_function(const char *function_name, const char *format, ...);

#endif