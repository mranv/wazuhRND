#ifndef LOGGER_H
#define LOGGER_H

#define LOG_FILE "/var/ossec/logs/network_ops.log"

void log_function(const char *function_name, const char *format, ...);

#endif /* LOGGER_H */