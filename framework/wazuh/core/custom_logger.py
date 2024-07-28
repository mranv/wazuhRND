import os
from datetime import datetime

def custom_logger(message):
    log_file_path = "/var/ossec/logs/ar_api_operations_flow.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))

def custom_logger_loop(message):
    log_file_path = "/var/ossec/logs/task_loop_log.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
        
def socket_logger(message):
    log_file_path = "/var/ossec/logs/wazuh_socket.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
        
def js_logger(message):
    log_file_path = "/var/ossec/logs/js_core_logs.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
        
def js_wazu_logger(message):
    log_file_path = "/var/ossec/logs/js_wazuh_logs.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
