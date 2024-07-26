# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import os.path
import socket
from struct import pack, unpack

from wazuh.core.exception import WazuhException, WazuhInternalError
from wazuh.core.custom_logger import socket_logger

SOCKET_COMMUNICATION_PROTOCOL_VERSION = 1


class WazuhSocket:
    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __enter__(self):
        return self

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
        except FileNotFoundError:
            raise WazuhInternalError(1013, extra_message=os.path.basename(self.path))
        except ConnectionRefusedError:
            raise WazuhInternalError(1121, extra_message=f"Socket '{os.path.basename(self.path)}' cannot receive "
                                                         "connections")
        except Exception as e:
            raise WazuhException(1013, str(e))

    def close(self):
        self.s.close()

    def send(self, msg_bytes, header_format="<I"):
        
        # logger
        socket_logger(f"send (wazuh_socket) -->> msg_bytes : {msg_bytes}, header_formal : {header_format}")
        
        if not isinstance(msg_bytes, bytes):
            
            # logger
            socket_logger(f"if not isintance {isinstance(msg_bytes, bytes)} and ERROR : {WazuhException(1105)} Type must be bytes")
            
            raise WazuhException(1105, "Type must be bytes")

        try:
            sent = self.s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
            if sent == 0:
                
                # logger
                socket_logger(f"if number of bytes is sende in 0 then ERROR : {WazuhException(1014)}")
                
                raise WazuhException(1014, "Number of sent bytes is 0")
            
            # logger
            socket_logger(f"send (wazuh_socket) return : {sent}")
            
            return sent
        except Exception as e:
            
            # logger
            socket_logger(f"if get any error in the sent the msg to the agnet ERROR : {e} | and wazuh error is : {WazuhException(1014, str(e))}")
            
            raise WazuhException(1014, str(e))

    def receive(self, header_format="<I", header_size=4):
        
        # Logger
        socket_logger(f"receive (wazuh_socket) -->> header_format : {header_format}")
        
        try:
            size = unpack(header_format, self.s.recv(header_size, socket.MSG_WAITALL))[0]
            return self.s.recv(size, socket.MSG_WAITALL)
        except Exception as e:
            raise WazuhException(1014, str(e))