# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json

from wazuh.core import common
from wazuh.core.agent import Agent
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.utils import WazuhVersion
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.wazuh_socket import create_wazuh_socket_message
from wazuh.core.custom_logger import custom_logger


def create_message(command: str = '', custom: bool = False, arguments: list = None) -> str:
    
    # logger
    custom_logger(f"create_message (active_response core)")
    custom_logger(f"command: {command} , custom : {custom}, aguments : {arguments}")
    
    """Create the message that will be sent.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
        name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.

    Raises
    ------
    WazuhError(1650)
        If the command is not specified.
    WazuhError(1652)
        If the command is not custom and the command is not one of the available commands.

    Returns
    -------
    str
        Message that will be sent to the socket.
    """
    if not command:
        
        # logger
        custom_logger(f"is not command : {WazuhError(1650)}")
        
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        
        # logger
        custom_logger(f"command is not custom and command is not one of the available commands : {WazuhError(1652)}")
        
        raise WazuhError(1652)

    msg_queue = "!{}".format(command) if custom else command
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

    # logger
    custom_logger(f"create_message (active_response core) return msg_queue : {msg_queue}")

    return msg_queue


def create_json_message(command: str = '', arguments: list = None, alert: dict = None) -> str:
    
    # logger
    custom_logger(f"create_json_message (active_response core)")
    custom_logger(f"command : {command}, arguments : {arguments}, alert : {alert}")
    
    """Create the JSON message that will be sent. Function used when Wazuh agent version is >= 4.2.0.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts by !, then it refers to a script name instead of a command
        name.
    arguments : list
        Command arguments.
    alert : dict
        Alert data that will be sent with the AR command.

    Raises
    ------
    WazuhError(1650)
        If the command is not specified.

    Returns
    -------
    str
        Message that will be sent to the socket.
    """
    if not command:
        
        # logger
        custom_logger(f"if not commmand : {WazuhError(1650)}")
        
        raise WazuhError(1650)

    cluster_enabled = not read_cluster_config()['disabled']
    
    # logger
    custom_logger(f"cluster endbled or not : {cluster_enabled}")
    
    node_name = get_node().get('node') if cluster_enabled else None

    # logger
    custom_logger(f"node_name : {node_name}")
    
    msg_queue = json.dumps(
        create_wazuh_socket_message(origin={'name': node_name, 'module': common.origin_module.get()},
                                    command=command,
                                    parameters={'extra_args': arguments if arguments else [],
                                                'alert': alert if alert else {}}))
    # logger
    custom_logger(f"create_json_message (active_response core) return msg_queue : {msg_queue}")
    
    return msg_queue


def send_ar_message(agent_id: str = '', wq: WazuhQueue = None, command: str = '', arguments: list = None,
                    custom: bool = False, alert: dict = None) -> None:
    
    # logger
    custom_logger(f"send_ar_message (active_response core)")
    custom_logger(f"agent_id : {agent_id}, wq : {wq}, command : {command}, argments : {arguments}, custom : {custom}, alert : {alert}")
    
    """Send the active response message to the agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the msg_queue will be sent to.
    wq : WazuhQueue
        WazuhQueue used for the active response messages.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Raises
    ------
    WazuhError(1707)
        If the agent with ID agent_id is not active.
    WazuhError(1750)
        If active response is disabled in the specified agent.
    """
    # Agent basic information
    agent_info = Agent(agent_id).get_basic_information()
    
    # logger
    custom_logger(f"1. send_ar_message (active responce core) anget Info : {agent_info}")

    # Check if agent is active
    
    # logger
    custom_logger(f"2. anget status : {agent_info['status'].lower()}")
    if agent_info['status'].lower() != 'active':
        
        custom_logger("if agent is not active : {WazuhError(1707)}")
        raise WazuhError(1707)

    # Once we know the agent is active, store version
    agent_version = agent_info['version']

    # logger
    custom_logger(f"3 .send_ar_message (active responce core) agent version : {agent_version}")
    
    # Check if AR is enabled
    agent_conf = Agent(agent_id).get_config('com', 'active-response', agent_version)
    
    # logger
    custom_logger(f"4. checkt if AR is enebled or not : {agent_conf}")
    
    if agent_conf['active-response']['disabled'] == 'yes':
        
        # logger
        custom_logger(f"if active response is disabled : {WazuhError(1750)}")
        
        raise WazuhError(1750)

    # Create classic msg or JSON msg depending on the agent version
    if WazuhVersion(agent_version) >= WazuhVersion(common.AR_LEGACY_VERSION):
        msg_queue = create_json_message(command=command, arguments=arguments, alert=alert)
        
        # logger
        custom_logger(f"5. json msg : {msg_queue}")
         
    else:
        msg_queue = create_message(command=command, arguments=arguments, custom=custom)
        
        # logger
        custom_logger(f"5. classic msg : {msg_queue}")
    
    # logger
    custom_logger(f"6. send_ar_message (active_response core) -- send the msg to wq (wazuh_queue) send_msg_to_agent msg_queue : {msg_queue}")

    wq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=WazuhQueue.AR_TYPE)


def get_commands() -> list:
    
    # logger
    custom_logger(f"get_commands (active_response core)")
    
    """Get the available commands.

    Returns
    -------
    list
        List with the available commands.
    """
    commands = list()
    with open(common.AR_CONF) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)
    # logger
    custom_logger(f"get_commands (active_response core) - commands: {commands}")
    
    return commands


def shell_escape(command: str = '') -> str:
    
    # logger
    custom_logger(f"shell_escape (active_response core)")
    custom_logger(f"command : {command}")
    """Escape some characters in the command before sending it.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a
        command name.

    Returns
    -------
    str
        Command with escape characters.
    """
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    # logger
    custom_logger(f"shell_escape (active_response core) - command: {command}")
    
    return command
