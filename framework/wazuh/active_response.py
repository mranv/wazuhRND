# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import active_response, common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources
from wazuh.core.custom_logger import custom_logger #,custom_logger_loop
# import asyncio


''' comment the code for backup  '''

# async def process_agent(agent_id, system_agents, wq, result, command, arguments, custom, alert):
#     try:
#         # Simulating a delay for demonstration purposes
#         await asyncio.sleep(2)
        
#         if agent_id not in system_agents:
#             custom_logger(f"if agent id not in the system_agents : {WazuhResourceNotFound(1701)}")
#             raise WazuhResourceNotFound(1701)
        
#         if (agent_id == "000"):
#             custom_logger(f"if the agent is the Manager (000) : {WazuhError(1703)}")
#             raise WazuhError(1703)
        
#         active_response.send_ar_message(agent_id, wq, command, arguments, custom, alert)
#         result.affected_items.append(agent_id)
#         result.total_affected_items += 1
#     except WazuhException as e:
#         custom_logger(f"send the AR message agent id : {agent_id}, Error : {e}")
#         result.add_failed_item(id_=agent_id, error=e)
#     except asyncio.TimeoutError:
#         custom_logger(f"TimeoutError: processing agent id : {agent_id} took too long")
#         result.add_failed_item(id_=agent_id, error="TimeoutError: processing took too long")

# async def run_command_async(agent_list, command, arguments, custom, alert, result, system_agents, wq):
#     tasks = []
#     for agent_id in agent_list:
#         # Set a timeout of 9 seconds for each agent processing
#         tasks.append(asyncio.wait_for(process_agent(agent_id, system_agents, wq, result, command, arguments, custom, alert), timeout=9))
#         custom_logger_loop(f"task in for loop : {tasks} ")
#     await asyncio.gather(*tasks, return_exceptions=True)

# @expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
#                   post_proc_kwargs={'exclude_codes': [1701, 1703]})
# def run_command(agent_list: list = None, command: str = '', arguments: list = None, custom: bool = False,
#                 alert: dict = None) -> AffectedItemsWazuhResult:
    
#     # logger
#     custom_logger(f"run_command (active_response wazuh)")
#     custom_logger(f"agent_list : {agent_list}, command : {command}, arguments : {arguments}, custom : {custom}")
    
#     result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
#                                       some_msg='AR command was not sent to some agents',
#                                       none_msg='AR command was not sent to any agent'
#                                       )
#     if agent_list:
#         with WazuhQueue(common.AR_SOCKET) as wq:
#             system_agents = get_agents_info()
            
#             loop = asyncio.new_event_loop()
#             asyncio.set_event_loop(loop)
#             loop.run_until_complete(run_command_async(agent_list, command, arguments, custom, alert, result, system_agents, wq))
#             result.affected_items.sort(key=int)
    
#     # logger
#     custom_logger(f"run_command (active_response wazuh) return result : {result}")
    
#     return result




@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def run_command(agent_list: list = None, command: str = '', arguments: list = None, custom: bool = False,
                alert: dict = None) -> AffectedItemsWazuhResult:
    
    # logger
    custom_logger(f"run_command (active_response wazuh)")
    custom_logger(f"agent_list : {agent_list}, command : {command}, arguments : {arguments}, custom : {custom}")
    """Run AR command in a specific agent.

    Parameters
    ----------
    agent_list : list
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )
    if agent_list:
        with WazuhQueue(common.AR_SOCKET) as wq:
            system_agents = get_agents_info()
            for agent_id in agent_list:
                try:
                    if agent_id not in system_agents:
                        custom_logger(f"if agent id not in the system_agents : {WazuhResourceNotFound(1701)}")
                        raise WazuhResourceNotFound(1701)
                    if agent_id == "000":
                        custom_logger(f"if the agent is the Manager (000) : {WazuhError(1703)}")
                        raise WazuhError(1703)
                    active_response.send_ar_message(agent_id, wq, command, arguments, custom, alert)
                    result.affected_items.append(agent_id)
                    result.total_affected_items += 1
                except WazuhException as e:
                    custom_logger(f"send the AR message agent id : {agent_id}, Error : {e}")
                    result.add_failed_item(id_=agent_id, error=e)
            result.affected_items.sort(key=int)

    # logger
    custom_logger(f"run_command (active_response wazuh) return result : {result}")

    return result