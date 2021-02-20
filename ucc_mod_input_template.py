 
import import_declare_test
import sys
import json
import os
import time
import datetime
import os.path as op
#####  New
import traceback
import requests
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer
# 2-16
import splunk_resthelper.base_modinput

 
APP_NAME = __file__.split(op.sep)[-3]
CONF_NAME
 
def get_log_level(session_key, logger):
   """
   This function returns the log level for the addon from configuration file.
   :param session_key: session key for particular modular input.
   :return : log level configured in addon.
   """
   try:
       settings_cfm = conf_manager.ConfManager(
           session_key,
           APP_NAME,
           realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))
 
       logging_details = settings_cfm.get_conf(
           CONF_NAME+"_settings").get("logging")
 
       log_level = logging_details.get('loglevel') if (
           logging_details.get('loglevel')) else 'INFO'
       return log_level
 
   except Exception:
       logger.error(
           "Failed to fetch the log details from the configuration taking INFO as default level.")
       return 'INFO'
 
def get_account_details(session_key, account_name, logger):
   """
   This function retrieves account details from addon configuration file.
   :param session_key: session key for particular modular input.
   :param account_name: account name configured in the addon.
   :param logger: provides logger of current input. 
   :return : account details in form of a dictionary.   
   """
   try:
       cfm = conf_manager.ConfManager(
           session_key, APP_NAME, realm='__REST_CREDENTIAL__#{}#configs/conf-{}_account'.format(APP_NAME,CONF_NAME))
       account_conf_file = cfm.get_conf(CONF_NAME + '_account')
       logger.info(f"Fetched configured account {account_name} details.")
       return {
           "username": account_conf_file.get(account_name).get('username'),
           "password": account_conf_file.get(account_name).get('password'),
       }
   except Exception as e:
       logger.error("Failed to fetch account details from configuration. {}".format(
           traceback.format_exc()))
       sys.exit(1)   
   

#response = helper.send_http_request(url, "GET", headers=headers,  parameters=parameters, payload=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
def send_http_request(url, method, headers, parameters, payload, cookies, verify, cert, timeout, use_proxy):
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, data=json.dumps(payload))
        else:
            r = requests.post(url, headers=headers, data=json.dumps(payload))
        
        r.raise_for_status()

    except Exception as e:
        raise e
    return r





class MYEXAMPLETA(smi.Script):
 
    def __init__(self):
        super(MYEXAMPLETA, self).__init__()

SCHEME_LOCATION

    def validate_input(self, definition):
VALIDATION_LOCATION       


    def stream_events(self, inputs, ew):
        meta_configs = self._input_definition.metadata
        session_key = meta_configs['session_key']

        input_items = {}
        input_name = list(inputs.inputs.keys())[0]
        input_items = inputs.inputs[input_name]

        # Generate logger with input name
        _, input_name = (input_name.split('//', 2))
        logger = log.Logs().get_logger('{}_input'.format(APP_NAME))

        # Log level configuration
        log_level = get_log_level(session_key, logger)
        logger.setLevel(log_level)
        logger.debug("Modular input invoked.")      

STREAM_EVENTS_LOCATION

        logger.debug("Modular input completed")



if __name__ == '__main__':
    exit_code = MYEXAMPLETA().run(sys.argv)
    sys.exit(exit_code)

