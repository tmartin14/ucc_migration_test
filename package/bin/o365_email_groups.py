import import_declare_test

import os
import os.path as op
import sys
import time
import datetime
import json

import traceback
import requests
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer
from splunktaucclib.modinput_wrapper import base_modinput  as base_mi 
import itertools
import re
import splunk.entity
import urllib

import os
import sys
import time
import datetime
import json





bin_dir = os.path.basename(__file__)

'''
'''
class ModInputo365_email_groups(base_mi.BaseModInput):

    def __init__(self):
        use_single_instance = False
        super(ModInputo365_email_groups, self).__init__("ta_microsoft_o365_email_add_on_for_splunk", "o365_email_groups", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputo365_email_groups, self).get_scheme()
        scheme.title = ("O365 Email Groups")
        scheme.description = ("Go to the add-on\'s configuration UI and configure modular inputs under the Inputs menu.")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(smi.Argument("name", title="Name",
                                         description="",
                                         required_on_create=True))

        """
        For customized inputs, hard code the arguments here to hide argument detail from users.
        For other input types, arguments should be get from input_module. Defining new input types could be easier.
        """
        scheme.add_argument(smi.Argument("tenant", title="Tenant",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("endpoint", title="Endpoint",
                                         description="Select your O365 tenant type",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("global_account", title="Global Account",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "TA_microsoft_o365_email_add_on_for_splunk"

    def validate_input(self, definition):
        """validate the input stanza"""
        interval_in_seconds = int(definition.parameters.get('interval'))
        if (interval_in_seconds < 600):
            raise ValueError("field 'Interval' shouldn't be lower than 10 minutes")
            
    #Function to write events to Splunk
    def _write_events(helper, ew, group_items=None):
        if group_items:
            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=helper.get_sourcetype(),
                data=json.dumps(group_items))
            ew.write_event(event)
    
    #Function to check if returned url is secure
    def is_https(url):
        if url.startswith("https://"):
            return True
        else:
            return False
    
    #Main function for gathering groups.

    def collect_events(helper, ew):
        
        if helper.get_arg('endpoint') == 'worldwide':
            graph_url = 'https://graph.microsoft.com/v1.0'
        elif helper.get_arg('endpoint') == 'gcchigh':
            graph_url = 'https://graph.microsoft.us/v1.0'
            
        access_token = _get_access_token(helper)
    
        headers = {"Authorization": "Bearer " + access_token,
                    "User-Agent": "MicrosoftGraphEmail-Splunk/" + _get_app_version(helper)}
    
        endpoint = "/groups/"
    
        groups_response = helper.send_http_request(graph_url + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 90.0)).json()
        
        group_ids = []
    
        #Routine that iterates through the groups.  Uses the @odata.nextLink values to find the next endpoint to query.
        
        group_ids.append(groups_response['value'])
        
        while ("@odata.nextLink" in groups_response) and (is_https(groups_response["@odata.nextLink"])):
            nextlinkurl = groups_response["@odata.nextLink"]
            groups_response = helper.send_http_request(nextlinkurl, "GET", headers=headers, parameters=None, timeout=(15.0, 90.0)).json()
            groups.append(groups_response['value'])
    
        
        for group in group_ids:
            
            for item in group:
    
                group_items = {}
    
                group_items['group'] = item['mail']
    
                group_id = item['id']
    
                endpoint = "/groups/" + group_id + "/members?$select=mail"
    
                members_response = helper.send_http_request(graph_url + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 90.0)).json()
    
                emails = []
    
                for item in members_response['value']:
                    if item['mail'] is not None:
                        emails.append(item['mail'])
    
                group_items['members'] = emails
    
                _write_events(helper, ew, group_items)

    def get_account_fields(self):
        account_fields = []
        account_fields.append("global_account")
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        return checkbox_fields

    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, 'global_checkbox_param.json')
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, 'r') as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as e:
                self.log_error('Get exception when loading global checkbox parameter names. ' + str(e))
                self.global_checkbox_fields = []
        return self.global_checkbox_fields

if __name__ == "__main__":
    exitcode = ModInputo365_email_groups().run(sys.argv)
    sys.exit(exitcode)
