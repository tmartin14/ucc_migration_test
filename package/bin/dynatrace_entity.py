
import os
import sys
import time
import datetime
import json





bin_dir = os.path.basename(__file__)

'''
'''
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
import requests

# encoding = utf-8




class ModInputdynatrace_entity(base_mi.BaseModInput):

    def __init__(self):
        use_single_instance = False
        super(ModInputdynatrace_entity, self).__init__("splunk_ta_dynatrace", "dynatrace_entity", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputdynatrace_entity, self).get_scheme()
        scheme.title = ("Dynatrace Entity")
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
        scheme.add_argument(smi.Argument("dynatrace_account", title="Dynatrace Account",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("dynatrace_collection_interval", title="Dynatrace Collection Interval",
                                         description="Relative timeframe passed to Dynatrace API. Timeframe of data to be collected at each polling interval.",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("entity_endpoints", title="Entity Endpoints",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("ssl_certificate_verification", title="SSL Certificate Verification",
                                         description="",
                                         required_on_create=False,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "Splunk_TA_Dynatrace"

    def validate_input(helper, definition):
        pass
    

    def collect_events(helper, ew):
    
        '''
        Verify SSL Certificate
        '''
        
        ssl_certificate = helper.get_arg('ssl_certificate_verification')
        
        if ssl_certificate == True:
            verify_ssl = True
        else:
            verify_ssl = False
    
        '''
        Force HTTPS
        '''
        
        dynatrace_account_input = helper.get_arg("dynatrace_account")
        dynatrace_tenant_input = dynatrace_account_input["username"]
        
        if dynatrace_tenant_input.find('https://') == 0:
            opt_dynatrace_tenant = dynatrace_tenant_input
        elif dynatrace_tenant_input.find('http://') == 0:
            opt_dynatrace_tenant = dynatrace_tenant_input.replace('http://', 'https://')
        else: 
            opt_dynatrace_tenant = 'https://' + dynatrace_tenant_input
        
        '''
        '''
        
        opt_dynatrace_api_token = dynatrace_account_input["password"]
        opt_dynatrace_collection_interval = helper.get_arg('dynatrace_collection_interval')
        opt_dynatrace_entity_endpoints = helper.get_arg('entity_endpoints')
        
        time_offset  = int(opt_dynatrace_collection_interval) * 1000
        current_time = int(round(time.time() * 1000))
        offset_time  = current_time - time_offset
    
    
        headers     = {'Authorization': 'Api-Token {}'.format(opt_dynatrace_api_token),
                        'version':'Splunk TA 1.0.3'}
        api_url     = opt_dynatrace_tenant + '/api/v1/entity/'
        parameters  = { 'startTimestamp':str(offset_time), 
                         'endTimestamp': str(current_time)
                       }
    
        for endpoint in opt_dynatrace_entity_endpoints:
            response = helper.send_http_request(api_url + endpoint , "GET", headers=headers,  parameters=parameters, payload=None, cookies=None, verify=verify_ssl, cert=None, timeout=None, use_proxy=True)
            try:
                response.raise_for_status()
            except:
                helper.log_error (response.text)
                return
        
            data = response.json()
            z = json.dumps(data)
            x = json.loads(z)
    
            for entity in x:
                eventLastSeenTime = entity["lastSeenTimestamp"]/1000
                entity.update({"timestamp":eventLastSeenTime})
                entity['endpoint'] = endpoint
                serialized = json.dumps(entity, sort_keys=True)
                event = helper.new_event(data=serialized, time=eventLastSeenTime, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
                ew.write_event(event)
    
        #   Save the name of the Dynatrace Server that this data came from
        event = helper.new_event(data='{"dynatrace_server":"' + opt_dynatrace_tenant + '"}', host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
        ew.write_event(event)
        
        
      

    def get_account_fields(self):
        account_fields = []
        account_fields.append("dynatrace_account")
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        checkbox_fields.append("ssl_certificate_verification")
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
    exitcode = ModInputdynatrace_entity().run(sys.argv)
    sys.exit(exitcode)
