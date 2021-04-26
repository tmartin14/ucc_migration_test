
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



class ModInputdynatrace_problem(base_mi.BaseModInput):

    def __init__(self):
        use_single_instance = False
        super(ModInputdynatrace_problem, self).__init__("splunk_ta_dynatrace", "dynatrace_problem", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputdynatrace_problem, self).get_scheme()
        scheme.title = ("Dynatrace Problem")
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
        scheme.add_argument(smi.Argument("ssl_certificate_verification", title="SSL Certificate Verification",
                                         description="",
                                         required_on_create=False,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "Splunk_TA_Dynatrace"

    def validate_input(helper, definition):
        """Implement your own validation logic to validate the input stanza configurations"""
        # This example accesses the modular input variable
        #dynatrace_tenant = definition.parameters.get('dynatrace_tenant', None)
        #dynatrace_api_token = definition.parameters.get('dynatrace_api_token', None)
        #dynatrace_collection_interval = definition.parameters.get('dynatrace_collection_interval', None)
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
    
        headers     = {'Authorization': 'Api-Token {}'.format(opt_dynatrace_api_token),
                        'version':'Splunk TA 1.0.3'}
        api_url     = opt_dynatrace_tenant + '/api/v1/problem/feed' + '?relativeTime=' + opt_dynatrace_collection_interval    
        # NOTE: problem_url not used anymore
        problem_url = opt_dynatrace_tenant + '/api/v1/problem/details/'
        
        #helper.log_debug("url: " + url)
     
        response = helper.send_http_request(api_url, "GET", headers=headers,  parameters=None, payload=None, cookies=None, verify=verify_ssl, cert=None, timeout=None, use_proxy=True)
        try:
            response.raise_for_status()
        except:
            helper.log_error (response.text)
    
        # check the response status, if the status is not sucessful, raise requests.HTTPError
        r_status = response.status_code
        r_data   = response.json()
        z = json.dumps(r_data)
        x = json.loads(z)
        entityDict = x["result"]["problems"]
        
        for problems in entityDict:
            '''
            #     The following code will retrieve the details for each problem ID
            #        (The volume of data exceeds the value provided.  )
            #
            problem_id = problems['id']
            api_url = problem_url + problem_id 
            response = helper.send_http_request(api_url, "GET", headers=headers,  parameters=None, payload=None, cookies=None, verify=None, cert=None, timeout=None, use_proxy=True)
            try:
                response.raise_for_status()
            except:
                helper.log_error (response.text)
            
            problem_details = response.json()
            
            problems["details"] = problem_details['result']
            '''
            
            HECEvent = json.dumps(problems, sort_keys=True)
            event = helper.new_event(data=HECEvent, source=None, index=None, sourcetype=None)
            ew.write_event(event)
            
                #   Save the name of the Dynatrace Server that this data came from
        event = helper.new_event(data='{"dynatrace_server":"' + opt_dynatrace_tenant + '"}', index=None, source=None, sourcetype=None)
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
    exitcode = ModInputdynatrace_problem().run(sys.argv)
    sys.exit(exitcode)
