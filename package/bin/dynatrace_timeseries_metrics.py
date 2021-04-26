
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


'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

class ModInputdynatrace_timeseries_metrics(base_mi.BaseModInput):

    def __init__(self):
        use_single_instance = False
        super(ModInputdynatrace_timeseries_metrics, self).__init__("splunk_ta_dynatrace", "dynatrace_timeseries_metrics", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputdynatrace_timeseries_metrics, self).get_scheme()
        scheme.title = ("Dynatrace Timeseries Metrics")
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
        ''' Updated for Splunk 8 ''' 
        '''SSL Verification'''
        
        
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
        
        opt_dynatrace_api_token           = dynatrace_account_input["password"]
        opt_dynatrace_collection_interval = helper.get_arg('dynatrace_collection_interval')
    
        headers     = {'Authorization': 'Api-Token {}'.format(opt_dynatrace_api_token),
                        'version':'Splunk TA 1.0.3'}
        api_url     = opt_dynatrace_tenant + '/api/v1/timeseries'
        parameters  = { 'queryMode':'total', 
                        'relativeTime': opt_dynatrace_collection_interval, 
                        'aggregationType': '', 
                        'timeseriesId': '' 
                      }
    
        COUNT    = 'COUNT'
        AVERAGE  = 'AVG'
        hecTime  = 0
        
        service_metrics_avg = [ 'com.dynatrace.builtin:app.useractionduration',
                                'com.dynatrace.builtin:service.responsetime',
                                'com.dynatrace.builtin:service.failurerate'
                              ]
        service_metrics_count = [ 'com.dynatrace.builtin:app.apdex',
                            'com.dynatrace.builtin:app.useractionsperminute',
                            'com.dynatrace.builtin:service.requestspermin'
                          ]
        process_metrics = [ 'com.dynatrace.builtin:pgi.cpu.usage',
                            'com.dynatrace.builtin:pgi.mem.usage',
                            'com.dynatrace.builtin:pgi.nic.bytesreceived',
                            'com.dynatrace.builtin:pgi.nic.bytessent',
                            'com.dynatrace.builtin:pgi.suspension',
                            'com.dynatrace.builtin:pgi.workerprocesses'
                          ]
    
        host_metrics =    [ 'com.dynatrace.builtin:host.cpu.idle',
                            'com.dynatrace.builtin:host.cpu.iowait',
                            'com.dynatrace.builtin:host.cpu.other',
                            'com.dynatrace.builtin:host.cpu.steal',
                            'com.dynatrace.builtin:host.cpu.system',
                            'com.dynatrace.builtin:host.cpu.user',
                            'com.dynatrace.builtin:host.mem.used',
                            'com.dynatrace.builtin:host.mem.pagefaults',
                            'com.dynatrace.builtin:host.nic.bytesreceived',
                            'com.dynatrace.builtin:host.nic.bytessent',
                            'com.dynatrace.builtin:host.nic.packetsreceived',
                            'com.dynatrace.builtin:host.nic.packetsreceiveddropped',
                            'com.dynatrace.builtin:host.nic.packetsreceivederrors',
                            'com.dynatrace.builtin:host.nic.packetssentdropped',
                            'com.dynatrace.builtin:host.nic.packetssenterrors',
                            'com.dynatrace.builtin:host.disk.readtime',
                            'com.dynatrace.builtin:host.disk.writetime',
                            'com.dynatrace.builtin:host.disk.freespacepercentage',
                            'com.dynatrace.builtin:host.disk.availablespace',
                            'com.dynatrace.builtin:host.disk.usedspace'
                          ]
    
        synthetic_metrics = [ 'com.dynatrace.builtin:webcheck.availability',
                              'com.dynatrace.builtin:webcheck.performance.actionduration'
                            ]
    
        
        '''
         Make an API Call and format the results into a Splunk Event
        '''
        
        def send_data(contains_aggregate = None):
            response = helper.send_http_request(api_url, "GET", headers=headers,  parameters=parameters, payload=None, cookies=None, verify=verify_ssl, cert=None, timeout=None, use_proxy=True)
            try:
                response.raise_for_status()
            except:
                helper.log_error (response.text)
                return
    
            data = response.json()
            z = json.dumps(data)
            x = json.loads(z)
            
            # Dict to store entity results.
            entityDict = x["result"]["entities"]
            timeseriesId = x["result"]["timeseriesId"]
            if not contains_aggregate:
                aggregationType = x["result"]["aggregationType"]
                unit = x["result"]["unit"]
            
            resultDict = {}
            
            for entityKeyList,results in x["result"]["dataPoints"].items():
                entities = entityKeyList.split(", ")
                
                for entity in entities:
                    entityTypeName,entityId = entity.split("-")
                    entityTypeLabel = entityTypeName.lower() + "Id"
                    resultDict.update({entityTypeLabel:entityId})
                    entityNameLabel = entityTypeName.lower() + "Name"
                    resultDict.update({entityNameLabel:entityDict[entity]})
                    
                for result in results:
                    eventTimeStr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result[0]/1000))
                    hecTime = result[0]/1000
                    resultValue = result[1]
                    resultDict.update({"timestamp":eventTimeStr})
                    resultDict.update({"value":resultValue})
                    resultDict.update({"timeseriesId":timeseriesId})
                    if not contains_aggregate:
                        resultDict.update({"aggregation":aggregationType})
                        resultDict.update({"unit":unit})
                    
                    HECEvent = json.dumps(resultDict, sort_keys=True)
                    event = helper.new_event(data=HECEvent, time=hecTime, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
                    ew.write_event(event)
    
                    helper.log_debug(HECEvent)
            
            return True
    
        
        '''
         Loop Through our array of metrics.  Call the API and insert an event
        '''
        
        for i in service_metrics_avg:
            parameters['aggregationType'] = AVERAGE 
            parameters['timeseriesId'] = i 
            send_data()
        
        for i in service_metrics_count:
            parameters['aggregationType'] = COUNT
            parameters['timeseriesId'] = i
            send_data()
        
        for i in host_metrics:
            parameters['timeseriesId'] = i
            parameters['aggregationType'] = AVERAGE
            send_data()
        
        for i in process_metrics:
            parameters['timeseriesId'] = i
            parameters['aggregationType'] = AVERAGE
            send_data()
        
        for i in synthetic_metrics:
            parameters['timeseriesId'] = i
            if i == 'com.dynatrace.builtin:webcheck.availability':
                #url = build_url(opt_dynatrace_tenant, params, i, opt_dynatrace_api_token)
                del parameters['aggregationType']
                send_data("no aggregate values")
            else:
                parameters['aggregationType'] = AVERAGE
                send_data()
        
        #   Save the name of the Dynatrace Server that this data came from
        event = helper.new_event(data='{"dynatrace_server":"' + opt_dynatrace_tenant + '"}', time=hecTime, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
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
    exitcode = ModInputdynatrace_timeseries_metrics().run(sys.argv)
    sys.exit(exitcode)
