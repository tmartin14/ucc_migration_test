
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import json

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

