
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
    opt_dynatrace_metric    = helper.get_arg('dynatrace_metric')
    opt_aggregation_type    = helper.get_arg('aggregation_type')
    opt_dynatrace_collection_interval = helper.get_arg('dynatrace_collection_interval')

    headers     = {'Authorization': 'Api-Token {}'.format(opt_dynatrace_api_token),
                    'version':'Splunk TA 1.0.3'}
    api_url     = opt_dynatrace_tenant + '/api/v1/timeseries'
    parameters  = { 'queryMode':'total', 
                    'relativeTime': opt_dynatrace_collection_interval, 
                    'aggregationType': opt_aggregation_type, 
                    'timeseriesId' : opt_dynatrace_metric 
                  }
    hecTime = 0

    response = helper.send_http_request(api_url, "GET", headers=headers,  parameters=parameters, payload=None, cookies=None, verify=verify_ssl, cert=None, timeout=None, use_proxy=True)
    try:
        response.raise_for_status()
    except:
        helper.log_error (response.text)
        return
  

    data = response.json()
    z = json.dumps(data)
    x = json.loads(z)
    
    entityDict = x["result"]["entities"]
    timeseriesId = x["result"]["timeseriesId"]
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
            resultDict.update({"aggregation":aggregationType})
            resultDict.update({"unit":unit})
            resultDict.update({"timeseriesId":timeseriesId})
            
            HECEvent = json.dumps(resultDict, sort_keys=True)
            event = helper.new_event(data=HECEvent, time=hecTime, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
            ew.write_event(event)
            #print str(resultDict) + "\r\n\r\n"
            helper.log_debug(HECEvent)


    #   Save the name of the Dynatrace Server that this data came from
    event = helper.new_event(data='{"dynatrace_server":"' + opt_dynatrace_tenant + '"}', time=hecTime, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    ew.write_event(event)
    
