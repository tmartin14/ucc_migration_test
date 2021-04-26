
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import json



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
    
    
  