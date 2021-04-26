
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import json


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


