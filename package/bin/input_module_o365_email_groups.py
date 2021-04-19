# encoding = utf-8

import json
import datetime
import splunk.entity
import urllib
import sys
import re
import itertools


ACCESS_TOKEN = 'access_token'
CURRENT_TOKEN = None
LOG_DIRECTORY_NAME = 'logs'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'

#Obtain access token via oauth2
def _get_access_token(helper):
    
    if helper.get_arg('endpoint') == 'worldwide':
        login_url = 'https://login.microsoftonline.com/'
        graph_url = 'https://graph.microsoft.com/'
    elif helper.get_arg('endpoint') == 'gcchigh':
        login_url = 'https://login.microsoftonline.us/'
        graph_url = 'https://graph.microsoft.us/'
        
    global CURRENT_TOKEN
    if CURRENT_TOKEN is None:
        _data = {
            'client_id': helper.get_arg('global_account')['username'],
            'scope': graph_url + '.default',
            'client_secret': helper.get_arg('global_account')['password'],
            'grant_type': 'client_credentials',
            'Content-Type': 'application/x-www-form-urlencoded'
            }
        _url = login_url + helper.get_arg('tenant') + '/oauth2/v2.0/token'
        if (sys.version_info > (3, 0)):
            access_token = helper.send_http_request(_url, "POST", payload=urllib.parse.urlencode(_data), timeout=(15.0, 15.0)).json()
        else:
            access_token = helper.send_http_request(_url, "POST", payload=urllib.urlencode(_data), timeout=(15.0, 15.0)).json()

        CURRENT_TOKEN = access_token[ACCESS_TOKEN]
        return access_token[ACCESS_TOKEN]

    else:
        return CURRENT_TOKEN

#Returning version of TA
def _get_app_version(helper):
    app_version = ""
    if 'session_key' in helper.context_meta:
        session_key = helper.context_meta["session_key"]
        entity = splunk.entity.getEntity('/configs/conf-app','launcher', namespace=helper.get_app_name(), sessionKey=session_key, owner='nobody')
        app_version = entity.get('version')
    return app_version

#Setting minimum interval in TA to 600 seconds
def validate_input(helper, definition):
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
