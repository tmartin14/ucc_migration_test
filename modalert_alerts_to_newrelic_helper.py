
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters and prints them to the log
    account = helper.get_param("account")
    helper.log_info("account={}".format(account))

    apikey = helper.get_param("apikey")
    helper.log_info("apikey={}".format(apikey))

    eventtype = helper.get_param("eventtype")
    helper.log_info("eventtype={}".format(eventtype))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action alerts_to_newrelic started.")

    # TODO: Implement your alert action logic here
    import json
    
    acctId = helper.get_param("account")
    insertKey = helper.get_param("apikey")
    eventType = helper.get_param("eventtype")
    insightsURL = 'https://insights-collector.newrelic.com/v1/accounts/' + acctId + '/events'
    
    
    # If the value is a number represented as a String, change it to a Number for Insights.
    # if the key is in the 'dontChange' list, then leave those as Strings
    dontChangeList = ['HTTPCode', 'httpcode']
    
    def parseFields(event):
        event_out = {}
        for key in event:
            if key in dontChangeList:
                event_out[key] = event[key]
            else:
                try:
                    result_float = float(event[key])
                    event_out[key] = result_float
                except ValueError:
                    event_out[key] = event[key]
        return event_out


    events = helper.get_events()

    results_out = []
    for event in events:
        event['eventType'] = eventType
        results_out.append(parseFields(event))

    #helper.log_info("everything={}".format(results_out))

    payload = json.dumps(results_out)
    headers = {  'X-Insert-Key': '{}'.format(insertKey), 'Content-Type': 'application/json'  }
    response = helper.send_http_request(insightsURL, "POST", parameters=None, payload=payload, headers=headers, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    
    #helper.log_info("result={}".format(response.text))  
    response.raise_for_status()
    
    return response.status_code
