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
from io import StringIO
from oletools.olevba import VBA_Parser, VBA_Scanner
from zipfile import ZipFile
import base64
import email
import hashlib
import io
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
class ModInputo365_email(base_mi.BaseModInput):

    def __init__(self):
        use_single_instance = False
        super(ModInputo365_email, self).__init__("ta_microsoft_o365_email_add_on_for_splunk", "o365_email", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputo365_email, self).get_scheme()
        scheme.title = ("O365 Email")
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
        scheme.add_argument(smi.Argument("audit_email_account", title="Audit Email Account",
                                         description="Please enter the audit email configured in the O365 mail flow rule",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("tenant", title="Tenant ID",
                                         description="Please enter the Tenant ID from the Azure App registration process",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("endpoint", title="Endpoint",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_attachment_info", title="Get Attachment Info",
                                         description="Gathers basic attachment info (name, type, size, hash, etc).",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("file_hash_algorithm", title="File Hash Algorithm",
                                         description="Used for attachment and zip file hashing.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("macro_analysis", title="Macro Analysis",
                                         description="Detects and analyses macros within Office document formats.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("read_zip_files", title="Read Zip Files",
                                         description="Attempts to read file names and file hashes from within zip files.  Requires Get Attachment Info to be selected.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("extract_body_iocs", title="Extract Body IOCs",
                                         description="Attempts to extract IOCs from email bodies. (URLs, domains, ipv4, ipv6, hashes, etc).",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_body", title="Get Body",
                                         description="Retrieves the whole message body for emails and any emails that are attached.WARNING- POTENTIALLY LARGE INGEST IF ENABLED",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_body_preview", title="Get Body Preview",
                                         description="Only retrieves the first 255 characters in the email body",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_message_path", title="Get Message Path",
                                         description="Gathers all MTA hops the message traversed",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_auth_results", title="Get Auth Results",
                                         description="Gathers authentication results headers",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_spf_results", title="Get SPF Results",
                                         description="Gathers SPF results from the headers",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_dkim_signature", title="Get DKIM Signature",
                                         description="Gathers DKIM signature results from the headers",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_x_headers", title="Get X Headers",
                                         description="Gathers all X-Headers from the headers",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_internet_headers", title="Get Internet Headers",
                                         description="Retrieves All Internet Headers",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("get_tracking_pixel", title="Get Tracking Pixel",
                                         description="Basic tracking pixel detection",
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
        if (interval_in_seconds < 60 or interval_in_seconds > 120):
            raise ValueError("field 'Interval' should be between 60 and 120")
    
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
                helper.log_info("Getting Auth Token")
                access_token = helper.send_http_request(_url, "POST", payload=urllib.parse.urlencode(_data), timeout=(15.0, 30.0)).json()
            else:
                helper.log_info("Getting Auth Token")
                access_token = helper.send_http_request(_url, "POST", payload=urllib.urlencode(_data), timeout=(15.0, 30.0)).json()
    
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
    
    #Function to write events to Splunk
    def _write_events(helper, ew, messages=None):
        if messages:
            for message in messages:
                event = helper.new_event(
                    source=helper.get_input_type(),
                    index=helper.get_output_index(),
                    sourcetype=helper.get_sourcetype(),
                    data=json.dumps(message))
                ew.write_event(event)
    
    #Purging of messages after ingest to Splunk.  This is using the recoverableitemspurges folder, which emulates a hard delete.
    def _purge_messages(helper, messages):
        
        if helper.get_arg('endpoint') == 'worldwide':
            graph_url = 'https://graph.microsoft.com/v1.0'
        elif helper.get_arg('endpoint') == 'gcchigh':
            graph_url = 'https://graph.microsoft.us/v1.0'
            
        access_token = _get_access_token(helper)
    
        headers = {"Authorization": "Bearer " + access_token,
                    "Content-type": "application/json"}
    
        #Turns off read receipts on messages in the compliance mailbox.  Doesn't affect read receipts to original user.
        _disable_rr = {
                     "singleValueExtendedProperties": [
                         {
                         "id": "Boolean 0x0C06",
                         "value": "false"
                         },
                         {
                         "id": "Boolean 0x0029",
                         "value": "false"
                         }
                     ]
                     }
    
        #Purge folder
        _data = {
                "destinationId": "recoverableitemspurges"
                }
    
        for message in messages:
            for item in message:
    
                #if read receipt is found remove it to keep from sending a deletion notice to the sender
                if item["isReadReceiptRequested"]:
                    helper.log_info("Removing read receipts before deletion")
                    remove_receipt_response = helper.send_http_request(graph_url + "/users/" + helper.get_arg('audit_email_account') + "/messages/" + item["id"], "PATCH", headers=headers, payload=_disable_rr, timeout=(15.0, 30.0))
    
                #actual purging of messages takes place here via a move to the purge folder
                helper.log_info("Purging message")
                response = helper.send_http_request(graph_url + "/users/" + helper.get_arg('audit_email_account') + "/messages/" + item["id"] + "/move", "POST", headers=headers, payload=_data, timeout=(15.0, 30.0))
    
    #URL IOC extraction function.
    def extract_urls(helper,data):
        urls = itertools.chain(
            url_re.finditer(data)
        )
        for url in urls:
            url = url.group(0)
            yield url
    
    #Domain IOC extraction function.
    def extract_domains(helper,data):
        domains = itertools.chain(
            domain_re.finditer(data)
        )
        for domain in domains:
            domain = domain.group(0)
            yield domain
    
    #IPv4 IOC extraction function.
    def extract_ipv4(helper,data):
        ipv4s = itertools.chain(
            ipv4_re.finditer(data)
        )
        for ip in ipv4s:
            ip = ip.group(0)
            yield ip
    
    #IPv6 IOC extraction function.
    def extract_ipv6(helper,data):
        ipv6s = itertools.chain(
            ipv6_re.finditer(data)
        )
        for ip in ipv6s:
            ip = ip.group(0)
            yield ip
    
    #Function to check if returned url is secure
    def is_https(url):
        if url.startswith("https://"):
            return True
        else:
            return False
    
    #Main function for gathering emails.

    def collect_events(helper, ew):
        
        if helper.get_arg('endpoint') == 'worldwide':
            graph_url = 'https://graph.microsoft.com/v1.0'
        elif helper.get_arg('endpoint') == 'gcchigh':
            graph_url = 'https://graph.microsoft.us/v1.0'
            
        access_token = _get_access_token(helper)
    
        headers = {"Authorization": "Bearer " + access_token,
                    "User-Agent": "MicrosoftGraphEmail-Splunk/" + _get_app_version(helper)}
    
        #defining email account to retrieve messages from
        endpoint = "/users/" + helper.get_arg('audit_email_account')
    
        #defining inbox id to retrieve messages from
        endpoint += "/mailFolders/inbox/messages/"
    
        #expanding property id 0x0E08 to gather message size, and then expanding attachments to get fileattachment type contentBytes
        endpoint += "?$expand=SingleValueExtendedProperties($filter=Id eq 'LONG 0x0E08'),attachments"
            
        #selecting which fields to retrieve from emails
        endpoint += "&$select=receivedDateTime,subject,sender,from,hasAttachments,internetMessageId,toRecipients,ccRecipients,bccRecipients,replyTo,internetMessageHeaders,body,bodyPreview,isReadReceiptRequested,isDeliveryReceiptRequested"
    
        #defining how many messages to retrieve from each page
        endpoint += "&$top=490"
    
        #getting the oldest messages first
        endpoint += "&$orderby=receivedDateTime"
    
        #getting the total count of messages in each round
        endpoint += "&$count=true"
    
        try:
            messages_response = helper.send_http_request(graph_url + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 90.0)).json()
            helper.log_info("Retrieving a max of 490 messages from a total of " + str(messages_response['@odata.count']))
        except:
            helper.log_info("Potential API timeout, will try again")
    
        messages = []
        
        #Routine that iterates through the messages.  Uses the @odata.nextLink values to find the next endpoint to query.
        
        messages.append(messages_response['value'])
    
        #Calculate how many pages of 490 messages we'll attempt based on the interval value.  Helps to keep requests within API limits.
        
        interval_in_seconds = int(helper.get_arg('interval'))
    
        url_count_limit = (interval_in_seconds//30) - 1
    
        if url_count_limit>0:
    
            url_count = 0
        
            while ("@odata.nextLink" in messages_response) and (is_https(messages_response["@odata.nextLink"])):
                if url_count < url_count_limit:
                    nextlinkurl = messages_response["@odata.nextLink"]
                    try:
                        messages_response = helper.send_http_request(nextlinkurl, "GET", headers=headers, parameters=None, timeout=(15.0, 90.0)).json()
                        helper.log_info("Retrieving another round of up to 490 messages")
                        url_count += 1
                        messages.append(messages_response['value'])
                    except:
                        helper.log_info("Potential API timeout, will try again")
                else:
                    helper.log_debug("Protecting API limits, breaking out")
                    break
    
        message_data = []
        
        for message in messages:
            
            for item in message:
    
                message_items = {}
                
                if item['hasAttachments']:
                    message_items['hasAttachments'] = item['hasAttachments']
    
                if item['internetMessageId']:  
                    message_items['internetMessageId'] = item['internetMessageId']
    
                if item['id']:
                    message_items['id'] = item['id']
    
                if item['receivedDateTime']:
                    message_items['DateTime'] = item['receivedDateTime']
    
                if item['toRecipients']:
                    message_items['to'] = list(map(lambda x : x['emailAddress']['address'], item['toRecipients']))
    
                if item['ccRecipients']:
                    message_items['ccRecipients'] = list(map(lambda x : x['emailAddress']['address'], item['ccRecipients']))
    
                if item['bccRecipients']:
                    message_items['bccRecipients'] = list(map(lambda x : x['emailAddress']['address'], item['bccRecipients']))
    
                try:
                    message_items['from'] = item['from']['emailAddress']['address']
                except:
                    message_items['from'] = 'null'
    
                try:
                    message_items['replyTo'] = item['replyTo']['emailAddress']['address']
                except:
                    message_items['replyTo'] = 'null'
    
                try:
                    message_items['sender'] = item['sender']['emailAddress']['address']
                except:
                    message_items['sender'] = 'null'
    
                try:
                    message_items['subject'] = item['subject']
                except:
                    message_items['subject'] = 'null'
                
                message_body = item['body']['content']
    
                body_preview = item['bodyPreview']
                
                attachments = item['attachments']
    
                single_value_properties = item['singleValueExtendedProperties']
    
                #determine if the message contains internet message headers
                if 'internetMessageHeaders' in item:
                    internet_message_headers = item['internetMessageHeaders']
    
                    #message path calculations
                    message_path = []
                    path_item = {}
                
                    for item in internet_message_headers:
                        if item['name'] == "Received":
                            path_item=item
                            message_path.append(path_item)
                
                    src_line = str(message_path[-1])
                    dest_line = str(message_path[0])
                
                    re_by = re.compile(r'(?<=\bby\s)(\S+)')
                    re_from = re.compile(r'(?<=\bfrom\s)(\S+)')
                
                    dest = re_by.search(dest_line)
                
                    if re_from.search(src_line):
                        src = re_from.search(src_line)
                    elif re_by.search(src_line):
                        src = re_by.search(src_line)
    
                    try:
                        message_items['src'] = str(src[0])
                    except:
                        message_items['src'] = "no source mta found"
    
                    try:
                        message_items['dest'] = str(dest[0])
                    except:
                        message_items['dest'] = "no destination mta found"
    
                    #ingest all internet message headers
                    if helper.get_arg('get_internet_headers'):
                        message_items['Internet-Headers'] = internet_message_headers
    
                    #ingest full mta path
                    if helper.get_arg('get_message_path'):
                        message_items['message_path'] = list(map(lambda x : x['value'], message_path))
      
                    #ingest x-headers
                    if helper.get_arg('get_x_headers'):
                    
                        x_headers = []
                        x_header_item = {}
                    
                        for item in internet_message_headers:
                            if "X-" in item['name']:
                                x_header_item=item
                                x_headers.append(x_header_item)
                                message_items['X-Headers'] = x_headers
    
                    #ingest auth results
                    if helper.get_arg('get_auth_results'):
                    
                        auth_results = []
                        auth_results_item = {}
                    
                        for item in internet_message_headers:
                            if "Authentication-Results" in item['name']:
                                auth_results_item=item
                                auth_results.append(auth_results_item)
                                message_items['Authentication-Results'] = list(map(lambda x : x['value'], auth_results))
    
                    #ingest spf results
                    if helper.get_arg('get_spf_results'):
                    
                        spf_results = []
                        spf_results_item = {}
                    
                        for item in internet_message_headers:
                            if "Received-SPF" in item['name']:
                                spf_results_item=item
                                spf_results.append(spf_results_item)
                                message_items['Received-SPF'] = list(map(lambda x : x['value'], spf_results))
                            
                    #ingest dkim signature results
                    if helper.get_arg('get_dkim_signature'):
                    
                        dkim_sig = []
                        dkim_sig_item = {}
                    
                        for item in internet_message_headers:
                            if "DKIM-Signature" in item['name']:
                                dkim_sig_item=item
                                dkim_sig.append(dkim_sig_item)
                                message_items['DKIM-Signature'] = dkim_sig
    
                #tracking pixel detection
                if helper.get_arg('get_tracking_pixel'):
                    if pixeltrack_re.search(message_body):
                        pixel_data = pixeltrack_re.search(message_body)
                        message_items['tracking_pixel'] = "true"
                        message_items['tracking_pixel_data'] = pixel_data.group(0)
    
                #size mapping
                for item in single_value_properties:
                    if item['id'] == "Long 0xe08":
                        message_items['size'] = item['value']
                        
                #ingest full email body
                if helper.get_arg('get_body'):
                    message_items['body'] = message_body
                
                #ingest email body preview of first 255 characters
                if helper.get_arg('get_body_preview'):
                    message_items['bodyPreview'] = body_preview
    
                #ingest iocs from body
                if helper.get_arg('extract_body_iocs'):
    
                    ipv4_extract = extract_ipv4(helper,message_body) 
                    ipv4_iocs = []
                    for ioc in ipv4_extract:
                        if not ioc in ipv4_iocs:
                            ipv4_iocs.append(ioc)
                        if ipv4_iocs:
                            message_items['ipv4_iocs'] = ipv4_iocs
    
                    ipv6_extract = extract_ipv6(helper,message_body)
                    ipv6_iocs = []
                    for ioc in ipv6_extract:
                        if not ioc in ipv6_iocs:
                            ipv6_iocs.append(ioc)
                        if ipv6_iocs:
                            message_items['ipv6_iocs'] = ipv6_iocs
    
                    url_extract = extract_urls(helper,message_body)
                    url_iocs = []
                    for ioc in url_extract:
                        if not ioc in url_iocs:
                            url_iocs.append(ioc)
                        if url_iocs:
                            message_items['url_iocs'] = url_iocs
    
                    domain_extract = extract_domains(helper,message_body)
                    domain_iocs = []
                    for ioc in domain_extract:
                        if not ioc in domain_iocs:
                            domain_iocs.append(ioc)
                        if domain_iocs:
                            message_items['domain_iocs'] = domain_iocs
                
                #ingest email attachments
                if helper.get_arg('get_attachment_info'):
    
                    if attachments:
    
                        attach_data = []
    
                        for attachment in attachments:
    
                            #Looks for itemAttachment type, which is a contact, event, or message that's attached.
                            if attachment["@odata.type"] == "#microsoft.graph.itemAttachment":
    
                                my_added_data = {}
                                
                                my_added_data['name'] = attachment['name']
                                my_added_data['odata_type'] = attachment['@odata.type']
                                my_added_data['id'] = attachment['id']
                                my_added_data['contentType'] = attachment['contentType']
                                my_added_data['size'] = attachment['size']
    
                                attach_data.append(my_added_data)
                            
                            #Looks for referenceAttachment type, which is a link to a file on OneDrive or other supported storage location
                            if attachment["@odata.type"] == "#microsoft.graph.referenceAttachment":
    
                                my_added_data = {}
    
                                my_added_data['name'] = attachment['name']
                                my_added_data['odata_type'] = attachment['@odata.type']
                                my_added_data['id'] = attachment['id']
                                my_added_data['contentType'] = attachment['contentType']
                                my_added_data['size'] = attachment['size']
    
                                attach_data.append(my_added_data)
                            
                            #Looks for fileAttachment type, which is a standard email attachment.
                                
                            if attachment["@odata.type"] == "#microsoft.graph.fileAttachment":
    
                                my_added_data = {}
    
                                attach_b64decode = base64.b64decode(attachment['contentBytes'])
    
                                #Selects which hashing algorithm (md5, sha1, sha256) to use on the attachment.
                                if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'md5':
                                    hash_object = hashlib.md5(attach_b64decode)
                                if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha1':
                                    hash_object = hashlib.sha1(attach_b64decode)
                                if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha256':
                                    hash_object = hashlib.sha256(attach_b64decode)
    
                                att_hash = hash_object.hexdigest()
    
                                my_added_data['name'] = attachment['name']
                                my_added_data['odata_type'] = attachment['@odata.type']
                                my_added_data['id'] = attachment['id']
                                my_added_data['contentType'] = attachment['contentType']
                                my_added_data['size'] = attachment['size']
                                my_added_data['file_hash'] = att_hash
    
                                #checks to see if @odata.mediaContentType exists for attachment before continuing
                                if attachment['@odata.mediaContentType']:
                                        
                                    #Attempts to open up zip file to list file names and hashes if the option is selected in the input.
                                    if helper.get_arg('get_attachment_info') and helper.get_arg('read_zip_files') and attachment['@odata.mediaContentType'] == 'application/zip':
    
                                        filedata_encoded = attachment['contentBytes'].encode()
                                        file_bytes = base64.b64decode(filedata_encoded)
    
                                        zipbytes = io.BytesIO(file_bytes)
                                    
                                        try:
                                            zipfile = ZipFile(zipbytes)
                                        
                                            zipmembers = zipfile.namelist()
                                        
                                            zip_files = []
                                            zip_hashes = []
                                        
                                            for file in zipmembers:
                                           
                                                zip_read = zipfile.read(file)
                                            
                                                if helper.get_arg('file_hash_algorithm') == 'md5':
                                                    hash_object = hashlib.md5(zip_read)
                                                if helper.get_arg('file_hash_algorithm') == 'sha1':
                                                    hash_object = hashlib.sha1(zip_read)
                                                if helper.get_arg('file_hash_algorithm') == 'sha256':
                                                    hash_object = hashlib.sha256(zip_read)    
                                                
                                                zip_hash = hash_object.hexdigest()
                                            
                                                if not file in zip_files:
                                                
                                                    zip_files.append(file)
                                                    zip_hashes.append(zip_hash)
    
                                                if zip_files:
                                                    my_added_data['zip_files'] = zip_files
                                                    my_added_data['zip_hashes'] = zip_hashes
                                                
                                        except:
                                            my_added_data['attention'] = 'could not extract the zip file, may be encrypted'
                                        
                                    #Routine to do macro analysis on files of supported content types listed below if selected in the input setup.  This uses OLEVBA tools to detect macros in the attachment, then analyses the macros.
                                    if helper.get_arg('get_attachment_info') and helper.get_arg('macro_analysis'):
    
                                        filename = attachment['name']
    
                                        #Content types supported by OLEVBA.
                                        supported_content = ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                        'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
                                        'application/vnd.ms-excel.sheet.macroenabled.12',
                                        'application/vnd.ms-excel.template.macroenabled.12',
                                        'application/vnd.ms-excel.addin.macroenabled.12',
                                        'application/vnd.ms-excel.sheet.binary.macroenabled.12',
                                        'application/vnd.ms-excel',
                                        'application/xml',
                                        'application/vnd.ms-powerpoint',
                                        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                                        'application/vnd.openxmlformats-officedocument.presentationml.template',
                                        'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
                                        'application/vnd.ms-powerpoint.addin.macroenabled.12',
                                        'application/vnd.ms-powerpoint.presentation.macroenabled.12',
                                        'application/vnd.ms-powerpoint.template.macroenabled.12',
                                        'application/vnd.ms-powerpoint.slideshow.macroenabled.12',
                                        'application/msword',
                                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                        'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
                                        'application/vnd.ms-word.document.macroenabled.12',
                                        'application/vnd.ms-word.template.macroenabled.12']
    
                                        if attachment['@odata.mediaContentType'] in supported_content:
    
                                            filedata_encoded = attachment['contentBytes'].encode()
                                            file_bytes = base64.b64decode(filedata_encoded)
    
                                            try:
                                                vbaparser = VBA_Parser(filename, data=file_bytes)
    
                                                if vbaparser.detect_vba_macros():
                                                    my_added_data['macros_exist'] = "true"
    
                                                    macro_analysis = VBA_Parser.analyze_macros(vbaparser)
                                                    helper.log_debug("GET Response: " + json.dumps(macro_analysis, indent=4))
    
                                                    if macro_analysis == []:
                                                        my_added_data['macro_analysis'] = "Macro doesn't look bad, but I never trust macros."
                                                    else:
                                                        my_added_data['macros_analysis'] = macro_analysis
    
                                                else:
                                                    my_added_data['macros_exist'] = "false"
                                                
                                            except:
                                                my_added_data['attention'] = 'could not extract the office document, may be encrypted'
    
                                attach_data.append(my_added_data)
    
                        message_items['attachments'] = attach_data
    
                message_data.append(message_items)
            
            helper.log_info("Writing messages to Splunk")
            _write_events(helper, ew, messages=message_data)
        _purge_messages(helper, messages)

    def get_account_fields(self):
        account_fields = []
        account_fields.append("global_account")
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        checkbox_fields.append("get_attachment_info")
        checkbox_fields.append("macro_analysis")
        checkbox_fields.append("read_zip_files")
        checkbox_fields.append("extract_body_iocs")
        checkbox_fields.append("get_body")
        checkbox_fields.append("get_body_preview")
        checkbox_fields.append("get_message_path")
        checkbox_fields.append("get_auth_results")
        checkbox_fields.append("get_spf_results")
        checkbox_fields.append("get_dkim_signature")
        checkbox_fields.append("get_x_headers")
        checkbox_fields.append("get_internet_headers")
        checkbox_fields.append("get_tracking_pixel")
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
    exitcode = ModInputo365_email().run(sys.argv)
    sys.exit(exitcode)
