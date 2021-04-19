[o365_email_groups://<name>]
tenant = 
endpoint = Select your O365 tenant type
global_account = 

[o365_email://<name>]
audit_email_account = Please enter the audit email configured in the O365 mail flow rule
tenant = Please enter the Tenant ID from the Azure App registration process
endpoint = 
get_attachment_info = Gathers basic attachment info (name, type, size, hash, etc).
file_hash_algorithm = Used for attachment and zip file hashing.
macro_analysis = Detects and analyses macros within Office document formats.
read_zip_files = Attempts to read file names and file hashes from within zip files.  Requires Get Attachment Info to be selected.
extract_body_iocs = Attempts to extract IOCs from email bodies. (URLs, domains, ipv4, ipv6, hashes, etc).
get_body = Retrieves the whole message body for emails and any emails that are attached.WARNING- POTENTIALLY LARGE INGEST IF ENABLED
get_body_preview = Only retrieves the first 255 characters in the email body
get_message_path = Gathers all MTA hops the message traversed
get_auth_results = Gathers authentication results headers
get_spf_results = Gathers SPF results from the headers
get_dkim_signature = Gathers DKIM signature results from the headers
get_x_headers = Gathers all X-Headers from the headers
get_internet_headers = Retrieves All Internet Headers
get_tracking_pixel = Basic tracking pixel detection
global_account =