# splunk-dynatrace
Splunk App &amp; Add-On for Dynatrace

## What's Needed?
- Downloads
    - Splunk Add-on for Dynatrace
    - Splunk App for Dynatrace


- Dynatrace Information Required
    - Dynatrace API base URL 
    - Dynatrace API Authorization Token
    
## Installation
The installation consists of creating a new index called "dynatrace" and 
then installing both the *Dynatrace Add-on for Splunk* and the 
*Dynatrace App for Splunk*.   
  - The Add-on is responsible for executing the rest API calls and 
collecting the data from Dynatrace.  
  - The App provides a collection of dashboards and saved searches.  
  
To install, navigate to Apps --> Manage Apps and select the “Install app 
from File” button.  Specify the location of the file you downloaded and 
install it.   

## Configuration
The Dynatrace Add-on for Splunk utilizes a Dynatrace account URL and API authorization token.  Enter those values on the **Configuration / Account** tab in the add-on, after having clicked on **Add** button.

Once done, navigate to the **Create New Input** tab in the Add-on. From the Inputs menu, create new Input for the data you wish to collect.  
Each Input requires 4 parameters:
  - Input Name 
  - Polling interval
  - Splunk Index to use
  - Your Dynatrace account
  - The Timeseries Metrics Input collects a pre-defined set of Dynatrace 
metrics
  
## Start Searching
Once the Splunk Add-on for Dynatrace is installed and configured you can 
execute searches using any of the following searches: 
```
sourcetype="dynatrace:metrics"
sourcetype="dynatrace:problem"
sourcetype="dynatrace:entity"
sourcetype="dynatrace:single-metric"
```

## Notes
1. You will need to create a "dynatrace" index and ensure any users that 
need to view the data have the proper permissions.  This includes any 
roles for ITSI such as "itoa_user" if you are using the APM Module of IT 
Service Intelligence.  
2. If you use a different index name, you will have to modify the 
dashboards in the Dynatrace App for Splunk.

----  
